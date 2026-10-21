// Code in this file is copied verbatim from php2shell-scan's command line
// (cmd/php2shell-scan/main.go at ebc53f1), so the engine reads system files and
// applies fixes exactly as the standalone scanner does. Only the receiver types
// differ: collector and options are the small adapters defined in php2shell.go.

package php2shell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/fix"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/netguard"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/report"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/reposcan"
)

// systemDirs are read from the system root on every fs scan, so a scan of one
// directory (/usr/bin) still sees the package databases and os-release.
var systemDirs = []string{"/var/lib/dpkg", "/lib/apk/db", "/var/lib/rpm", "/usr/lib/sysimage/rpm", "/etc/os-release", "/usr/lib/os-release", "/etc/debian_version", "/etc/alpine-release"}

// readSystem reads package databases, os-release and the top-level directory
// links (merged /usr) from the system root, for fs scans of a directory below it.
func readSystem(c *collector, sysRoot string, o options) {
	for _, d := range systemDirs {
		full := filepath.Join(sysRoot, filepath.FromSlash(d))
		fi, err := os.Lstat(full)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if t, err := os.Readlink(full); err == nil {
				c.symlinks[d] = filepath.ToSlash(t)
			}
			continue // the target is read under its own name (/usr/lib/os-release)
		}
		if !fi.IsDir() {
			readSystemFile(c, full, d, o.maxFile)
			continue
		}
		_ = filepath.WalkDir(full, func(fp string, e os.DirEntry, err error) error {
			if err != nil || !e.Type().IsRegular() {
				return nil
			}
			rel, _ := filepath.Rel(full, fp)
			readSystemFile(c, fp, path.Join(d, filepath.ToSlash(rel)), o.maxFile)
			return nil
		})
	}
	for _, dir := range []string{"/", "/usr"} {
		ents, err := os.ReadDir(filepath.Join(sysRoot, filepath.FromSlash(dir)))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.Type()&os.ModeSymlink == 0 {
				continue
			}
			p := path.Join(dir, e.Name())
			if t, err := os.Readlink(filepath.Join(sysRoot, filepath.FromSlash(p))); err == nil {
				c.symlinks[p] = filepath.ToSlash(t)
			}
		}
	}
}

func readSystemFile(c *collector, osPath, abs string, maxFile int64) {
	if !pkgdb.Wanted(abs) {
		return
	}
	f, err := os.Open(osPath)
	if err != nil {
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || int64(len(b)) > maxFile {
		return
	}
	c.dbFiles[abs] = b
}

func runFix(ctx context.Context, dirs []string, o options, stdout, stderr io.Writer) int {
	code := 0
	for _, dir := range dirs {
		_, items, err := reposcan.Run(ctx, dir, repoOptions(o))
		var te *reposcan.TransientError
		if errors.As(err, &te) {
			// Fix what was checked; report the rest as not checked.
			fmt.Fprintf(stderr, "%s: %v\n", dir, err)
			code = 2
		} else if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", dir, err)
			return 2
		}
		var changes []fix.Change
		seen := map[string]bool{}
		for _, it := range items {
			r := it.Result.Ref
			switch {
			case it.Change != nil:
				k := fmt.Sprintf("%s:%d", it.Change.File, it.Change.Line)
				if seen[k] {
					continue // one edit (a shared ARG) fixes several references
				}
				seen[k] = true
				changes = append(changes, *it.Change)
				c := it.Change
				fmt.Fprintf(stdout, "%s:%d  %s -> %s\n    - %s\n    + %s\n", clean(c.File), c.Line, clean(c.Before), clean(c.After), clean(c.Old), clean(c.New))
			case it.Decline != nil:
				if code == 0 {
					code = 1
				}
				fmt.Fprintf(stdout, "%s:%d  %s: not changed: %s\n", clean(r.File), r.Line, clean(r.Image), clean(it.Decline.Reason))
			}
		}
		if len(changes) == 0 {
			fmt.Fprintf(stdout, "%s: nothing to change\n", clean(dir))
			continue
		}
		if o.dryRun {
			fmt.Fprintf(stdout, "%s: %d change(s) not written (--dry-run)\n", dir, len(changes))
			continue
		}
		if err := fix.Apply(dir, changes); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", dir, err)
			return 2
		}
		fmt.Fprintf(stdout, "%s: %d change(s) written\n", dir, len(changes))
	}
	return code
}

// clean keeps repository and registry text from injecting terminal escapes or
// extra lines into the fix listing.
func clean(s string) string { return registry.CleanText(s, 4096) }

// repoOptions: repository checks cover every platform an image publishes unless
// --platform names the ones you build.
func repoOptions(o options) reposcan.Options {
	ro := reposcan.Options{Registry: registry.Options{Offline: o.offline, Timeout: o.timeout, Transport: netguard.Transport(o.publicOnly)}}
	if o.platformSet && o.platform != "all" {
		ro.Registry.Platforms = strings.Split(o.platform, ",")
	}
	return ro
}

func scanRepo(ctx context.Context, dir string, o options) *report.Target {
	t, _, err := reposcan.Run(ctx, dir, repoOptions(o))
	var te *reposcan.TransientError
	switch {
	case errors.As(err, &te):
		t.Incomplete = err.Error()
	case err != nil:
		return &report.Target{Name: dir, Type: "repository", Error: err.Error()}
	}
	return t
}
