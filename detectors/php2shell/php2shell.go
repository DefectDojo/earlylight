// Package php2shell is the detector for CVE-2026-109618 and CVE-2026-109619
// ("PHP2Shell"), the two remote code execution flaws in the PHP engine fixed in
// PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 on October 21, 2026. It finds PHP
// runtimes in filesystems and container images and judges each by upstream
// release and by its vendor's backport data, and it checks the images a source
// tree builds on and deploys.
//
// The detection lives in internal/, copied verbatim from php2shell-scan (see
// SNAPSHOT at the repo root), and verbatim.go holds the parts of its command
// line the engine needs. This file only adapts them to the engine and replays
// php2shell-scan's per-target collector, so verdicts stay identical.
package php2shell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/detect"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"
	_ "github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb/rpmdb" // rpm sqlite databases
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/report"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/source"
)

// ID is the detector's ID.
const ID = "php2shell"

// Kind IDs. Runtimes that serve web requests and those that do not are
// separate kinds because they carry different severities.
const (
	KindRuntimeWeb = "php-runtime-web"
	KindRuntimeCLI = "php-runtime-cli"
	KindImage      = "php-image"
)

// Detector implements engine.Detector, engine.Reader, engine.RepoScanner and
// engine.Fixer.
type Detector struct {
	data *knowledge.Data
}

func init() { engine.Register(&Detector{}) }

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	cves := strings.Join(knowledge.CVEIDs(), " and ")
	about := " PHP's October 21, 2026 security releases (8.2.35, 8.3.36, 8.4.27 and 8.5.12) fix " + cves +
		", two remote code execution flaws in the PHP engine reachable before any application code runs."
	var adv []string
	for _, c := range knowledge.CVEs {
		adv = append(adv, c.URL)
	}
	snap := ""
	if d.data != nil {
		snap = "distribution fix data from " + d.data.Snapshot
	}
	cwe := []string{"CWE-416", "CWE-824"}
	return engine.Manifest{
		ID:         ID,
		Title:      "PHP2Shell: PHP vulnerable to " + cves,
		CVEs:       knowledge.CVEIDs(),
		Advisories: adv,
		Disclosed:  "2026-10-21",
		Targets:    []engine.TargetKind{engine.Filesystem, engine.Image, engine.Repository},
		Kinds: []engine.Kind{
			{ID: KindRuntimeWeb, Title: "PHP runtime serving web requests is vulnerable to " + cves, Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
				Description: "A PHP runtime that serves web requests (PHP-FPM, CGI, the Apache module, LiteSpeed or FrankenPHP) without the fix." + about},
			{ID: KindRuntimeCLI, Title: "PHP CLI or embedded runtime is vulnerable to " + cves, Level: "error", SecuritySeverity: "7.5", CWEs: cwe,
				Description: "A PHP command-line or embedded runtime without the fix. It is exposed when it serves requests (php -S, a worker) or handles untrusted input." + about},
			{ID: KindImage, Title: "Container image with PHP vulnerable to " + cves, Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
				Description: "An image reference that resolves to a PHP build without the fix. Images built from it, and containers running them, are vulnerable." + about},
		},
		Tags: []string{"security", "php", "PHP2Shell"},
		Data: snap,
	}
}

// Load loads the distribution fix data, which refuses to load if it
// contradicts itself.
func (d *Detector) Load() error {
	if d.data != nil {
		return nil
	}
	data, err := knowledge.Load()
	if err != nil {
		return err
	}
	d.data = data
	return nil
}

// Wants reads executables (possible PHP runtimes) and package-database files.
// The executable test is php2shell-scan's own, which tells Java class files
// from Mach-O universal binaries.
func (d *Detector) Wants(p string, head []byte, _ bool) bool {
	return detect.Executable(head) || pkgdb.Wanted(p)
}

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(kind engine.TargetKind) engine.Scan {
	c := &collector{data: d.data, dbFiles: map[string][]byte{}, symlinks: map[string]string{}}
	if kind == engine.Image {
		c.exclude = source.DefaultExcludes // php2shell-scan skips /proc, /sys and /dev in images
	}
	return c
}

func excluded(p string, ex []string) bool {
	for _, e := range ex {
		if p == strings.TrimSuffix(e, "/") || strings.HasPrefix(p, e) {
			return true
		}
	}
	return false
}

// collector is php2shell-scan's per-target collector.
type collector struct {
	data     *knowledge.Data
	binaries []*detect.Binary
	dbFiles  map[string][]byte
	symlinks map[string]string
	exclude  []string
}

// options carries the command-line settings verbatim.go reads.
type options struct {
	maxFile     int64
	platform    string
	platformSet bool
	offline     bool
	publicOnly  bool
	dryRun      bool
	timeout     time.Duration
}

func optionsFrom(o engine.Options) options {
	po := options{maxFile: o.MaxFileSize, offline: o.Offline, publicOnly: o.PublicOnly, dryRun: o.DryRun, timeout: o.Timeout}
	if len(o.Platforms) > 0 {
		po.platform, po.platformSet = strings.Join(o.Platforms, ","), true
	}
	if po.timeout == 0 {
		po.timeout = 30 * time.Second
	}
	return po
}

const headSize = 4096

// upx reports a UPX-packed executable: its code and strings are compressed, so a
// PHP runtime inside could not be recognised. (From php2shell-scan's source.)
func upx(head []byte) bool {
	return bytes.Contains(head, []byte("UPX!")) || (bytes.Contains(head, []byte("UPX0")) && bytes.Contains(head, []byte("UPX1")))
}

func (c *collector) Visit(f engine.File) []engine.Skip {
	if f.Member || excluded(f.Path, c.exclude) {
		return nil // installed files only, not archive members or excluded paths
	}
	head := f.Data
	if len(head) > headSize {
		head = head[:headSize]
	}
	exe := detect.Executable(head)
	if exe && upx(head) {
		return []engine.Skip{{Path: f.Path, Reason: "UPX-packed executable: its contents are compressed and cannot be checked"}}
	}
	if pkgdb.Wanted(f.Path) {
		c.dbFiles[f.Path] = f.Data
	}
	if exe {
		if b := detect.Inspect(f.Path, f.Data); b != nil {
			c.binaries = append(c.binaries, b)
		}
	}
	return nil
}

func (c *collector) Finish(ctx engine.TargetContext) []engine.Finding {
	links, hard := ctx.Links()
	for p, t := range links {
		if !excluded(p, c.exclude) {
			c.symlinks[p] = t
		}
	}
	if root := ctx.SystemRoot(); root != "" {
		readSystem(c, root, options{maxFile: 1 << 30})
	}
	ix := pkgdb.Build(c.dbFiles)
	for _, p := range ix.Problems {
		ctx.Problem(p)
	}
	var osr *knowledge.OSRelease
	if o, ok := pkgdb.OSRelease(c.dbFiles); ok {
		osr = &o
		ctx.Annotate("os", osr)
	}
	res := pkgdb.NewResolver(c.symlinks)
	for p, target := range hard {
		if !excluded(p, c.exclude) {
			res.AddHardlink(p, target)
		}
	}
	fs := assess.Run(assess.Input{Binaries: c.binaries, Index: ix, Aliases: res.Aliases, OS: osr, Data: c.data})
	out := make([]engine.Finding, 0, len(fs))
	for _, f := range fs {
		out = append(out, runtimeFinding(f))
	}
	return out
}

var verdicts = map[assess.Status]engine.Verdict{
	assess.Vulnerable: engine.Vulnerable,
	assess.Fixed:      engine.Fixed,
	assess.Unknown:    engine.Unknown,
}

func verdict(s assess.Status) engine.Verdict {
	if v, ok := verdicts[s]; ok {
		return v
	}
	return engine.Unknown
}

func cveResults(rs []assess.CVEResult) []engine.CVEResult {
	out := make([]engine.CVEResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, engine.CVEResult{ID: r.ID, Verdict: verdict(r.Status), Reason: r.Reason})
	}
	return out
}

func runtimeFinding(f assess.Finding) engine.Finding {
	kind := KindRuntimeCLI
	if f.WebFacing {
		kind = KindRuntimeWeb
	}
	facts := map[string]string{"php_version": f.PHPVersion, "sapi": f.SAPI}
	if f.Package != nil {
		facts["package"] = f.Package.Name + " " + f.Package.Version
	}
	return engine.Finding{
		Kind:     kind,
		Path:     f.Path,
		Verdict:  verdict(f.Status),
		Reason:   f.Reason,
		Message:  fmt.Sprintf("PHP %s (%s)", f.PHPVersion, f.SAPI),
		Method:   "elf-strings",
		Facts:    facts,
		CVEs:     cveResults(f.CVEs),
		Fix:      f.Fix,
		Severity: f.Severity,
		Details:  f,
	}
}

// ScanRepo checks the images a source tree builds on and deploys.
func (d *Detector) ScanRepo(ctx context.Context, dir string, o engine.Options) *engine.Target {
	rt := scanRepo(ctx, dir, optionsFrom(o))
	t := &engine.Target{Name: rt.Name, Type: engine.Repository, Files: rt.RefsChecked, Incomplete: rt.Incomplete, Error: rt.Error, Problems: rt.Problems}
	for _, s := range rt.Skipped {
		t.Skipped = append(t.Skipped, source.Skip{Path: s.Path, Reason: s.Reason, Excluded: s.Excluded})
	}
	for _, r := range rt.Refs {
		t.Findings = append(t.Findings, refFinding(r))
	}
	return t
}

func refFinding(r report.RefFinding) engine.Finding {
	facts := map[string]string{"image": r.Image, "reference": r.Kind}
	if len(r.Platforms) > 0 {
		facts["platforms"] = strings.Join(r.Platforms, ",")
	}
	return engine.Finding{
		Kind:     KindImage,
		Path:     r.File,
		Line:     r.Line,
		Verdict:  verdict(r.Status),
		Reason:   r.Reason,
		Message:  "image " + r.Image,
		Method:   "registry",
		Facts:    facts,
		Fix:      r.Fix,
		Severity: r.Severity,
		Details:  r,
	}
}

// Fix moves a source tree's vulnerable PHP image references to published
// fixed images, as php2shell-scan fix does.
func (d *Detector) Fix(ctx context.Context, dirs []string, o engine.Options, stdout, stderr io.Writer) int {
	return runFix(ctx, dirs, optionsFrom(o), stdout, stderr)
}
