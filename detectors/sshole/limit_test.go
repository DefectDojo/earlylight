package sshole_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	_ "github.com/DefectDojo/earlylight/detectors/emudhra" // a detector that reads every file
	"github.com/DefectDojo/earlylight/detectors/sshole/internal/testelf"
	"github.com/DefectDojo/earlylight/internal/cli"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// maxKept is the most sshole reads of a file its verdict depends on.
const maxKept = 4 << 20

// padded writes data followed by zeros up to size bytes (sparse).
func padded(t *testing.T, root, rel string, data []byte, size int64) {
	t.Helper()
	write(t, root, rel, data, 0o644)
	if err := os.Truncate(filepath.Join(root, rel), size); err != nil {
		t.Fatal(err)
	}
}

// scanExit runs a JSON scan and returns its findings, skips and exit status.
func scanExit(t *testing.T, args ...string) ([]engine.Finding, []struct {
	Path     string `json:"path"`
	Excluded bool   `json:"excluded"`
}, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(cfg, append([]string{"scan", "fs", "--format", "json"}, args...), &out, &errb)
	var r struct {
		Targets []struct {
			Findings []engine.Finding `json:"findings"`
			Skipped  []struct {
				Path     string `json:"path"`
				Excluded bool   `json:"excluded"`
			} `json:"skipped"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Targets) != 1 {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errb.String())
	}
	return r.Targets[0].Findings, r.Targets[0].Skipped, code
}

// pamRoot is alpineRoot with sshd built with PAM and UsePAM yes after an
// Include of sshd_config.d.
func pamRoot(t *testing.T) string {
	root := alpineRoot(t, "10.0_p1-r10")
	write(t, root, "usr/sbin/sshd", testelf.ELF("/lib/ld-musl-x86_64.so.1", []string{"libc.musl-x86_64.so.1", "libpam.so.0"},
		testelf.SSHDStrings("10.0p2", "/usr/lib/ssh/sshd-session", "/usr/lib/ssh/sshd-auth")...), 0o755)
	write(t, root, "etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"), 0o644)
	return root
}

// Review finding 1: an included file over the limit that may turn PAM off
// keeps the server from being cleared, and is a coverage gap.
func TestIncludeOverLimitNeverClears(t *testing.T) {
	root := pamRoot(t)
	fs, _, _ := scanExit(t, "--detector", "sshole", "--as-root", root)
	if len(fs) != 1 || fs[0].Verdict != engine.Inactive {
		t.Fatalf("PAM on, nothing included: %+v", fs)
	}
	write(t, root, "etc/ssh/sshd_config.d/50-site.conf", []byte("UsePAM no\n"), 0o644)
	fs, _, _ = scanExit(t, "--detector", "sshole", "--as-root", root)
	if len(fs) != 1 || fs[0].Verdict != engine.Vulnerable || fs[0].Severity != "critical" {
		t.Fatalf("a small include turning PAM off: %+v", fs)
	}
	padded(t, root, "etc/ssh/sshd_config.d/50-site.conf", []byte("UsePAM no\n"), maxKept+1)
	for _, extra := range [][]string{nil, {"--detector", "emudhra"}} {
		args := append(append([]string{"--detector", "sshole"}, extra...), "--as-root", "--fail-on-skip", root)
		fs, skipped, code := scanExit(t, args...)
		var got []engine.Finding
		for _, f := range fs {
			if f.Detector == "sshole" {
				got = append(got, f)
			}
		}
		if len(got) != 1 || got[0].Verdict.Cleared() || got[0].Verdict != engine.Unknown || !strings.Contains(got[0].Reason, "50-site.conf") {
			t.Errorf("with %v, an include over the limit: %+v", extra, got)
		}
		gap := false
		for _, s := range skipped {
			gap = gap || s.Path == "/etc/ssh/sshd_config.d/50-site.conf" && !s.Excluded
		}
		if !gap || code != 3 {
			t.Errorf("with %v: exit %d, skipped %+v", extra, code, skipped)
		}
	}
}

// Review finding 2: a login shell over the script limit still exists, so
// the verdict is the same as for a small one, with or without other
// detectors.
func TestShellOverLimitExists(t *testing.T) {
	verdict := func(script []byte, size int64, extra ...string) string {
		root := alpineRoot(t, "10.0_p1-r10")
		write(t, root, "etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/usr/local/bin/menu\n"), 0o644)
		padded(t, root, "usr/local/bin/menu", script, size)
		fs, _, _ := scanExit(t, append(append([]string{"--detector", "sshole"}, extra...), "--as-root", root)...)
		for _, f := range fs {
			if f.Detector == "sshole" {
				return string(f.Verdict) + "/" + f.Severity
			}
		}
		return "none"
	}
	script := []byte("#!/bin/sh\nexec /bin/sh\n")
	small := verdict(script, int64(len(script)))
	if small != "vulnerable/critical" {
		t.Fatalf("small shell: %s", small)
	}
	if big := verdict(script, 300<<10); big != small {
		t.Errorf("a 300 KiB shell: %s, a small one: %s", big, small)
	}
	if big := verdict(script, 300<<10, "--detector", "emudhra"); big != small {
		t.Errorf("a 300 KiB shell with emudhra: %s, a small one: %s", big, small)
	}
}

// --fail-on-skip: a start script over the limit is a deliberate exclusion
// (the startup analysis never clears a server), an account file over it a
// gap.
func TestFailOnSkipWithLimits(t *testing.T) {
	root := alpineRoot(t, "10.0_p1-r11") // fixed: exit 0 when nothing is a gap
	padded(t, root, "opt/install.sh", []byte("#!/bin/sh\n"), 300<<10)
	_, skipped, code := scanExit(t, "--detector", "sshole", "--as-root", "--fail-on-skip", root)
	if code != 0 || len(skipped) != 1 || !skipped[0].Excluded {
		t.Errorf("a large script: exit %d skipped %+v", code, skipped)
	}
	padded(t, root, "etc/shadow", []byte("root:*::0:::::\n"), maxKept+1)
	_, skipped, code = scanExit(t, "--detector", "sshole", "--as-root", "--fail-on-skip", root)
	gaps := 0
	for _, s := range skipped {
		if s.Path == "/etc/shadow" && !s.Excluded {
			gaps++
		}
	}
	if code != 3 || gaps != 1 {
		t.Errorf("a large /etc/shadow: exit %d skipped %+v", code, skipped)
	}
}

// sshVerdict returns sshole's single verdict and the exit status.
func sshVerdict(t *testing.T, args ...string) (engine.Verdict, int) {
	t.Helper()
	fs, _, code := scanExit(t, append([]string{"--detector", "sshole"}, args...)...)
	if len(fs) != 1 {
		t.Fatalf("findings %+v", fs)
	}
	return fs[0].Verdict, code
}

// Round-2 review finding 2: a package database over the old 4 MiB limit is
// read (16 MiB, as java4shell), and with no OpenSSH server in the target a
// file over the limit is no coverage gap.
func TestPackageDBLimit(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", []byte("ID=alpine\nVERSION_ID=3.22.2\n"), 0o644)
	padded(t, root, "lib/apk/db/installed", []byte("P:musl\nV:1.2.5-r10\n\n"), 4500036)
	if _, _, code := scanExit(t, "--detector", "sshole", "--as-root", "--fail-on-skip", root); code != 0 {
		t.Errorf("a 4.5 MB apk database and no sshd: exit %d", code)
	}
	padded(t, root, "lib/apk/db/installed", []byte("P:musl\nV:1.2.5-r10\n\n"), 16<<20+1)
	if _, skipped, code := scanExit(t, "--detector", "sshole", "--as-root", "--fail-on-skip", root); code != 0 || len(skipped) != 1 || !skipped[0].Excluded {
		t.Errorf("an apk database over 16 MiB and no sshd: exit %d skipped %+v", code, skipped)
	}
	root = alpineRoot(t, "10.0_p1-r11")
	db, _ := os.ReadFile(filepath.Join(root, "lib/apk/db/installed"))
	padded(t, root, "lib/apk/db/installed", db, 4500036)
	if v, code := sshVerdict(t, "--as-root", "--fail-on-skip", root); v != engine.Fixed || code != 0 {
		t.Errorf("a 4.5 MB apk database naming the fixed package: %s exit %d", v, code)
	}
	// Over 16 MiB, the fixed package is not known: not cleared, and a gap.
	padded(t, root, "lib/apk/db/installed", db, 16<<20+1)
	fs, skipped, _ := scanExit(t, "--detector", "sshole", "--as-root", root)
	gap := false
	for _, s := range skipped {
		gap = gap || s.Path == "/lib/apk/db/installed" && !s.Excluded
	}
	if len(fs) != 1 || fs[0].Verdict.Cleared() || !gap {
		t.Errorf("an apk database over 16 MiB with sshd: %+v skipped %+v", fs, skipped)
	}
}

// Round-2 review finding 3: a start script over the limit that may start
// sshd with PAM off keeps the server from being cleared.
func TestStartScriptOverLimitNeverClears(t *testing.T) {
	for _, c := range []struct{ name, rel, text string }{
		{"-o UsePAM=no", "etc/cont-init.d/10-sshd", "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n"},
		{"-f another config", "etc/cont-init.d/10-sshd", "#!/bin/sh\nexec /usr/sbin/sshd -D -f /etc/ssh/alt_sshd_config\n"},
		// Named like sshd_config, so read up to 4 MiB as a config file,
		// but past the script limit.
		{"a script read for its name", "etc/cont-init.d/gen-sshd_config.sh", "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n"},
	} {
		root := pamRoot(t)
		write(t, root, "etc/ssh/alt_sshd_config", []byte("UsePAM no\n"), 0o644)
		write(t, root, c.rel, []byte(c.text), 0o755)
		if v, _ := sshVerdict(t, "--as-root", root); v != engine.Vulnerable {
			t.Errorf("%s, small: %s", c.name, v)
		}
		padded(t, root, c.rel, []byte(c.text), 307200)
		if v, code := sshVerdict(t, "--as-root", root); v.Cleared() || code == 0 {
			t.Errorf("%s, 307,200 bytes: %s exit %d", c.name, v, code)
		}
	}
	// A large script that does not run at start changes nothing.
	root := pamRoot(t)
	padded(t, root, "opt/install.sh", []byte("#!/bin/sh\n"), 307200)
	if v, _ := sshVerdict(t, "--as-root", root); v != engine.Inactive {
		t.Errorf("a large script outside the start: %s", v)
	}
}

// Round-2 review finding 4: an include over --max-file-size, not only over
// sshole's own limit, keeps the server from being cleared, at and around
// the boundary where the two limits are equal.
func TestIncludeOverMaxFileSize(t *testing.T) {
	for _, c := range []struct {
		size int64
		max  string
	}{{2 << 20, "1048576"}, {maxKept + 1, "4194304"}, {maxKept + 1, "4194305"}, {maxKept, "4194303"}} {
		root := pamRoot(t)
		padded(t, root, "etc/ssh/sshd_config.d/50-site.conf", []byte("UsePAM no\n"), c.size)
		if v, code := sshVerdict(t, "--as-root", "--max-file-size", c.max, "--fail-on-skip", root); v.Cleared() || code != 3 {
			t.Errorf("a %d-byte include, --max-file-size %s: %s exit %d", c.size, c.max, v, code)
		}
	}
}

// Round-2 review finding 7: an include too large to read from disk under
// --root (a subdirectory scanned, the configuration read from the root)
// keeps the server from being cleared.
func TestIncludeOverLimitOnDisk(t *testing.T) {
	root := pamRoot(t)
	if v, _ := sshVerdict(t, "--root", root, filepath.Join(root, "usr")); v != engine.Inactive {
		t.Fatalf("PAM on, read from disk: %s", v)
	}
	padded(t, root, "etc/ssh/sshd_config.d/50-site.conf", []byte("UsePAM no\n"), maxKept+1)
	if v, _ := sshVerdict(t, "--root", root, filepath.Join(root, "usr")); v.Cleared() {
		t.Errorf("an include over the limit on disk: %s", v)
	}
}

// unreadable makes p unreadable, or skips the test when that cannot be
// done (running as root).
func unreadable(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o755) })
	if f, err := os.Open(p); err == nil {
		f.Close()
		t.Skip("running as root: permissions do not keep a file unread")
	}
}

// Round-3 review finding 1: an include, a start script or an init
// directory the scan could not read keeps a PAM server from being cleared,
// and an unreadable login shell still exists.
func TestUnreadableNeverClears(t *testing.T) {
	for _, c := range []struct{ name, rel, text, lock string }{
		{"an include", "etc/ssh/sshd_config.d/50-site.conf", "UsePAM no\n", ""},
		{"an include directory", "etc/ssh/sshd_config.d/50-site.conf", "UsePAM no\n", "etc/ssh/sshd_config.d"},
		{"a start script", "etc/cont-init.d/10-sshd", "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n", ""},
		{"an init directory", "etc/cont-init.d/10-sshd", "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n", "etc/cont-init.d"},
	} {
		root := pamRoot(t)
		write(t, root, c.rel, []byte(c.text), 0o644)
		lock := c.lock
		if lock == "" {
			lock = c.rel
		}
		unreadable(t, filepath.Join(root, lock))
		if v, code := sshVerdict(t, "--as-root", root); v.Cleared() || code == 0 {
			t.Errorf("%s not readable: %s exit %d", c.name, v, code)
		}
	}
	verdict := func(lock bool) string {
		root := alpineRoot(t, "10.0_p1-r10")
		write(t, root, "etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/usr/local/bin/menu\n"), 0o644)
		write(t, root, "usr/local/bin/menu", []byte("#!/bin/sh\nexec /bin/sh\n"), 0o755)
		if lock {
			unreadable(t, filepath.Join(root, "usr/local/bin/menu"))
		}
		fs, _, _ := scanExit(t, "--detector", "sshole", "--as-root", root)
		return string(fs[0].Verdict) + "/" + fs[0].Severity
	}
	if a, b := verdict(false), verdict(true); a != b {
		t.Errorf("a login shell that cannot be read: %s, one that can: %s", b, a)
	}
}

// tarOf writes root and then extra entries (path, content) to a rootfs tar.
func tarOf(t *testing.T, root string, extra ...[2]string) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		h, _ := tar.FileInfoHeader(fi, "")
		if fi.Mode()&os.ModeSymlink != 0 {
			h.Linkname, _ = os.Readlink(p)
		}
		h.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			tw.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range extra {
		tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o755, Size: int64(len(e[1])), Typeflag: tar.TypeReg})
		tw.Write([]byte(e[1]))
	}
	tw.Close()
	p := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Round-3 review finding 2: of two image entries for a start script, the
// last is the file, whatever the first was.
func TestDuplicateStartScript(t *testing.T) {
	root := pamRoot(t)
	const p = "etc/cont-init.d/10-sshd"
	for _, c := range []struct {
		name          string
		first, second string
		want          engine.Verdict
	}{
		{"a script that turns PAM off, then plain text", "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n", "not a script\n", engine.Inactive},
		{"a harmless script, then one that turns PAM off", "#!/bin/sh\ntrue\n", "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n", engine.Vulnerable},
		{"one over the limit, then a harmless one", "#!/bin/sh\n" + strings.Repeat("#", maxScript), "#!/bin/sh\ntrue\n", engine.Inactive},
	} {
		img := tarOf(t, root, [2]string{p, c.first}, [2]string{p, c.second})
		fs, _, _ := scanImage(t, img)
		if len(fs) != 1 || fs[0].Verdict != c.want {
			t.Errorf("%s: %+v", c.name, fs)
		}
	}
}

const maxScript = 256 << 10

func scanImage(t *testing.T, img string) ([]engine.Finding, []struct {
	Path     string `json:"path"`
	Excluded bool   `json:"excluded"`
}, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(cfg, []string{"scan", "image", "--format", "json", "--detector", "sshole", "rootfs:" + img}, &out, &errb)
	var r struct {
		Targets []struct {
			Error    string           `json:"error"`
			Findings []engine.Finding `json:"findings"`
			Skipped  []struct {
				Path     string `json:"path"`
				Excluded bool   `json:"excluded"`
			} `json:"skipped"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Targets) != 1 || r.Targets[0].Error != "" {
		t.Fatalf("%v %+v\n%s", err, r, errb.String())
	}
	return r.Targets[0].Findings, r.Targets[0].Skipped, code
}

// Round-3 review finding 4: a start script that kept the verdict unknown
// is a coverage gap, with one record that does not contradict another.
func TestUnreadStartScriptIsAGap(t *testing.T) {
	root := pamRoot(t)
	padded(t, root, "etc/cont-init.d/10-sshd", []byte("#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n"), 307200)
	fs, skipped, _ := scanExit(t, "--detector", "sshole", "--as-root", root)
	var recs []bool
	for _, s := range skipped {
		if s.Path == "/etc/cont-init.d/10-sshd" {
			recs = append(recs, s.Excluded)
		}
	}
	if len(fs) != 1 || fs[0].Verdict != engine.Unknown || fmt.Sprint(recs) != "[false]" {
		t.Errorf("findings %+v records %v (skipped %+v)", fs, recs, skipped)
	}
}

// Round-3 review finding 5: a package database between 4 and 16 MiB is
// read from disk under --root.
func TestPackageDBFromDisk(t *testing.T) {
	root := alpineRoot(t, "10.0_p1-r11")
	db, _ := os.ReadFile(filepath.Join(root, "lib/apk/db/installed"))
	padded(t, root, "lib/apk/db/installed", db, 5<<20)
	if v, _ := sshVerdict(t, "--root", root, filepath.Join(root, "usr")); v != engine.Fixed {
		t.Errorf("a 5 MiB apk database read from disk: %s", v)
	}
}

// dirLayer is a layer of root's files, named relative to the root unless
// abs; skip leaves names out.
func dirLayer(t *testing.T, root string, abs bool, skip ...string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		for _, s := range skip {
			if rel == s {
				return nil
			}
		}
		h, _ := tar.FileInfoHeader(fi, "")
		if fi.Mode()&os.ModeSymlink != 0 {
			h.Linkname, _ = os.Readlink(p)
		}
		h.Name = rel
		if abs {
			h.Name = "/" + rel
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			tw.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// dockerArchive writes layers (bottom first) as a docker save archive.
func dockerArchive(t *testing.T, layers ...v1.Layer) string {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(p, name.MustParseReference("test/sshole:1"), img); err != nil {
		t.Fatal(err)
	}
	return p
}

// Final review finding 1: an upper layer that spells a path with a leading
// slash replaces the lower layer's file, as a container runtime extracts
// it: the real sshd over a placeholder is found, and an upper sshd_config
// that turns PAM off is the one read.
func TestUpperLayerSpelledDifferently(t *testing.T) {
	scan := func(img string) []engine.Finding {
		var out, errb bytes.Buffer
		cli.Run(cfg, []string{"scan", "image", "--format", "json", "--detector", "sshole", "docker-archive:" + img}, &out, &errb)
		var r struct {
			Targets []struct {
				Error    string           `json:"error"`
				Findings []engine.Finding `json:"findings"`
			} `json:"targets"`
		}
		if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Targets) != 1 || r.Targets[0].Error != "" {
			t.Fatalf("%v %+v %s", err, r, errb.String())
		}
		return r.Targets[0].Findings
	}

	// The real sshd in the upper layer, a placeholder below.
	real := alpineRoot(t, "10.0_p1-r10")
	lower := t.TempDir()
	write(t, lower, "usr/sbin/sshd", []byte("placeholder"), 0o755)
	upper := t.TempDir()
	b, _ := os.ReadFile(filepath.Join(real, "usr/sbin/sshd"))
	write(t, upper, "usr/sbin/sshd", b, 0o755)
	fs := scan(dockerArchive(t, dirLayer(t, real, false, "usr/sbin/sshd"), dirLayer(t, lower, false), dirLayer(t, upper, true)))
	if len(fs) != 1 || fs[0].Verdict != engine.Vulnerable || fs[0].Severity != "critical" {
		t.Errorf("real sshd over a placeholder: %+v", fs)
	}

	// An upper sshd_config that turns PAM off.
	root := pamRoot(t)
	cfgUp := t.TempDir()
	write(t, cfgUp, "etc/ssh/sshd_config", []byte("UsePAM no\n"), 0o644)
	fs = scan(dockerArchive(t, dirLayer(t, root, false), dirLayer(t, cfgUp, true)))
	if len(fs) != 1 || fs[0].Verdict.Cleared() {
		t.Errorf("an upper sshd_config turning PAM off: %+v", fs)
	}
}
