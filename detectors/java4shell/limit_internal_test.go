package java4shell

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/engine"
)

// allocated returns the bytes f allocates.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func excludedFor(tg *engine.Target, p string) bool {
	for _, s := range tg.Skipped {
		if s.Path == p && s.Excluded && strings.Contains(s.Reason, "limit of "+ID) {
			return true
		}
	}
	return false
}

// Sensei review: a hostile os-release as large as --max-file-size is not
// read into memory. The detector ignores one over 64 KiB, so the engine
// never reads it past its head.
func TestOSReleaseBounded(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, "etc/os-release"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("ID=ubuntu\nVERSION_ID=24.04\n")
	if err := f.Truncate(128 << 20); err != nil { // sparse
		t.Fatal(err)
	}
	f.Close()
	var tg *engine.Target
	if a := allocated(func() {
		tg = engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true, MaxFileSize: 256 << 20})
	}); a > 8<<20 {
		t.Errorf("a 128 MiB os-release cost %d bytes", a)
	}
	if !excludedFor(tg, "/etc/os-release") || tg.Gaps() != 0 {
		t.Errorf("skipped %+v", tg.Skipped)
	}
}

// The os-release probe of a move's current image does not read a large
// os-release either.
func TestOSProbeBounded(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := append([]byte("ID=ubuntu\nVERSION_ID=24.04\n"), make([]byte, 16<<20)...)
	tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	small := []byte("ID=alpine\nVERSION_ID=3.22.1\n")
	tw.WriteHeader(&tar.Header{Name: "usr/lib/os-release", Mode: 0o644, Size: int64(len(small)), Typeflag: tar.TypeReg})
	tw.Write(small)
	tw.Close()
	p := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	body, buf = nil, bytes.Buffer{}
	var tg *engine.Target
	if a := allocated(func() {
		tg = engine.ScanImage([]engine.Detector{osProbe{}}, "rootfs:"+p, engine.Options{MaxFileSize: 256 << 20})
	}); a > 4<<20 {
		t.Errorf("a 16 MiB os-release cost %d bytes", a)
	}
	if tg.Error != "" || tg.Annotations["java4shell_os"] != "alpine 3.22.1" || len(tg.Skipped) != 1 || !tg.Skipped[0].Excluded {
		t.Errorf("error %q annotations %v skipped %+v", tg.Error, tg.Annotations, tg.Skipped)
	}
}

// Each limit is the one Visit applies after reading, so the detector sees
// every file it would have kept.
func TestLimits(t *testing.T) {
	elf := []byte("\x7fELF\x02\x01\x01")
	script := []byte("#!/bin/sh\n")
	d := &Detector{}
	for _, c := range []struct {
		path string
		head []byte
		want int64
	}{
		{"/etc/os-release", []byte("ID=x"), maxOSRelease},
		{"/usr/lib/os-release", script, maxScript}, // a script is kept up to its own limit
		{"/var/lib/dpkg/status", []byte("Package: x"), maxKept},
		{"/lib/apk/db/installed", script, maxKept},
		{"/var/lib/dpkg/info/openjdk-21-jre-headless:amd64.list", []byte("/."), maxKept},
		{"/opt/app/bin/start.sh", script, maxScript},
		{"/opt/app/hs_err_pid42.log", []byte("#"), maxHsErr},
		{"/opt/app/hs_err_pid42.log", script, maxHsErr},
		{"/etc/systemd/system/app.service", []byte("[Service]"), maxSetting},
		{"/usr/lib/jvm/java-21/lib/server/libjvm.so", elf, 0},
		{"/usr/lib/jvm/java-21/release", []byte("JAVA_VERSION="), 0}, // its size is part of the verdict
		{"/usr/bin/ls", elf, 0},
		{"/etc/passwd", []byte("root:x:0:0"), 0},
	} {
		if got := d.Limit(c.path, c.head, false); got != c.want {
			t.Errorf("%s %q: limit %d, want %d", c.path, c.head, got, c.want)
		}
	}
	if osProbe.Limit(osProbe{}, "/etc/os-release", nil, false) != maxOSRelease {
		t.Error("the os-release probe has no limit")
	}
}

// At its limit an os-release is still read and used.
func TestOSReleaseAtLimit(t *testing.T) {
	root := t.TempDir()
	body := []byte("ID=debian\nVERSION_ID=\"12\"\n")
	body = append(body, bytes.Repeat([]byte("#"), maxOSRelease-len(body))...)
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/os-release"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := (&Detector{}).NewScan(engine.Image).(*scan)
	s.Visit(engine.File{Path: "/etc/os-release", Data: body})
	if osRelease(s.kept["/etc/os-release"]) != "debian 12" {
		t.Errorf("a %d-byte os-release was not used", len(body))
	}
	if tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true}); len(tg.Skipped) != 0 {
		t.Errorf("skipped %+v", tg.Skipped)
	}
}

// A JVM settings file over the limit is a coverage gap; the other files
// with a limit are deliberate exclusions.
func TestOverLimitGaps(t *testing.T) {
	root := t.TempDir()
	for rel, size := range map[string]int64{
		"opt/atlassian/confluence/bin/setenv.sh": maxSetting + 1,
		"etc/os-release":                         maxOSRelease + 1,
		"opt/install.sh":                         maxScript + 1,
		"var/lib/dpkg/status":                    maxKept + 1,
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		head := []byte("X=1\n")
		if strings.HasSuffix(rel, ".sh") {
			head = []byte("#!/bin/sh\n")
		}
		if err := os.WriteFile(p, head, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(p, size); err != nil {
			t.Fatal(err)
		}
	}
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
	got := map[string]bool{}
	for _, s := range tg.Skipped {
		got[s.Path] = s.Excluded
	}
	want := map[string]bool{"/opt/atlassian/confluence/bin/setenv.sh": false, "/etc/os-release": true, "/opt/install.sh": true, "/var/lib/dpkg/status": true}
	if len(got) != len(want) || tg.Gaps() != 1 {
		t.Fatalf("skipped %+v", tg.Skipped)
	}
	for p, ex := range want {
		if got[p] != ex {
			t.Errorf("%s: excluded %v, want %v", p, got[p], ex)
		}
	}
}

// A script over the limit is remembered as unread, and of several entries
// for one path the last decides.
func TestUnreadScripts(t *testing.T) {
	s := (&Detector{}).NewScan(engine.Image).(*scan)
	s.VisitOverLimit("/entrypoint.sh", 300<<10)
	s.VisitOverLimit("/etc/os-release", 300<<10)
	if !s.unreadScripts["/entrypoint.sh"] || s.unreadScripts["/etc/os-release"] {
		t.Fatalf("unread %v", s.unreadScripts)
	}
	s.Visit(engine.File{Path: "/entrypoint.sh", Data: []byte("#!/bin/sh\nexec java $JAVA_OPTS -jar /app.jar\n")})
	if s.unreadScripts["/entrypoint.sh"] || !s.scripts["/entrypoint.sh"]["JAVA_OPTS"] {
		t.Errorf("read after unread: unread %v scripts %v", s.unreadScripts, s.scripts)
	}
	s.VisitOverLimit("/entrypoint.sh", 300<<10)
	if !s.unreadScripts["/entrypoint.sh"] || s.scripts["/entrypoint.sh"] != nil {
		t.Errorf("unread after read: unread %v scripts %v", s.unreadScripts, s.scripts)
	}
}
