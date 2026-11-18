package sshole

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/engine"
)

// A hostile account file as large as --max-file-size is not read into
// memory: the detector keeps one only up to 4 MiB.
func TestKeptFileBounded(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, "etc/shadow"))
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("root:*:19000:0:99999:7:::\n")
	if err := f.Truncate(128 << 20); err != nil { // sparse
		t.Fatal(err)
	}
	f.Close()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true, MaxFileSize: 256 << 20})
	runtime.ReadMemStats(&after)
	if a := after.TotalAlloc - before.TotalAlloc; a > 8<<20 {
		t.Errorf("a 128 MiB /etc/shadow cost %d bytes", a)
	}
	// With no OpenSSH server in the target, no verdict reads it: an
	// exclusion, not a gap.
	if len(tg.Skipped) != 1 || !tg.Skipped[0].Excluded || !strings.Contains(tg.Skipped[0].Reason, "limit of sshole") || tg.Gaps() != 0 {
		t.Errorf("skipped %+v", tg.Skipped)
	}
}

// Each limit is the one Visit applies after reading.
func TestLimits(t *testing.T) {
	elf := []byte("\x7fELF\x02\x01\x01")
	script := []byte("#!/bin/sh\n")
	d := &Detector{}
	for _, c := range []struct {
		path string
		head []byte
		want int64
	}{
		{"/etc/shadow", []byte("root:"), maxKept},
		{"/etc/ssh/sshd_config", script, maxKept},
		{"/docker-entrypoint.sh", script, maxScript},
		{"/usr/sbin/sshd", elf, 0},
		{"/etc/ssh/sshd_config", elf, 0}, // an executable is inspected whole
		{"/usr/share/doc/x", []byte("text"), 0},
	} {
		if got := d.Limit(c.path, c.head, false); got != c.want {
			t.Errorf("%s %q: limit %d, want %d", c.path, c.head, got, c.want)
		}
	}
}

// Round-2 review finding 5, round-3 finding 2: when an image names a path
// again, the engine has the scan forget the first entry, read or not.
func TestForget(t *testing.T) {
	const p = "/etc/cont-init.d/10-sshd"
	s := (&Detector{}).NewScan(engine.Image).(*scan)
	s.Visit(engine.File{Path: p, Data: []byte("#!/bin/sh\nexec /usr/sbin/sshd -D\n")})
	s.Forget(p)
	s.VisitOverLimit(p, maxScript+1)
	if _, ok := s.scripts[p]; ok || !s.unreadScripts[p] || s.scriptBytes != 0 {
		t.Errorf("read then over: scripts %v unread %v bytes %d", s.scripts, s.unreadScripts, s.scriptBytes)
	}
	s.Forget(p)
	s.Visit(engine.File{Path: p, Data: []byte("#!/bin/sh\n")})
	if _, ok := s.scripts[p]; !ok || s.unreadScripts[p] {
		t.Errorf("over then read: scripts %v unread %v", s.scripts, s.unreadScripts)
	}
	const c = "/etc/ssh/sshd_config.d/50-site.conf"
	s.Visit(engine.File{Path: c, Data: []byte("UsePAM yes\n")})
	s.Forget(c)
	s.VisitOverLimit(c, maxKept+1)
	if _, ok := s.files[c]; ok || !s.over[c] {
		t.Errorf("config read then over: files %v over %v", s.files, s.over)
	}
}
