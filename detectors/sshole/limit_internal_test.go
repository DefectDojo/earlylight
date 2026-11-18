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
// memory: the detector keeps one only up to 4 MiB, and one over that is a
// coverage gap.
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
	// The verdict reads it: a coverage gap, not an exclusion.
	if len(tg.Skipped) != 1 || tg.Skipped[0].Excluded || !strings.Contains(tg.Skipped[0].Reason, "sshole reads") || tg.Gaps() != 1 {
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
