//go:build unix

package source

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A file swapped for a FIFO or a symlink after the walk saw it must be skipped,
// never read: a FIFO would block the scan forever, a symlink would read a file
// outside the scanned tree.
func TestSwappedFileIsNotRead(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("outside"), 0o600)
	for _, swap := range []string{"fifo", "symlink"} {
		p := filepath.Join(dir, swap)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		os.Remove(p)
		if swap == "fifo" {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Skip("mkfifo:", err)
			}
		} else if err := os.Symlink(secret, p); err != nil {
			t.Fatal(err)
		}
		var skips []Skip
		read := false
		done := make(chan struct{})
		go func() {
			readOne(p, "/"+swap, fi, Options{}, func(File) error { read = true; return nil }, &skips)
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: readOne blocked", swap)
		}
		if read || len(skips) != 1 {
			t.Fatalf("%s: read=%v skips=%v", swap, read, skips)
		}
		if swap == "fifo" && !strings.Contains(skips[0].Reason, "changed while") {
			t.Errorf("fifo skip reason %q", skips[0].Reason)
		}
	}
}
