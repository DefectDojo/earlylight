package source

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func tarOf(t testing.TB, files map[string]string) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.WriteHeader(&tar.Header{Name: "usr/bin/php", Typeflag: tar.TypeSymlink, Linkname: "php8.3"})
	tw.WriteHeader(&tar.Header{Name: "usr/bin/php-copy", Typeflag: tar.TypeLink, Linkname: "usr/bin/php8.3"})
	tw.Close()
	return buf.Bytes()
}

func TestTarReadFilterAndLinks(t *testing.T) {
	data := tarOf(t, map[string]string{"etc/a.conf": "a", "big": "0123456789", "usr/bin/php8.3": "\x7fELFxx"})
	var read []string
	links := map[string]string{}
	opts := Options{
		MaxFileSize: 5,
		Read: func(p string, head []byte, exe bool) (bool, Limit) {
			return p != "/etc/a.conf" || len(head) == 1, Limit{}
		},
		IsExecutable: func(h []byte) bool { return bytes.HasPrefix(h, []byte("\x7fELF")) },
		Symlink:      func(p, to string) { links[p] = to },
		Hardlink:     func(p, to string) { links[p] = to },
	}
	skips, n, err := Tar(bytes.NewReader(data), opts, func(f File) error {
		read = append(read, f.Path)
		if f.Path == "/usr/bin/php8.3" && !f.Executable {
			t.Error("executable not flagged")
		}
		return nil
	})
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(skips) != 2 { // big and the 6-byte executable are over the 5-byte limit
		t.Errorf("skips %v", skips)
	}
	if len(read) != 1 || read[0] != "/etc/a.conf" {
		t.Errorf("read %v", read)
	}
	if links["/usr/bin/php"] != "php8.3" || links["/usr/bin/php-copy"] != "/usr/bin/php8.3" {
		t.Errorf("links %v", links)
	}
}

// Tar reads hostile image layers: it must never panic or hang, whatever the bytes.
func FuzzTar(f *testing.F) {
	f.Add(tarOf(f, map[string]string{"a": "b"}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		Tar(bytes.NewReader(data), Options{MaxFileSize: 1 << 20}, func(File) error { return nil })
		// With a reader's own limit, nothing larger is ever handed out.
		limited := Options{MaxFileSize: 1 << 20, Read: func(string, []byte, bool) (bool, Limit) { return true, Limit{Bytes: 100, Name: "t"} }}
		Tar(bytes.NewReader(data), limited, func(f File) error {
			if len(f.Data) > 100 {
				t.Errorf("%s: %d bytes over a 100-byte limit", f.Path, len(f.Data))
			}
			return nil
		})
	})
}

// A reader's own limit below MaxFileSize skips a larger file as a deliberate
// exclusion naming who set it; MaxFileSize still applies under it.
func TestTarOwnLimit(t *testing.T) {
	data := tarOf(t, map[string]string{"etc/os-release": "0123456789", "etc/small": "01", "big": "0123456789abcdef"})
	var read []string
	opts := Options{
		MaxFileSize: 12,
		Read: func(p string, _ []byte, _ bool) (bool, Limit) {
			if p == "/big" {
				return true, Limit{Bytes: 100, Name: "t"} // above MaxFileSize: MaxFileSize applies
			}
			return true, Limit{Bytes: 4, Name: "the 4-byte limit of java4shell"}
		},
	}
	skips, _, err := Tar(bytes.NewReader(data), opts, func(f File) error { read = append(read, f.Path); return nil })
	if err != nil || len(read) != 1 || read[0] != "/etc/small" {
		t.Fatalf("read %v err %v", read, err)
	}
	got := map[string]Skip{}
	for _, s := range skips {
		got[s.Path] = s
	}
	if s := got["/etc/os-release"]; !s.Excluded || s.Reason != "excluded: larger than the 4-byte limit of java4shell for this file (10 bytes)" {
		t.Errorf("own limit: %+v", s)
	}
	if s := got["/big"]; s.Excluded || s.Reason != "larger than --max-file-size (16 bytes)" {
		t.Errorf("max file size: %+v", s)
	}
}

func TestDirOwnLimit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "os-release"), make([]byte, 5000), 0o600); err != nil {
		t.Fatal(err)
	}
	var read []string
	skips, n, err := Dir(root, Options{Read: func(string, []byte, bool) (bool, Limit) {
		return true, Limit{Bytes: 4096, Name: "the 4096-byte limit of t"}
	}},
		func(f File) error { read = append(read, f.Path); return nil })
	if err != nil || n != 1 || len(read) != 0 || len(skips) != 1 || !skips[0].Excluded ||
		skips[0].Reason != "excluded: larger than the 4096-byte limit of t for this file (5000 bytes)" {
		t.Fatalf("n %d read %v skips %+v err %v", n, read, skips, err)
	}
}

// A tar member over a reader's own limit is passed over, not read: a 128 MiB
// one costs about nothing.
func TestTarOwnLimitNeverReads(t *testing.T) {
	const size = 128 << 20
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: size, Typeflag: tar.TypeReg})
		io.CopyN(tw, zeros{}, size)
		tw.Close()
		pw.Close()
	}()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	skips, _, err := Tar(pr, Options{MaxFileSize: 256 << 20, Read: func(string, []byte, bool) (bool, Limit) { return true, Limit{Bytes: 64 << 10, Name: "t"} }},
		func(File) error { t.Error("visited"); return nil })
	runtime.ReadMemStats(&after)
	if err != nil || len(skips) != 1 || !skips[0].Excluded {
		t.Fatalf("skips %+v err %v", skips, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Errorf("passing over a 128 MiB member allocated %d bytes", alloc)
	}
}

type zeros struct{}

func (zeros) Read(b []byte) (int, error) { clear(b); return len(b), nil }
