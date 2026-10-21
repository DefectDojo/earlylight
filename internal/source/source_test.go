package source

import (
	"archive/tar"
	"bytes"
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
		MaxFileSize:  5,
		Read:         func(p string, head []byte, exe bool) bool { return p != "/etc/a.conf" || len(head) == 1 },
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
	})
}
