package pkgdb

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"path"
	"strings"
	"testing"
)

// fixtureFiles returns files from testdata/images whose path ends in suffix.
func fixtureFiles(f *testing.F, suffix string, max int) [][]byte {
	var out [][]byte
	ms, _ := os.ReadDir("testdata/images")
	for _, m := range ms {
		fh, err := os.Open(path.Join("testdata/images", m.Name()))
		if err != nil {
			f.Fatal(err)
		}
		zr, err := gzip.NewReader(fh)
		if err != nil {
			f.Fatal(err)
		}
		tr := tar.NewReader(zr)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			if h.Typeflag == tar.TypeReg && strings.HasSuffix(h.Name, suffix) && len(out) < max {
				b, _ := io.ReadAll(tr)
				out = append(out, b)
			}
		}
		fh.Close()
	}
	return out
}

func FuzzParseDpkgStatus(f *testing.F) {
	for _, b := range fixtureFiles(f, "var/lib/dpkg/status", 4) {
		f.Add(b[:min(len(b), 4096)])
	}
	f.Add([]byte(statusFoo))
	f.Fuzz(func(t *testing.T, data []byte) {
		ps, _ := parseDeb822(data)
		for _, p := range ps {
			if len(p.fields) == 0 {
				t.Fatal("empty paragraph returned")
			}
		}
		// The whole dpkg reader on the same bytes, as status and as status.d.
		Build(map[string][]byte{"/var/lib/dpkg/status": data, "/var/lib/dpkg/status.d/x": data, "/var/lib/dpkg/diversions": data, "/var/lib/dpkg/info/x.list": data})
	})
}

func FuzzParseMD5Sums(f *testing.F) {
	for _, b := range fixtureFiles(f, ".md5sums", 8) {
		f.Add(b[:min(len(b), 2048)])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		m, _ := parseMD5Sums(data)
		for p, d := range m {
			if len(d) != 16 || !strings.HasPrefix(p, "/") || path.Clean(p) != p {
				t.Fatalf("bad entry %q %x", p, d)
			}
		}
	})
}

func FuzzParseAPKInstalled(f *testing.F) {
	for _, b := range fixtureFiles(f, "lib/apk/db/installed", 3) {
		f.Add(b[:min(len(b), 4096)])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pkgs, _ := parseAPKInstalled(data, "/lib/apk/db/installed")
		for _, p := range pkgs {
			if p.Package.Name == "" || p.Package.Source == "" {
				t.Fatalf("package without name or source: %+v", p.Package)
			}
			for _, fl := range p.Files {
				if (fl.Algo == "") != (fl.Digest == nil) {
					t.Fatalf("digest without algorithm: %+v", fl)
				}
			}
		}
	})
}

func FuzzParseHeaderBlob(f *testing.F) {
	f.Add(header(tagName, typeString, "x", tagVersion, typeString, "1", tagRelease, typeString, "1",
		tagBasenames, typeStringArray, []string{"a"}, tagDirnames, typeStringArray, []string{"/"}, tagDirIndexes, typeInt32, []uint32{0}))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := parseHeaderBlob(data)
		if err != nil {
			return
		}
		headerPackage(h, "db")
	})
}

func FuzzReadBDB(f *testing.F) {
	f.Add(makeBDB(binary.LittleEndian, smallHeader("a", "1"), smallHeader("b", "2")))
	f.Add(makeBDB(binary.BigEndian, smallHeader("a", "1")))
	f.Fuzz(func(t *testing.T, data []byte) {
		Build(map[string][]byte{"/var/lib/rpm/Packages": data})
	})
}

func FuzzReadNDB(f *testing.F) {
	f.Add(makeNDB(smallHeader("a", "1")))
	f.Fuzz(func(t *testing.T, data []byte) {
		Build(map[string][]byte{"/usr/lib/sysimage/rpm/Packages.db": data})
	})
}

// FuzzResolver: links come as "path=target" lines, the last line is the query.
func FuzzResolver(f *testing.F) {
	f.Add("/bin=usr/bin\n/lib=usr/lib\n/usr/lib64=lib\n/lib64=/usr/lib\n/a=b\n/b=a\n/bin/x")
	f.Add("/x=../../..\n/y=/x/y\n/y/z")
	f.Fuzz(func(t *testing.T, s string) {
		lines := strings.Split(s, "\n")
		r := NewResolver(nil)
		for _, l := range lines[:len(lines)-1] {
			if k, v, ok := strings.Cut(l, "="); ok {
				r.AddSymlink(k, v)
			}
		}
		q := lines[len(lines)-1]
		c, err := r.Canonical(q)
		if err != nil {
			return
		}
		if !strings.HasPrefix(c, "/") || path.Clean(c) != c {
			t.Fatalf("Canonical(%q) = %q not clean", q, c)
		}
		if c2, err := r.Canonical(c); err != nil || c2 != c {
			t.Fatalf("Canonical not idempotent: %q -> %q -> %q (%v)", q, c, c2, err)
		}
		as := r.Aliases(q)
		if len(as) == 0 || len(as) > maxAliases {
			t.Fatalf("%d aliases", len(as))
		}
		found := false
		for i, a := range as {
			if i > 0 && as[i-1] >= a {
				t.Fatalf("aliases not sorted/unique: %q", as)
			}
			if a == clean(q) {
				found = true
			}
			if ca, err := r.Canonical(a); err == nil && ca != c {
				t.Fatalf("alias %q of %q canonicalizes to %q, not %q", a, q, ca, c)
			}
		}
		if cq, err := r.Canonical(clean(q)); !found && err == nil && cq == c {
			t.Fatalf("Aliases(%q) = %q lacks the path itself", q, as)
		}
	})
}
