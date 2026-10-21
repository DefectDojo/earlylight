package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func zipOf(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, b := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

func tarOf(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	tw.Close()
	return buf.Bytes()
}

func collect(t *testing.T, path string, data []byte, lim Limits) (map[string]string, []string) {
	seen := map[string]string{}
	var skips []string
	Walk(path, data, lim, func(p string, b []byte) { seen[p] = string(b) }, func(p, r string) { skips = append(skips, p+": "+r) })
	return seen, skips
}

func TestNested(t *testing.T) {
	inner := zipOf(t, map[string][]byte{"cacerts": []byte("STORE")})
	war := zipOf(t, map[string][]byte{"WEB-INF/lib/lib.jar": inner, "index.html": []byte("hi")})
	tgz := gzOf(t, tarOf(t, map[string][]byte{"app/app.war": war}))
	seen, skips := collect(t, "/opt/app.tgz", tgz, DefaultLimits)
	if len(skips) != 0 {
		t.Fatalf("skips: %v", skips)
	}
	want := "/opt/app.tgz!/app/app.war!/WEB-INF/lib/lib.jar!/cacerts"
	if seen[want] != "STORE" {
		var keys []string
		for k := range seen {
			keys = append(keys, k)
		}
		t.Fatalf("missing %s; got %s", want, strings.Join(keys, "\n"))
	}
}

func TestDepthLimit(t *testing.T) {
	b := []byte("STORE")
	for i := 0; i < 6; i++ {
		b = zipOf(t, map[string][]byte{"x": b})
	}
	seen, skips := collect(t, "/deep.zip", b, Limits{MaxDepth: 3, MaxMemberSize: 1 << 20, MaxArchiveSize: 1 << 20})
	for _, v := range seen {
		if v == "STORE" {
			t.Fatal("went deeper than the limit")
		}
	}
	if len(skips) == 0 {
		t.Fatal("depth limit not reported as a skip")
	}
}

func TestBombIsBounded(t *testing.T) {
	big := bytes.Repeat([]byte{0}, 8<<20) // compresses to almost nothing
	z := zipOf(t, map[string][]byte{"bomb": big})
	_, skips := collect(t, "/bomb.zip", z, Limits{MaxDepth: 4, MaxMemberSize: 1 << 20, MaxArchiveSize: 1 << 20})
	if len(skips) != 1 {
		t.Fatalf("want one skip, got %v", skips)
	}
}

func TestNonArchiveVisitedOnce(t *testing.T) {
	seen, skips := collect(t, "/etc/ssl/certs/ca-certificates.crt", []byte("-----BEGIN CERTIFICATE-----"), DefaultLimits)
	if len(seen) != 1 || len(skips) != 0 {
		t.Fatalf("got %v %v", seen, skips)
	}
}

func FuzzWalk(f *testing.F) {
	f.Add([]byte("PK\x03\x04garbage"))
	f.Add([]byte{0x1f, 0x8b, 8, 0})
	// Each format's magic alone, then a small valid instance of each.
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0x58})
	f.Add([]byte{0xfd, '7', 'z', 'X', 'Z', 0, 0, 4})
	f.Add([]byte("BZh91AY&SY\x00\x00"))
	f.Add([]byte("!<arch>\ndebian-binary   "))
	f.Add([]byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	f.Add([]byte("07070100000001"))
	f.Add([]byte("\x7fELF\x02\x01\x01" + pyiMagic + "\x00\x00\x00\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x38"))
	f.Add([]byte("\x7fELF\x02\x01\x01\x03\x00\x00UPX!"))
	tarball := tarList(f, file{"./etc/ssl/ca.pem", []byte("STORE")}, file{"b", []byte("x")})
	cp := cpioOf(file{"./etc/ca.pem", []byte("STORE")})
	f.Add(zstdOf(f, tarball))
	f.Add(xzOf(f, tarball))
	f.Add([]byte(tarBz2))
	f.Add(arOf([]file{{"debian-binary", []byte("2.0\n")}, {"data.tar.xz", xzOf(f, tarball)}}, "deb"))
	f.Add(arOf([]file{{"a-long-member-name.o", []byte("x")}}, "gnu-long"))
	f.Add(arOf([]file{{"a-long-member-name.o", []byte("x")}}, "bsd"))
	f.Add(cp)
	f.Add(rpmOf("gzip", gzOf(f, cp)))
	f.Add(rpmOf("zstd", zstdOf(f, cp)))
	f.Add(pyiOf(f, 88, pyiFile{name: "certifi/cacert.pem", data: []byte("STORE"), compress: true}, pyiFile{name: "x", data: []byte("y")}))
	f.Add(pyiOf(f, 24, pyiFile{name: "a", data: []byte("STORE")}))
	f.Fuzz(func(t *testing.T, b []byte) {
		Walk("/f", b, Limits{MaxDepth: 3, MaxMemberSize: 1 << 20, MaxArchiveSize: 4 << 20}, func(string, []byte) {}, func(string, string) {})
	})
}
