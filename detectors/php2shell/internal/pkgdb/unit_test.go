package pkgdb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func hasProblem(ix *Index, sub string) bool {
	for _, p := range ix.Problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func pkgByName(ix *Index, name string) *Installed {
	for i, p := range ix.Packages() {
		if p.Package.Name == name {
			return &ix.Packages()[i]
		}
	}
	return nil
}

const statusFoo = `Package: foo
Status: install ok installed
Version: 1.0-1
Source: foosrc (1.0-0.1)
Architecture: all
Maintainer: X <x@y>
Description: test
 long
 .
 text

`

func TestDpkgDiversion(t *testing.T) {
	// Recorded from a real dpkg: after "dpkg-divert --local --rename --divert
	// /usr/bin/foo.orig --add /usr/bin/foo" and installing foo, foo's file is
	// on disk at /usr/bin/foo.orig while dpkg -S still answers for
	// /usr/bin/foo. The index records where the file is.
	files := map[string][]byte{
		"/var/lib/dpkg/status":           []byte(statusFoo),
		"/var/lib/dpkg/info/foo.list":    []byte("/.\n/usr\n/usr/bin\n/usr/bin/foo\n"),
		"/var/lib/dpkg/info/foo.md5sums": []byte("764efa883dda1e11db47671c4a3bbd9e  usr/bin/foo\n"),
		"/var/lib/dpkg/diversions":       []byte("/usr/bin/foo\n/usr/bin/foo.orig\n:\n"),
	}
	ix := Build(files)
	if len(ix.Problems) != 0 {
		t.Fatal(ix.Problems)
	}
	if o := ix.Owners("/usr/bin/foo"); len(o) != 0 {
		t.Errorf("/usr/bin/foo owners %v, want none (diverted)", o)
	}
	o := ix.Owners("/usr/bin/foo.orig")
	if len(o) != 1 || o[0].Package.Name != "foo" || hex.EncodeToString(o[0].File.Digest) != "764efa883dda1e11db47671c4a3bbd9e" {
		t.Errorf("/usr/bin/foo.orig owners %+v", o)
	}
	p := pkgByName(ix, "foo").Package
	if p.Source != "foosrc" || p.Version != "1.0-1" || p.Vendor != "X <x@y>" || p.Arch != "all" {
		t.Errorf("package %+v", p)
	}
	// The diverting package keeps its own file.
	files["/var/lib/dpkg/diversions"] = []byte("/usr/bin/foo\n/usr/bin/foo.orig\nfoo\n")
	if o := Build(files).Owners("/usr/bin/foo"); len(o) != 1 {
		t.Errorf("diverting package lost its file: %v", o)
	}
}

func TestDpkgStates(t *testing.T) {
	status := `Package: a
Status: install ok installed
Version: 1
Architecture: amd64

Package: b
Status: deinstall ok config-files
Version: 2
Architecture: amd64

Package: c
Status: install reinstreq half-installed
Version: 3
Architecture: amd64

Package: d
Status: install ok unpacked
Version: 4
Architecture: amd64

Package: e
Version: 5
Architecture: amd64

Package: libx
Status: install ok installed
Version: 6
Architecture: arm64
Multi-Arch: same

Package: libx
Status: install ok installed
Version: 6
Architecture: armhf
Multi-Arch: same
`
	files := map[string][]byte{"/var/lib/dpkg/status": []byte(status)}
	for _, n := range []string{"a", "b", "c", "d", "e", "libx:arm64", "libx:armhf"} {
		files["/var/lib/dpkg/info/"+n+".list"] = []byte("/usr/lib/" + n + "\n")
	}
	ix := Build(files)
	var names []string
	for _, p := range ix.Packages() {
		names = append(names, p.Package.Name+":"+p.Package.Arch)
	}
	want := []string{"a:amd64", "c:amd64", "d:amd64", "e:amd64", "libx:arm64", "libx:armhf"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("packages %v, want %v (config-files excluded)", names, want)
	}
	for _, sub := range []string{"c:amd64 is half-installed", "reinstreq", "e:amd64: missing or malformed Status"} {
		if !hasProblem(ix, sub) {
			t.Errorf("no problem %q in %v", sub, ix.Problems)
		}
	}
	if o := ix.Owners("/usr/lib/libx:armhf"); len(o) != 1 || o[0].Package.Arch != "armhf" {
		t.Errorf("multi-arch list: %v", o)
	}
	// Missing list file is a problem, not silence.
	delete(files, "/var/lib/dpkg/info/a.list")
	if !hasProblem(Build(files), "package a:amd64: no file list") {
		t.Error("missing .list not reported")
	}
}

func TestDpkgUpdatesJournal(t *testing.T) {
	files := map[string][]byte{
		"/var/lib/dpkg/status":        []byte(statusFoo),
		"/var/lib/dpkg/info/foo.list": []byte("/usr/bin/foo\n"),
		"/var/lib/dpkg/updates/0001":  []byte(strings.Replace(statusFoo, "1.0-1", "1.0-2", 1)),
		"/var/lib/dpkg/updates/0000":  []byte(strings.Replace(statusFoo, "1.0-1", "1.0-9", 1)),
		"/var/lib/dpkg/updates/tmp.i": []byte("garbage"),
	}
	ix := Build(files)
	if v := pkgByName(ix, "foo").Package.Version; v != "1.0-2" {
		t.Errorf("version %s, want the last journal entry 1.0-2", v)
	}
	if len(ix.Packages()) != 1 {
		t.Errorf("%d packages", len(ix.Packages()))
	}
}

func TestDpkgDistroless(t *testing.T) {
	files := map[string][]byte{
		"/var/lib/dpkg/status.d/libssl3":         []byte("Package: libssl3\nSource: openssl\nVersion: 3.0.20-1~deb12u2\nArchitecture: arm64\n"),
		"/var/lib/dpkg/status.d/libssl3.md5sums": []byte("30561bade1f57903c1f800c036f8b3c3  usr/lib/aarch64-linux-gnu/engines-3/afalg.so\n"),
		"/var/lib/dpkg/status.d/tzdata":          []byte("Package: tzdata\nVersion: 2025b-0+deb12u1\nArchitecture: all\n"),
	}
	ix := Build(files)
	if len(ix.Problems) != 0 {
		t.Fatal(ix.Problems)
	}
	if p := pkgByName(ix, "tzdata"); p == nil || len(p.Files) != 0 {
		t.Errorf("tzdata (no md5sums) must be listed with no files: %+v", p)
	}
	if o := ix.Owners("/usr/lib/aarch64-linux-gnu/engines-3/afalg.so"); len(o) != 1 || o[0].Package.Source != "openssl" {
		t.Errorf("owners %v", o)
	}
}

func TestDpkgMalformed(t *testing.T) {
	ix := Build(map[string][]byte{
		"/var/lib/dpkg/status":         []byte("Package: a\nStatus: install ok installed\nVersion: 1\nno colon here\n continuation\n"),
		"/var/lib/dpkg/info/a.list":    []byte("/x\n"),
		"/var/lib/dpkg/info/a.md5sums": []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  x\nshort\n"),
		"/var/lib/dpkg/diversions":     []byte("/a\n/b\n"),
	})
	for _, sub := range []string{"line 4: not a field", "bad md5", "not \"<md5>  <path>\"", "multiple of 3"} {
		if !hasProblem(ix, sub) {
			t.Errorf("no problem %q in %v", sub, ix.Problems)
		}
	}
	if pkgByName(ix, "a") == nil {
		t.Error("package a dropped")
	}
	if !hasProblem(Build(map[string][]byte{"/var/lib/dpkg/info/a.list": []byte("/x\n")}), "status is missing") {
		t.Error("lists without status not reported")
	}
}

func TestAPK(t *testing.T) {
	db := "C:Q1abc=\nP:php84\nV:8.4.21-r0\nA:aarch64\no:php84\nf:S\nF:usr/bin\nR:php84\nZ:Q1" +
		"AAECAwQFBgcICQoLDA0ODxAREhM=\n\nP:musl\nV:1.2.5-r10\nA:aarch64\nF:lib\nR:ld-musl-aarch64.so.1\nZ:Q2" +
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nR:x\nZ:Q1bad!\nW:new\n"
	ix := Build(map[string][]byte{"/lib/apk/db/installed": []byte(db)})
	o := ix.Owners("/usr/bin/php84")
	if len(o) != 1 || o[0].File.Algo != "sha256-160" || len(o[0].File.Digest) != 20 || o[0].Package.Source != "php84" {
		t.Errorf("php84: %+v", o)
	}
	o = ix.Owners("/lib/ld-musl-aarch64.so.1")
	if len(o) != 1 || o[0].File.Algo != "sha256" || o[0].Package.Source != "musl" {
		t.Errorf("musl: %+v", o)
	}
	for _, sub := range []string{"unreadable Z: checksum", "unknown field \"W\""} {
		if !hasProblem(ix, sub) {
			t.Errorf("no problem %q in %v", sub, ix.Problems)
		}
	}
	// Same database seen at /lib and /usr/lib is read once; different ones both, with a problem.
	ix = Build(map[string][]byte{"/lib/apk/db/installed": []byte(db), "/usr/lib/apk/db/installed": []byte(db)})
	if len(ix.DBs) != 1 {
		t.Errorf("DBs %v", ix.DBs)
	}
	ix = Build(map[string][]byte{"/lib/apk/db/installed": []byte(db), "/usr/lib/apk/db/installed": []byte("P:x\nV:1-r0\n")})
	if len(ix.DBs) != 2 || !hasProblem(ix, "both /lib/apk/db/installed and /usr/lib/apk/db/installed exist") {
		t.Errorf("DBs %v problems %v", ix.DBs, ix.Problems)
	}
}

// header builds an rpm header blob from (tag, type, value) entries.
func header(entries ...any) []byte {
	var index, store bytes.Buffer
	n := 0
	for i := 0; i < len(entries); i += 3 {
		tag, typ := entries[i].(int), entries[i+1].(int)
		var data []byte
		count := 1
		switch v := entries[i+2].(type) {
		case string:
			data = append([]byte(v), 0)
		case []string:
			for _, s := range v {
				data = append(data, append([]byte(s), 0)...)
			}
			count = len(v)
		case []uint32:
			for store.Len()%4 != 0 {
				store.WriteByte(0)
			}
			for _, x := range v {
				data = binary.BigEndian.AppendUint32(data, x)
			}
			count = len(v)
		case []byte:
			data, count = v, len(v)
		}
		for _, x := range []uint32{uint32(tag), uint32(typ), uint32(store.Len()), uint32(count)} {
			index.Write(binary.BigEndian.AppendUint32(nil, x))
		}
		store.Write(data)
		n++
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(n))
	out = binary.BigEndian.AppendUint32(out, uint32(store.Len()))
	return append(append(out, index.Bytes()...), store.Bytes()...)
}

func TestRPMHeader(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	h := header(
		tagName, typeString, "php-cli",
		tagVersion, typeString, "8.0.30",
		tagRelease, typeString, "1.el9_2",
		tagEpoch, typeInt32, []uint32{1},
		tagArch, typeString, "x86_64",
		tagVendor, typeString, "Red Hat, Inc.",
		tagSourceRPM, typeString, "php-8.0.30-1.el9_2.src.rpm",
		tagDirnames, typeStringArray, []string{"/usr/bin/", "/usr/share/doc/php-cli/"},
		tagBasenames, typeStringArray, []string{"php", "README", "ghost"},
		tagDirIndexes, typeInt32, []uint32{0, 1, 0},
		tagFileDigests, typeStringArray, []string{sha, sha, ""},
		tagFileDigestAlgo, typeInt32, []uint32{8},
		tagFileStates, typeChar, []byte{0, 2, 0},
		tagFileFlags, typeInt32, []uint32{0, 0, rpmFileGhost},
	)
	hd, err := parseHeaderBlob(h)
	if err != nil {
		t.Fatal(err)
	}
	inst, warn, err := headerPackage(hd, "/var/lib/rpm/rpmdb.sqlite")
	if err != nil || len(warn) != 0 {
		t.Fatal(err, warn)
	}
	want := Package{Format: RPM, Name: "php-cli", Version: "1:8.0.30-1.el9_2", Source: "php", Vendor: "Red Hat, Inc.", Arch: "x86_64", DB: "/var/lib/rpm/rpmdb.sqlite"}
	if inst.Package != want {
		t.Errorf("package %+v", inst.Package)
	}
	if len(inst.Files) != 3 || inst.Files[0].Path != "/usr/bin/php" || inst.Files[0].Algo != "sha256" ||
		inst.Files[1].Digest != nil /* not installed (nodocs) */ || inst.Files[2].Path != "/usr/bin/ghost" {
		t.Errorf("files %+v", inst.Files)
	}
	// Truncations and out-of-range offsets are errors, never panics.
	for i := 0; i < len(h); i++ {
		if _, err := parseHeaderBlob(h[:i]); err == nil {
			t.Fatalf("truncated header (%d of %d bytes) accepted", i, len(h))
		}
	}
	bad := append([]byte(nil), h...)
	binary.BigEndian.PutUint32(bad[8+8:], 1<<30) // first entry offset
	if _, err := parseHeaderBlob(bad); err == nil {
		t.Error("offset out of range accepted")
	}
}

func TestSourceName(t *testing.T) {
	for in, want := range map[string]string{
		"php-8.2.13-1.module+el9.4.0+20xxx+abcd1234.src.rpm": "php",
		"php-pecl-apcu-5.1.23-1.el9.src.rpm":                 "php-pecl-apcu",
		"php8-8.2.35-150600.3.39.1.src.rpm":                  "php8",
		"foo-1-2.nosrc.rpm":                                  "foo",
		"(none)":                                             "",
		"":                                                   "",
		"x.src.rpm":                                          "",
		"a-b.src.rpm":                                        "",
	} {
		if got := sourceName(in); got != want {
			t.Errorf("sourceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRPMNoSQLiteReader(t *testing.T) {
	saved := getSQLiteReader()
	RegisterRPMSQLiteReader(nil)
	defer RegisterRPMSQLiteReader(saved)
	ix := Build(map[string][]byte{"/var/lib/rpm/rpmdb.sqlite": []byte("SQLite format 3\x00")})
	if !hasProblem(ix, "no rpm sqlite reader") || ix.Empty() {
		t.Errorf("problems %v", ix.Problems)
	}
}

func TestRPMCorrupt(t *testing.T) {
	for _, f := range []string{"/var/lib/rpm/Packages", "/usr/lib/sysimage/rpm/Packages.db"} {
		for _, data := range [][]byte{nil, []byte("junk"), bytes.Repeat([]byte{0xff}, 8192)} {
			ix := Build(map[string][]byte{f: data})
			if len(ix.Problems) == 0 || len(ix.Packages()) != 0 {
				t.Errorf("%s %q: problems %v", f, data, ix.Problems)
			}
		}
	}
}

func TestNDBChecksum(t *testing.T) {
	// A one-package ndb database built the way rpmpkg.c writes it.
	blob := header(tagName, typeString, "x", tagVersion, typeString, "1", tagRelease, typeString, "1")
	db := make([]byte, ndbPage)
	le := binary.LittleEndian
	le.PutUint32(db, ndbMagic)
	le.PutUint32(db[12:], 1)
	for o := 32; o < ndbPage; o += 16 {
		le.PutUint32(db[o:], ndbSlotMagic)
	}
	blkoff := ndbPage / ndbBlk
	blks := (16 + len(blob) + 12 + ndbBlk - 1) / ndbBlk
	le.PutUint32(db[32+4:], 7)
	le.PutUint32(db[32+8:], uint32(blkoff))
	le.PutUint32(db[32+12:], uint32(blks))
	b := make([]byte, blks*ndbBlk)
	le.PutUint32(b, ndbBlobHead)
	le.PutUint32(b[4:], 7)
	le.PutUint32(b[12:], uint32(len(blob)))
	copy(b[16:], blob)
	tail := b[len(b)-12:]
	le.PutUint32(tail, adler32(adler32(1, b[:16]), b[16:len(b)-12]))
	le.PutUint32(tail[4:], uint32(len(blob)))
	le.PutUint32(tail[8:], ndbBlobTail)
	db = append(db, b...)
	ix := Build(map[string][]byte{"/usr/lib/sysimage/rpm/Packages.db": db})
	if len(ix.Problems) != 0 || len(ix.Packages()) != 1 || ix.Packages()[0].Package.Version != "1-1" {
		t.Fatalf("packages %+v problems %v", ix.Packages(), ix.Problems)
	}
	db[len(db)-20] ^= 1 // flip a byte inside the blob
	ix = Build(map[string][]byte{"/usr/lib/sysimage/rpm/Packages.db": db})
	if !hasProblem(ix, "checksum mismatch") || len(ix.Packages()) != 0 {
		t.Errorf("corrupt blob: problems %v", ix.Problems)
	}
}

func TestResolver(t *testing.T) {
	r := NewResolver(map[string]string{
		"/bin":                  "usr/bin",
		"/lib":                  "usr/lib",
		"/usr/lib64":            "lib",
		"/lib64":                "/usr/lib",
		"/etc/os-release":       "../usr/lib/os-release",
		"/usr/bin/php":          "/etc/alternatives/php",
		"/etc/alternatives/php": "/usr/bin/php8.2",
		"/loop/a":               "b",
		"/loop/b":               "a",
		"/up":                   "usr/lib/../bin",
		"/dot":                  "./usr/./bin/",
	})
	r.AddHardlink("/usr/bin/php-hard", "usr/bin/php8.2")
	for in, want := range map[string]string{
		"/bin/bash":       "/usr/bin/bash",
		"/bin/../lib/x":   "/usr/lib/x",
		"/usr/lib64/x":    "/usr/lib/x",
		"/lib64/ld.so":    "/usr/lib/ld.so",
		"/etc/os-release": "/etc/os-release", // last component not followed
		"/up/sh":          "/usr/bin/sh",
		"/dot/sh":         "/usr/bin/sh",
		"/../../bin/x":    "/usr/bin/x",
		"bin//x/":         "/usr/bin/x",
	} {
		if got, err := r.Canonical(in); err != nil || got != want {
			t.Errorf("Canonical(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if got, _ := r.Resolve("/usr/bin/php"); got != "/usr/bin/php8.2" {
		t.Errorf("Resolve(php) = %q", got)
	}
	if got, _ := r.Resolve("/etc/os-release"); got != "/usr/lib/os-release" {
		t.Errorf("Resolve(os-release) = %q", got)
	}
	if _, err := r.Resolve("/loop/a"); err != ErrLinkLoop {
		t.Errorf("loop: %v", err)
	}
	if _, err := r.Canonical("/loop/a/x"); err != ErrLinkLoop {
		t.Errorf("loop dir: %v", err)
	}
	got := r.Aliases("/usr/bin/php8.2")
	want := []string{"/bin/php-hard", "/bin/php8.2", "/dot/php-hard", "/dot/php8.2", "/up/php-hard", "/up/php8.2", "/usr/bin/php-hard", "/usr/bin/php8.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Aliases = %v\nwant %v", got, want)
	}
	got = r.Aliases("/lib/x")
	want = []string{"/lib/x", "/lib64/x", "/usr/lib/x", "/usr/lib64/x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Aliases = %v\nwant %v", got, want)
	}
	var nilR *Resolver
	if got := nilR.Aliases("x"); !reflect.DeepEqual(got, []string{"/x"}) {
		t.Errorf("nil resolver: %v", got)
	}
	// Owners through aliases: dpkg lists /bin/bash, the walk finds /usr/bin/bash.
	ix := NewIndex([]Installed{{Package: Package{Name: "bash"}, Files: []File{{Path: "/bin/bash"}}}}, nil, nil)
	if o := ix.OwnersOf(r, "/usr/bin/bash"); len(o) != 1 {
		t.Errorf("OwnersOf = %v", o)
	}
}

func TestOSRelease(t *testing.T) {
	os, ok := OSRelease(map[string][]byte{"/usr/lib/os-release": []byte("# c\nNAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian \\\"x\\\" 12\"\nID_LIKE='rhel fedora'\n")})
	if !ok || os.ID != "debian" || os.VersionID != "12" || os.Codename != "bookworm" || os.Pretty != `Debian "x" 12` || !reflect.DeepEqual(os.IDLike, []string{"rhel", "fedora"}) {
		t.Errorf("%+v", os)
	}
	if os, ok := OSRelease(map[string][]byte{"/etc/os-release": []byte("ID=alpine\nVERSION_ID=3.22.2\n"), "/usr/lib/os-release": []byte("ID=other\n")}); !ok || os.ID != "alpine" {
		t.Errorf("/etc first: %+v", os)
	}
	if os, ok := OSRelease(map[string][]byte{"/etc/alpine-release": []byte("3.23.0\n")}); !ok || os.ID != "alpine" || os.VersionID != "3.23.0" {
		t.Errorf("alpine-release: %+v", os)
	}
	if os, ok := OSRelease(map[string][]byte{"/etc/debian_version": []byte("trixie/sid\n")}); !ok || os.Codename != "trixie" {
		t.Errorf("debian_version: %+v", os)
	}
	if _, ok := OSRelease(nil); ok {
		t.Error("empty accepted")
	}
}

func TestWanted(t *testing.T) {
	for _, p := range []string{"/var/lib/dpkg/status", "/var/lib/dpkg/info/libc6:arm64.list", "/var/lib/dpkg/info/a.md5sums",
		"/var/lib/dpkg/status.d/libc6", "/var/lib/dpkg/status.d/libc6.md5sums", "/var/lib/dpkg/updates/0003", "/var/lib/dpkg/diversions",
		"/lib/apk/db/installed", "/usr/lib/apk/db/installed", "/var/lib/rpm/Packages", "/var/lib/rpm/rpmdb.sqlite",
		"/var/lib/rpm/rpmdb.sqlite-wal", "/usr/lib/sysimage/rpm/Packages.db", "/etc/os-release", "/usr/lib/os-release",
		"/etc/debian_version", "/etc/alpine-release", "var/lib/dpkg/status", "/var/lib/chisel/manifest.wall"} {
		if !Wanted(p) {
			t.Errorf("Wanted(%q) = false", p)
		}
	}
	for _, p := range []string{"/var/lib/dpkg/info/a.postinst", "/var/lib/dpkg/updates/tmp.i", "/var/lib/rpm/Name", "/var/lib/rpm/__db.001",
		"/var/lib/rpm/rpmdb.sqlite-shm", "/usr/bin/php", "/var/lib/dpkg/status-old", "/var/lib/dpkg/status.d/.hidden", "/etc/os-release/x"} {
		if Wanted(p) {
			t.Errorf("Wanted(%q) = true", p)
		}
	}
}

// makeBDB builds a Berkeley DB hash database the way rpm's Packages looks:
// record 0 (rpm's instance counter) inline, the first blob inline, the others
// on overflow pages. One bucket; page size 512.
func makeBDB(bo binary.ByteOrder, blobs ...[]byte) []byte {
	u32 := func(b []byte, v uint32) []byte { var x [4]byte; bo.PutUint32(x[:], v); return append(b, x[:]...) }
	const ps = 512
	pages := [][]byte{make([]byte, ps), make([]byte, ps)}
	var items [][]byte
	items = append(items, []byte{bdbItemKeyData, 0, 0, 0, 0}, append([]byte{bdbItemKeyData}, u32(nil, uint32(len(blobs)+1))...))
	for i, b := range blobs {
		key := append([]byte{bdbItemKeyData}, u32(nil, uint32(i+1))...)
		if i == 0 {
			items = append(items, key, append([]byte{bdbItemKeyData}, b...))
			continue
		}
		first := uint32(len(pages))
		for off := 0; off < len(b); off += ps - bdbPageHeader {
			p := make([]byte, ps)
			n := copy(p[bdbPageHeader:], b[off:])
			p[25] = bdbPageOverflow
			bo.PutUint16(p[22:], uint16(n))
			if off+n < len(b) {
				bo.PutUint32(p[16:], uint32(len(pages)+1))
			}
			pages = append(pages, p)
		}
		ref := []byte{bdbItemOffPage, 0, 0, 0}
		ref = u32(ref, first)
		ref = u32(ref, uint32(len(b)))
		items = append(items, key, ref)
	}
	hp := pages[1]
	hp[25] = bdbPageHash
	bo.PutUint16(hp[20:], uint16(len(items)))
	end := ps
	for i, it := range items {
		end -= len(it)
		copy(hp[end:], it)
		bo.PutUint16(hp[bdbPageHeader+2*i:], uint16(end))
	}
	m := pages[0]
	bo.PutUint32(m[12:], bdbHashMagic)
	bo.PutUint32(m[16:], 9)
	bo.PutUint32(m[20:], ps)
	m[25] = bdbPageHashMeta
	bo.PutUint32(m[32:], uint32(len(pages)-1))
	bo.PutUint32(m[88:], uint32(len(items)/2))
	bo.PutUint32(m[96:], 1) // spares[0]: bucket 0 is page 1
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

func smallHeader(name, ver string) []byte {
	return header(tagName, typeString, name, tagVersion, typeString, ver, tagRelease, typeString, "1",
		tagDirnames, typeStringArray, []string{"/usr/bin/"}, tagBasenames, typeStringArray, []string{name},
		tagDirIndexes, typeInt32, []uint32{0})
}

func TestBDBSynthetic(t *testing.T) {
	big := header(tagName, typeString, "big", tagVersion, typeString, "2", tagRelease, typeString, "1",
		tagSourceRPM, typeString, strings.Repeat("x", 1500)+"-1-1.src.rpm")
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		db := makeBDB(bo, smallHeader("small", "1"), big)
		ix := Build(map[string][]byte{"/var/lib/rpm/Packages": db})
		if len(ix.Problems) != 0 || len(ix.Packages()) != 2 {
			t.Fatalf("%v: packages %d, problems %v", bo, len(ix.Packages()), ix.Problems)
		}
		if o := ix.Owners("/usr/bin/small"); len(o) != 1 {
			t.Errorf("%v: inline record lost: %v", bo, o)
		}
		// Truncation anywhere is a problem, never a panic or a silent drop.
		for _, n := range []int{0, 100, 512, 1000, len(db) - 1} {
			ix := Build(map[string][]byte{"/var/lib/rpm/Packages": db[:n]})
			if len(ix.Problems) == 0 {
				t.Errorf("%v: truncated to %d: no problem", bo, n)
			}
		}
		// A wrong record count in the metadata is reported.
		bad := append([]byte(nil), db...)
		bo.PutUint32(bad[88:], 7)
		if !hasProblem(Build(map[string][]byte{"/var/lib/rpm/Packages": bad}), "hash metadata counts 7") {
			t.Errorf("%v: nelem mismatch not reported", bo)
		}
	}
}

func makeNDB(blobs ...[]byte) []byte {
	db := make([]byte, ndbPage)
	le := binary.LittleEndian
	le.PutUint32(db, ndbMagic)
	le.PutUint32(db[12:], 1)
	for o := 32; o < ndbPage; o += 16 {
		le.PutUint32(db[o:], ndbSlotMagic)
	}
	for i, blob := range blobs {
		blkoff := len(db) / ndbBlk
		blks := (16 + len(blob) + 12 + ndbBlk - 1) / ndbBlk
		s := db[32+16*i:]
		le.PutUint32(s[4:], uint32(i+1))
		le.PutUint32(s[8:], uint32(blkoff))
		le.PutUint32(s[12:], uint32(blks))
		b := make([]byte, blks*ndbBlk)
		le.PutUint32(b, ndbBlobHead)
		le.PutUint32(b[4:], uint32(i+1))
		le.PutUint32(b[12:], uint32(len(blob)))
		copy(b[16:], blob)
		tail := b[len(b)-12:]
		le.PutUint32(tail, adler32(adler32(1, b[:16]), b[16:len(b)-12]))
		le.PutUint32(tail[4:], uint32(len(blob)))
		le.PutUint32(tail[8:], ndbBlobTail)
		db = append(db, b...)
	}
	return db
}

// TestBinaryMutations: random byte corruption of BDB and ndb databases never
// panics, and every package is either read or a problem is recorded.
func TestBinaryMutations(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	cases := map[string][]byte{
		"/var/lib/rpm/Packages":             makeBDB(binary.LittleEndian, smallHeader("a", "1"), smallHeader("b", "2"), header(tagName, typeString, "c", tagVersion, typeString, "3", tagRelease, typeString, strings.Repeat("r", 900))),
		"/usr/lib/sysimage/rpm/Packages.db": makeNDB(smallHeader("a", "1"), smallHeader("b", "2")),
	}
	for p, seed := range cases {
		for i := 0; i < 20000; i++ {
			d := append([]byte(nil), seed...)
			for k := 0; k < 1+r.Intn(4); k++ {
				d[r.Intn(len(d))] = byte(r.Intn(256))
			}
			if r.Intn(10) == 0 {
				d = d[:r.Intn(len(d))]
			}
			ix := Build(map[string][]byte{p: d})
			if len(ix.Packages()) < 2 && len(ix.Problems) == 0 && !bytes.Equal(d, seed) {
				t.Fatalf("%s: mutation %d lost packages silently (%d read)", p, i, len(ix.Packages()))
			}
		}
	}
}
