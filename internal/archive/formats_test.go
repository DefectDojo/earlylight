package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// tarBz2 is a ustar archive holding etc/ssl/certs/ca.pem = "STORE", made with
// Python's tarfile and bz2 modules (the standard library cannot write bzip2).
const tarBz2 = "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x55\x24\xcb\x4a\x00\x00\x74\xff\x80\xc9\x80\x00\x02\x40\x01\xf7\x00\x02\x04\x9c\x00\x6a\x06\x5e\x00\x08\x08\x20\x00\x54\x34\xa7\xa9\xea\x1a\x00\x0c\x9a\x1e\xa3\xca\x09\x25\x06\x80\xd1\xa0\x01\xa0\x7d\xcd\x64\x88\x41\x09\x90\x84\x3e\x37\xd2\x42\xca\xa8\x40\x86\x06\x37\xee\x3d\x60\xe1\x39\x84\x48\xc8\x1c\x72\xbf\x19\x6f\x55\x93\xa3\xbe\x9f\xc4\xcd\x82\x86\xa5\x62\xdf\x4c\xe0\x90\x73\x45\x7c\x08\x88\x0f\xc5\xdc\x91\x4e\x14\x24\x15\x49\x32\xd2\x80"

// bz2Bomb is 8 MiB of zero bytes in 48 bytes of bzip2.
const bz2Bomb = "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\xa2\x3d\x4b\x58\x00\x40\x40\x40\x80\xc0\x00\x00\x04\x00\x08\x20\x00\x30\xcc\x05\x29\xa6\x01\x00\xd8\x80\x80\x78\xbb\x92\x29\xc2\x84\x85\x11\xea\x5a\xc0"

func zstdOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func xzOf(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := xz.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	zw.Write(b)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type file struct {
	name string
	data []byte
}

// tarList keeps member order, unlike tarOf.
func tarList(t testing.TB, files ...file) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		tw.Write(f.data)
	}
	tw.Close()
	return buf.Bytes()
}

// arOf writes an ar archive. GNU-style names ("name/") are used unless gnuLong
// or bsd asks for the long-name variants.
func arOf(files []file, variant string) []byte {
	var buf bytes.Buffer
	buf.WriteString("!<arch>\n")
	hdr := func(name string, size int) {
		fmt.Fprintf(&buf, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", size)
	}
	var table bytes.Buffer
	offsets := map[string]int{}
	if variant == "gnu-long" {
		for _, f := range files {
			offsets[f.name] = table.Len()
			table.WriteString(f.name + "/\n")
		}
		hdr("//", table.Len())
		buf.Write(table.Bytes())
		if table.Len()%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	for _, f := range files {
		body := f.data
		switch variant {
		case "gnu-long":
			hdr(fmt.Sprintf("/%d", offsets[f.name]), len(body))
		case "bsd":
			hdr(fmt.Sprintf("#1/%d", len(f.name)), len(f.name)+len(body))
			buf.WriteString(f.name)
		case "deb":
			hdr(f.name, len(body))
		default:
			hdr(f.name+"/", len(body))
		}
		buf.Write(body)
		if buf.Len()%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

// cpioOf writes a newc cpio archive, with a directory and a symlink too.
func cpioOf(files ...file) []byte {
	var buf bytes.Buffer
	ino := 1
	entry := func(name string, mode uint32, data []byte) {
		fmt.Fprintf(&buf, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
			ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name)+1, 0)
		ino++
		buf.WriteString(name + "\x00")
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
		buf.Write(data)
		for buf.Len()%4 != 0 {
			buf.WriteByte(0)
		}
	}
	entry("./etc", 0o040755, nil)
	entry("./etc/link", 0o120777, []byte("target"))
	for _, f := range files {
		entry(f.name, 0o100644, f.data)
	}
	entry("TRAILER!!!", 0, nil)
	return buf.Bytes()
}

// rpmHeaderOf builds an RPM header structure holding STRING tags.
func rpmHeaderOf(tags map[uint32]string) []byte {
	var index, store bytes.Buffer
	keys := make([]uint32, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		binary.Write(&index, binary.BigEndian, [4]uint32{k, 6, uint32(store.Len()), 1})
		store.WriteString(tags[k] + "\x00")
	}
	var b bytes.Buffer
	b.Write([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	binary.Write(&b, binary.BigEndian, [2]uint32{uint32(len(tags)), uint32(store.Len())})
	b.Write(index.Bytes())
	b.Write(store.Bytes())
	return b.Bytes()
}

// rpmOf builds an RPM: lead, signature header padded to 8, main header, payload.
func rpmOf(compressor string, payload []byte) []byte {
	var b bytes.Buffer
	lead := make([]byte, 96)
	copy(lead, []byte{0xed, 0xab, 0xee, 0xdb, 3, 0})
	copy(lead[10:], "test-1.0-1")
	b.Write(lead)
	b.Write(rpmHeaderOf(map[uint32]string{1000: "sha256"})) // 16+16+7 bytes: needs padding
	for b.Len()%8 != 0 {
		b.WriteByte(0)
	}
	tags := map[uint32]string{1000: "test", rpmTagPayloadFormat: "cpio"}
	if compressor != "" {
		tags[rpmTagPayloadCompressor] = compressor
	}
	b.Write(rpmHeaderOf(tags))
	b.Write(payload)
	return b.Bytes()
}

type pyiFile struct {
	name     string
	data     []byte
	compress bool
	typ      byte
}

// pyiOf builds a PyInstaller one-file executable the way PyInstaller's
// CArchiveWriter does: bootloader, entry data, TOC, cookie. The fake
// bootloader carries the magic as a constant, like the real one.
func pyiOf(t testing.TB, cookieSize int, files ...pyiFile) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString("\x7fELF\x02\x01\x01")
	out.Write(make([]byte, 200))
	out.WriteString(pyiMagic + "\x00\x00\x00\x00 bootloader rodata")
	out.Write(make([]byte, 100))
	start := out.Len()
	var toc bytes.Buffer
	for _, f := range files {
		pos := out.Len() - start
		data := f.data
		flag := byte(0)
		if f.compress {
			var z bytes.Buffer
			zw := zlib.NewWriter(&z)
			zw.Write(data)
			zw.Close()
			data, flag = z.Bytes(), 1
		}
		out.Write(data)
		name := []byte(f.name + "\x00")
		for (18+len(name))%16 != 0 {
			name = append(name, 0)
		}
		binary.Write(&toc, binary.BigEndian, [4]uint32{uint32(18 + len(name)), uint32(pos), uint32(len(data)), uint32(len(f.data))})
		typ := f.typ
		if typ == 0 {
			typ = 'x'
		}
		toc.Write([]byte{flag, typ})
		toc.Write(name)
	}
	tocPos := out.Len() - start
	out.Write(toc.Bytes())
	pkgLen := out.Len() - start + cookieSize
	out.WriteString(pyiMagic)
	binary.Write(&out, binary.BigEndian, [4]uint32{uint32(pkgLen), uint32(tocPos), uint32(toc.Len()), 312})
	if cookieSize == 88 {
		lib := make([]byte, 64)
		copy(lib, "libpython3.12.so.1.0")
		out.Write(lib)
	}
	return out.Bytes()
}

func keys(m map[string]string) string {
	var k []string
	for p := range m {
		k = append(k, fmt.Sprintf("%q", p))
	}
	sort.Strings(k)
	return strings.Join(k, "\n")
}

func expect(t *testing.T, seen map[string]string, path, content string) {
	t.Helper()
	got, ok := seen[path]
	if !ok {
		t.Fatalf("missing %q; visited:\n%s", path, keys(seen))
	}
	if got != content {
		t.Fatalf("%s = %q, want %q", path, got, content)
	}
}

func noSkips(t *testing.T, skips []string) {
	t.Helper()
	if len(skips) != 0 {
		t.Fatalf("unexpected skips:\n%s", strings.Join(skips, "\n"))
	}
}

func wantSkip(t *testing.T, skips []string, path, reason string) {
	t.Helper()
	for _, s := range skips {
		if strings.HasPrefix(s, path) && strings.Contains(s, reason) {
			return
		}
	}
	t.Fatalf("no skip for %q containing %q; got:\n%s", path, reason, strings.Join(skips, "\n"))
}

func TestCompressedTarballs(t *testing.T) {
	tarball := tarList(t, file{"./etc/ssl/certs/ca.pem", []byte("STORE")})
	for name, data := range map[string][]byte{
		"/x.tar.gz":  gzOf(t, tarball),
		"/x.tar.zst": zstdOf(t, tarball),
		"/x.tar.xz":  xzOf(t, tarball),
		"/x.tar.bz2": []byte(tarBz2),
	} {
		t.Run(name, func(t *testing.T) {
			seen, skips := collect(t, name, data, DefaultLimits)
			noSkips(t, skips)
			expect(t, seen, name+"!/etc/ssl/certs/ca.pem", "STORE")
		})
	}
}

func TestCompressedFileKeepsPath(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nSTORE\n")
	for name, data := range map[string][]byte{
		"/ca.pem.zst": zstdOf(t, pem),
		"/ca.pem.xz":  xzOf(t, pem),
	} {
		seen, skips := collect(t, name, data, DefaultLimits)
		noSkips(t, skips)
		expect(t, seen, name, string(pem))
	}
}

func TestZipZstdMember(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.RegisterCompressor(93, func(w io.Writer) (io.WriteCloser, error) { return zstd.NewWriter(w) })
	f, _ := zw.CreateHeader(&zip.FileHeader{Name: "certifi/cacert.pem", Method: 93})
	f.Write([]byte("STORE"))
	zw.Close()
	seen, skips := collect(t, "/a.whl", buf.Bytes(), DefaultLimits)
	noSkips(t, skips)
	expect(t, seen, "/a.whl!/certifi/cacert.pem", "STORE")
}

func TestDeb(t *testing.T) {
	data := tarList(t,
		file{"./usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", []byte("STORE")},
		file{"./etc/ssl/certs/ca-certificates.crt", []byte("BUNDLE")})
	control := gzOf(t, tarList(t, file{"./control", []byte("Package: ca-certificates\n")}))
	for ext, compressed := range map[string][]byte{
		"xz":  xzOf(t, data),
		"zst": zstdOf(t, data),
		"gz":  gzOf(t, data),
	} {
		t.Run(ext, func(t *testing.T) {
			deb := arOf([]file{
				{"debian-binary", []byte("2.0\n")},
				{"control.tar.gz", control},
				{"data.tar." + ext, compressed},
			}, "deb")
			seen, skips := collect(t, "/pkg.deb", deb, DefaultLimits)
			noSkips(t, skips)
			expect(t, seen, "/pkg.deb!/data.tar."+ext+"!/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt", "STORE")
			expect(t, seen, "/pkg.deb!/data.tar."+ext+"!/etc/ssl/certs/ca-certificates.crt", "BUNDLE")
			expect(t, seen, "/pkg.deb!/control.tar.gz!/control", "Package: ca-certificates\n")
			expect(t, seen, "/pkg.deb!/debian-binary", "2.0\n")
		})
	}
}

func TestArNameVariants(t *testing.T) {
	files := []file{
		{"a-very-long-member-name-indeed.pem", []byte("ONE")},
		{"odd", []byte("TWO")}, // odd size exercises the 2-byte alignment
		{"x.pem", []byte("THREE")},
	}
	for _, v := range []string{"gnu", "gnu-long", "bsd", "deb"} {
		t.Run(v, func(t *testing.T) {
			if v != "gnu-long" && v != "bsd" {
				files[0].name = "short.pem"
			} else {
				files[0].name = "a-very-long-member-name-indeed.pem"
			}
			seen, skips := collect(t, "/lib.a", arOf(files, v), DefaultLimits)
			noSkips(t, skips)
			for _, f := range files {
				expect(t, seen, "/lib.a!/"+f.name, string(f.data))
			}
		})
	}
}

func TestArMalformed(t *testing.T) {
	good := arOf([]file{{"x", []byte("STORE")}}, "gnu")
	for name, b := range map[string][]byte{
		"truncated header": good[:40],
		"bad magic":        append(append([]byte{}, good[:66]...), 'X', 'X'),
		"past end":         good[:len(good)-2],
	} {
		t.Run(name, func(t *testing.T) {
			_, skips := collect(t, "/x.a", b, DefaultLimits)
			wantSkip(t, skips, "/x.a", "ar: ")
		})
	}
}

func TestCpio(t *testing.T) {
	c := cpioOf(file{"./etc/pki/tls/certs/ca-bundle.crt", []byte("STORE")}, file{"empty", nil})
	seen, skips := collect(t, "/initrd.cpio", c, DefaultLimits)
	noSkips(t, skips)
	expect(t, seen, "/initrd.cpio!/etc/pki/tls/certs/ca-bundle.crt", "STORE")
	if _, ok := seen["/initrd.cpio!/etc/link"]; ok {
		t.Fatal("symlink visited as a file")
	}
	seen, skips = collect(t, "/initrd.img", zstdOf(t, c), DefaultLimits)
	noSkips(t, skips)
	expect(t, seen, "/initrd.img!/etc/pki/tls/certs/ca-bundle.crt", "STORE")

	_, skips = collect(t, "/cut.cpio", c[:len(c)-60], DefaultLimits)
	wantSkip(t, skips, "/cut.cpio", "without a trailer")
}

func TestRPM(t *testing.T) {
	payload := cpioOf(
		file{"./etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", []byte("STORE")},
		file{"./usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit", []byte("P11")})
	for name, tc := range map[string]struct {
		compressor string
		payload    []byte
	}{
		"gzip": {"gzip", gzOf(t, payload)},
		"zstd": {"zstd", zstdOf(t, payload)},
		"xz":   {"xz", xzOf(t, payload)},
		"none": {"", payload},
	} {
		t.Run(name, func(t *testing.T) {
			seen, skips := collect(t, "/p.rpm", rpmOf(tc.compressor, tc.payload), DefaultLimits)
			noSkips(t, skips)
			expect(t, seen, "/p.rpm!/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "STORE")
			expect(t, seen, "/p.rpm!/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit", "P11")
		})
	}
}

func TestRPMMalformed(t *testing.T) {
	gz := gzOf(t, cpioOf(file{"./x", []byte("STORE")}))
	good := rpmOf("gzip", gz)
	sigEnd := 96 + 16 + 16 + 7 + 1
	stripped := bytes.Replace(cpioOf(file{"./x", []byte("STORE")}), []byte("070701"), []byte("07070X"), -1)
	for name, tc := range map[string]struct {
		b      []byte
		reason string
	}{
		"short lead":        {good[:50], "truncated lead"},
		"bad sig magic":     {append(append(append([]byte{}, good[:96]...), 0, 0, 0, 0), good[100:]...), "signature header: bad header magic"},
		"truncated header":  {good[:sigEnd+20], "main header"},
		"unknown payload":   {rpmOf("", []byte("not a payload at all")), "payload compression not recognised"},
		"payload not cpio":  {rpmOf("gzip", gzOf(t, []byte("hello, this is not cpio"))), "not a newc cpio archive"},
		"stripped cpio":     {rpmOf("gzip", gzOf(t, stripped)), "stripped cpio"},
		"corrupt payload":   {rpmOf("gzip", []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}), "rpm: payload"},
		"truncated payload": {rpmOf("gzip", gz[:len(gz)/2]), "rpm payload"},
	} {
		t.Run(name, func(t *testing.T) {
			_, skips := collect(t, "/p.rpm", tc.b, DefaultLimits)
			wantSkip(t, skips, "/p.rpm", tc.reason)
		})
	}
}

func TestPyInstaller(t *testing.T) {
	for _, size := range []int{88, 24} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			app := pyiOf(t, size,
				pyiFile{name: "pyi-runtime-tmpdir", typ: 'o'},
				pyiFile{name: "struct", data: []byte("marshalled code"), compress: true, typ: 'm'},
				pyiFile{name: "libssl.so.3", data: []byte("\x7fELF shared object"), typ: 'b'},
				pyiFile{name: "certifi/cacert.pem", data: []byte("-----BEGIN CERTIFICATE-----\nSTORE"), compress: true},
				pyiFile{name: "data/plain.pem", data: []byte("PLAIN")},
				pyiFile{name: "app", data: []byte("script"), compress: true, typ: 's'},
			)
			seen, skips := collect(t, "/opt/app", app, DefaultLimits)
			noSkips(t, skips)
			expect(t, seen, "/opt/app!/certifi/cacert.pem", "-----BEGIN CERTIFICATE-----\nSTORE")
			expect(t, seen, "/opt/app!/data/plain.pem", "PLAIN")
			expect(t, seen, "/opt/app!/libssl.so.3", "\x7fELF shared object")
			if _, ok := seen["/opt/app!/pyi-runtime-tmpdir"]; ok {
				t.Fatal("empty option entry visited")
			}
		})
	}
}

func TestPyInstallerUnparsable(t *testing.T) {
	app := pyiOf(t, 88, pyiFile{name: "certifi/cacert.pem", data: []byte("STORE"), compress: true})
	// Break the first TOC entry's length.
	toc := len(app) - 88 - 48 // one entry: 18 bytes + "certifi/cacert.pem\x00", padded to 16
	bad := append([]byte{}, app...)
	binary.BigEndian.PutUint32(bad[toc:], 3)
	_, skips := collect(t, "/opt/app", bad, DefaultLimits)
	wantSkip(t, skips, "/opt/app", "PyInstaller archive could not be parsed")

	// A bootloader alone carries the magic but no archive: nothing to report.
	boot := append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 64)...)
	boot = append(boot, pyiMagic+"\x00\x00\x00\x00 rodata"...)
	seen, skips := collect(t, "/usr/lib/python3/site-packages/PyInstaller/bootloader/run", boot, DefaultLimits)
	noSkips(t, skips)
	if len(seen) != 1 {
		t.Fatalf("visited %v", keys(seen))
	}
}

func TestUPX(t *testing.T) {
	elf := append([]byte("\x7fELF\x02\x01\x01\x03"), make([]byte, 0xe0)...)
	elf = append(elf, "\x00\x00UPX!\x0d\x16"...)
	elf = append(elf, make([]byte, 1000)...)
	pe := append([]byte("MZ"), make([]byte, 0x178)...)
	pe = append(pe, "UPX0\x00\x00\x00\x00"...)
	pe = append(pe, make([]byte, 32)...)
	pe = append(pe, "UPX1\x00\x00\x00\x00"...)
	for name, b := range map[string][]byte{"/bin/tool": elf, "/tool.exe": pe} {
		seen, skips := collect(t, name, b, DefaultLimits)
		if len(seen) != 1 || len(skips) != 1 || skips[0] != name+": "+reasonUPX {
			t.Fatalf("%s: seen %v skips %v", name, keys(seen), skips)
		}
	}
	// A text file mentioning UPX is not an executable.
	_, skips := collect(t, "/README", []byte("compress with UPX! then ship"), DefaultLimits)
	noSkips(t, skips)
}

func TestDefaultLimits(t *testing.T) {
	if DefaultLimits.MaxMemberSize != 256<<20 || DefaultLimits.MaxArchiveSize != 1<<30 {
		t.Fatalf("DefaultLimits = %+v", DefaultLimits)
	}
}

// small limits for the bomb tests.
var small = Limits{MaxDepth: 4, MaxMemberSize: 1 << 20, MaxArchiveSize: 4 << 20}

func TestCompressionBombs(t *testing.T) {
	zeros := make([]byte, 16<<20)
	for name, b := range map[string][]byte{
		"/b.gz":  gzOf(t, zeros),
		"/b.zst": zstdOf(t, zeros),
		"/b.xz":  xzOf(t, zeros[:8<<20]),
		"/b.bz2": []byte(bz2Bomb),
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, skips := collect(t, name, b, small)
			runtime.ReadMemStats(&after)
			wantSkip(t, skips, name, "size limit")
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 40<<20 {
				t.Fatalf("allocated %d MB for a bomb under a 1 MB member limit", alloc>>20)
			}
		})
	}
}

func TestTarStreamBudget(t *testing.T) {
	// Eight 1 MB members in a gzip: the stream is read member by member and
	// stops when the 4 MB per-file budget runs out, reporting the rest.
	var files []file
	for i := range 8 {
		files = append(files, file{fmt.Sprintf("m%d", i), bytes.Repeat([]byte{byte('a' + i)}, 1<<20-600)})
	}
	tgz := gzOf(t, tarList(t, files...))
	seen, skips := collect(t, "/big.tgz", tgz, Limits{MaxDepth: 4, MaxMemberSize: 2 << 20, MaxArchiveSize: 4 << 20})
	if _, ok := seen["/big.tgz!/m0"]; !ok {
		t.Fatalf("first member not visited: %v", keys(seen))
	}
	if _, ok := seen["/big.tgz!/m7"]; ok {
		t.Fatal("budget not enforced")
	}
	wantSkip(t, skips, "/big.tgz", "per-file limit")

	// One member over the member limit is skipped and the rest still read.
	files = []file{{"big", make([]byte, 3<<20)}, {"after", []byte("STORE")}}
	seen, skips = collect(t, "/m.tar.zst", zstdOf(t, tarList(t, files...)), Limits{MaxDepth: 4, MaxMemberSize: 2 << 20, MaxArchiveSize: 64 << 20})
	wantSkip(t, skips, "/m.tar.zst!/big", "size limit")
	expect(t, seen, "/m.tar.zst!/after", "STORE")
}

func TestZipBudget(t *testing.T) {
	files := map[string][]byte{}
	for i := range 10 {
		files[fmt.Sprintf("m%d", i)] = make([]byte, 900<<10)
	}
	_, skips := collect(t, "/many.zip", zipOf(t, files), small)
	wantSkip(t, skips, "/many.zip!/", "per-file limit")
}

func TestXzHugeDictionary(t *testing.T) {
	b := xzOf(t, []byte("STORE"))
	// The block header starts after the 12-byte stream header; its LZMA2
	// filter is ID 0x21 with one property byte. 40 means 4 GiB.
	i := bytes.Index(b[12:], []byte{0x21, 0x01}) + 12
	b[i+2] = 40
	_, skips := collect(t, "/x.xz", b, DefaultLimits)
	wantSkip(t, skips, "/x.xz", "dictionary of 4294967295 bytes exceeds")
}

func TestDecompressionErrorsReported(t *testing.T) {
	for name, b := range map[string][]byte{
		"/t.zst": zstdOf(t, tarList(t, file{"a", []byte("STORE")}))[:30],
		"/t.xz":  xzOf(t, []byte("STORE"))[:30],
		"/t.bz2": []byte(tarBz2[:60]),
		"/t.gz":  gzOf(t, []byte("STORE"))[:12],
	} {
		_, skips := collect(t, name, b, DefaultLimits)
		if len(skips) == 0 {
			t.Errorf("%s: truncated stream not reported", name)
		}
	}
}

// tarSafe reports whether a PAX header can carry the name at all.
func tarSafe(n string) bool { return !strings.ContainsRune(n, 0) && utf8.ValidString(n) }

func TestSanitizedNames(t *testing.T) {
	names := map[string]string{
		"../../etc/ssl/certs/x.pem":       "../../etc/ssl/certs/x.pem",
		"/etc/pki/abs.pem":                "/etc/pki/abs.pem",
		"evil\nINFO /etc/ssl/ok.pem":      `evil\x0aINFO /etc/ssl/ok.pem`,
		"nul\x00.pem":                     `nul\x00.pem`,
		"esc\x1b[2Kgone.pem":              `esc\x1b[2Kgone.pem`,
		"bidi\u202emep.crt":               `bidi\u202emep.crt`,
		"bad\xffutf8.pem":                 `bad\xffutf8.pem`,
		"ünïcödé/証明書.pem":                 "ünïcödé/証明書.pem",
		"./usr/share/ca-certificates.crt": "usr/share/ca-certificates.crt",
	}
	var tf []file
	zf := map[string][]byte{}
	for n := range names {
		if tarSafe(n) {
			tf = append(tf, file{n, []byte("STORE " + n)})
		}
		zf[n] = []byte("STORE " + n)
	}
	for archive, data := range map[string][]byte{"/a.tar": tarList(t, tf...), "/a.zip": zipOf(t, zf)} {
		seen, skips := collect(t, archive, data, DefaultLimits)
		noSkips(t, skips)
		for raw, want := range names {
			if archive == "/a.tar" && !tarSafe(raw) {
				continue
			}
			expect(t, seen, archive+"!/"+want, "STORE "+raw)
		}
		for p := range seen {
			for _, r := range p {
				if r < 0x20 || r == 0x7f || r == '‮' {
					t.Fatalf("raw control character in reported path %q", p)
				}
			}
		}
	}
}
