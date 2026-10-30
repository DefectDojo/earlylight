package assess_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/fingerprint"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/testbin"
)

const nodeURL = "https://nodejs.org/download/release/v%s/node-v%s-headers.tar.gz"

func node(v string) []byte {
	return []byte(strings.ReplaceAll(nodeURL, "%s", v))
}

var decoder = []testbin.Symbol{{Name: "BrotliDecoderDecompressStream", Defined: true}}

func TestFile(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		data    []byte
		status  assess.Status
		kind    assess.Kind
		product assess.Product
		fix     string // a substring of the fix; empty when fixed
	}{
		{"debian 12 unfixed", "/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9", testbin.ELF(decoder, testbin.Table("1.0.9")),
			assess.Vulnerable, assess.Library, assess.LibBrotliDec, "system Brotli package"},
		{"debian 12 backport", "/usr/lib/x86_64-linux-gnu/libbrotlidec.so.1.0.9", testbin.ELF(decoder, testbin.Table("1.0.10")),
			assess.Fixed, assess.Library, assess.LibBrotliDec, ""},
		{"fedora 43", "/usr/lib64/libbrotlidec.so.1.2.0", testbin.ELF(decoder, testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Library, assess.LibBrotliDec, "1.2.1"},
		{"node 24 unfixed", "/usr/local/bin/node", testbin.Executable(node("24.22.0"), testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Bundled, assess.Node, "Update Node.js 24.22.0 to 24.22.1."},
		{"node 22 fixed", "/usr/local/bin/node", testbin.Executable(node("22.23.4"), testbin.Table("1.1.1")),
			assess.Fixed, assess.Bundled, assess.Node, ""},
		{"node 20 has no fix", "/opt/node/bin/node", testbin.Executable(node("20.20.2"), testbin.Table("1.1.0")),
			assess.Vulnerable, assess.Bundled, assess.Node, "Node.js 20 has no fixed release: move to 22.23.4, 24.22.1 or 26.12.1."},
		{"node without its URL", "C:/Program Files/nodejs/node.exe", testbin.Executable(testbin.Table("1.1.0")),
			assess.Vulnerable, assess.Bundled, assess.Node, "Update Node.js to 22.23.4"},
		{"node 26 stripped unfixed", "/usr/local/bin/node", testbin.ELF(decoder, node("26.12.0")),
			assess.Vulnerable, assess.Bundled, assess.Node, "Update Node.js 26.12.0 to 26.12.1."},
		{"node 26 stripped fixed", "/usr/local/bin/node", testbin.ELF(decoder, node("26.12.1")),
			assess.Fixed, assess.Bundled, assess.Node, ""},
		{"node 25 stripped", "/usr/local/bin/node", testbin.ELF(decoder, node("25.9.0")),
			assess.Vulnerable, assess.Bundled, assess.Node, "Node.js 25 has no fixed release"},
		{"pillow wheel on linux", "/usr/local/lib/python3.14/site-packages/pillow.libs/libbrotlidec-7e5462ba.so.1.2.0", testbin.ELF(decoder, testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Bundled, assess.PyWheel, "Upgrade the pillow Python package"},
		{"pillow wheel fixed", "/usr/lib/python3/dist-packages/pillow.libs/libbrotlidec-0a1b2c3d.so.1.2.1", testbin.ELF(decoder, testbin.Table("1.2.1")),
			assess.Fixed, assess.Bundled, assess.PyWheel, ""},
		{"pillow wheel on macos", "/Users/a/.venv/lib/python3.13/site-packages/PIL/.dylibs/libbrotlidec.1.2.0.dylib", testbin.ELF(decoder, testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Bundled, assess.PyWheel, "Upgrade the Python package that provides PIL"},
		{"wheel archive member", "/srv/wheels/pillow-13.0.0-cp314-manylinux_2_28_x86_64.whl!/pillow.libs/libbrotlidec-7e5462ba.so.1.2.0", testbin.ELF(decoder, testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Bundled, assess.PyWheel, "Updating the system Brotli package does not change this copy"},
		{"libtool build dir stays system", "/build/brotli-1.2.0/.libs/libbrotlidec.so.1.2.0", testbin.ELF(decoder, testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Library, assess.LibBrotliDec, "system Brotli package"},
		{"foo.libs outside python stays system", "/opt/vendor/foo.libs/libbrotlidec.so.1.2.0", testbin.ELF(decoder, testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Library, assess.LibBrotliDec, "system Brotli package"},
		{"wheel member", "/srv/wheels/brotli-1.2.0-cp313.whl!/_brotli.cpython-313-x86_64-linux-gnu.so", testbin.Executable(testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Bundled, assess.PyBrotli, "Brotli Python package to 1.2.1"},
		{"brotlicffi", "/app/.venv/lib/python3.13/site-packages/brotlicffi/_brotlicffi.abi3.so", testbin.Executable(testbin.Table("1.2.0")),
			assess.Vulnerable, assess.Bundled, assess.BrotliCFFI, "brotlicffi Python package to 1.2.1.0"},
		{"dotnet 9 table", "/usr/share/dotnet/shared/Microsoft.NETCore.App/9.0.21/libSystem.IO.Compression.Native.so",
			testbin.ELF(decoder, append([]byte("@(#)Version 9.0.2126.1 @Commit: x\x00"), testbin.Table("1.1.0")...)),
			assess.Vulnerable, assess.Bundled, assess.Dotnet, "Update .NET 9.0.21 to 9.0.22."},
		{"dotnet 8 stripped unfixed", "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.32/libSystem.IO.Compression.Native.so",
			testbin.ELF(decoder, []byte("\x00@(#)Version 8.0.3226.50405 @Commit: b9a49e4\x00")),
			assess.Vulnerable, assess.Bundled, assess.Dotnet, "Update .NET 8.0.32 to 8.0.33."},
		{"dotnet 8 stripped fixed", "/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.33/libSystem.IO.Compression.Native.so",
			testbin.ELF(decoder, []byte("\x00@(#)Version 8.0.3326.52219 @Commit: da7a9be\x00")),
			assess.Fixed, assess.Bundled, assess.Dotnet, ""},
		{"dotnet 7 stripped", "/app/libSystem.IO.Compression.Native.so",
			testbin.ELF(decoder, []byte("\x00@(#)Version 7.0.2024.1 @Commit: x\x00")),
			assess.Vulnerable, assess.Bundled, assess.Dotnet, "NET 7 has no fixed release"},
		{"dotnet 6 stripped", "/app/libSystem.IO.Compression.Native.so",
			testbin.ELF(decoder, []byte("\x00@(#)Version 6.0.3624.1 @Commit: x\x00")),
			assess.Vulnerable, assess.Bundled, assess.Dotnet, "NET 6 has no fixed release"},
		{"dotnet 5 stripped", "/app/libSystem.IO.Compression.Native.so",
			testbin.ELF(decoder, []byte("\x00@(#)Version 5.0.1722.1 @Commit: x\x00")),
			assess.Unknown, assess.Bundled, assess.Dotnet, "NET 5 has no fixed release"},
		{"node 27 stripped", "/usr/local/bin/node", testbin.ELF(decoder, node("27.1.0")),
			assess.Fixed, assess.Bundled, assess.Node, ""},
		{"dotnet windows stripped no stamp", `C:\app\System.IO.Compression.Native.dll`,
			testbin.PE([]string{"BrotliDecoderDecompressStream"}, nil),
			assess.Unknown, assess.Bundled, assess.Dotnet, ""},
		{"bun unfixed", "/usr/local/bin/bun", testbin.Executable(node("24.3.0"), []byte("Bun v1.4.3 (c6da4a4d3) Linux x64\x00"), testbin.DecoderTables(16)),
			assess.Vulnerable, assess.Bundled, assess.Bun, "Bun to 1.4.4"},
		{"bun compiled app fixed", "/app/server", testbin.Executable([]byte("Bun v1.4.4 (38afee6c8) Linux x64\x00"), testbin.DecoderTables(64)),
			assess.Fixed, assess.Bundled, assess.Bun, ""},
		{"envoy", "/usr/local/bin/envoy", testbin.Executable(testbin.DecoderTables(16)),
			assess.Unknown, assess.Bundled, assess.Envoy, "Envoy to 1.37.8"},
		{"stripped other", "/usr/lib/libfoo.so", testbin.ELF(decoder, nil),
			assess.Unknown, assess.Bundled, assess.Other, "Rebuild it with Brotli"},
		{"pre 1.0.3", "/usr/lib/libbrotlidec.so.1.0.2", testbin.ELF(decoder, testbin.Table("1.0.2")),
			assess.Fixed, assess.Library, assess.LibBrotliDec, ""},
		{"pre 1.0.3 table but DISTANCE elsewhere", "/usr/lib/libbrotlidec.so.1.0.2", testbin.ELF(decoder, append(testbin.Table("1.0.2"), "MAX_DISTANCE\x00"...)),
			assess.Unknown, assess.Library, assess.LibBrotliDec, "system Brotli package"},
		{"stripped decoder, no symbols", "/opt/app/bin/server", testbin.Executable(testbin.DecoderTables(32)),
			assess.Unknown, assess.Bundled, assess.Other, "Rebuild it with Brotli"},
		{"node 26 stripped by tables only", "/usr/local/bin/node", testbin.Executable(node("26.12.0"), testbin.DecoderTables(16)),
			assess.Vulnerable, assess.Bundled, assess.Node, "Update Node.js 26.12.0 to 26.12.1."},
		{"mixed evidence", "/usr/lib/libfoo.so", testbin.Executable(testbin.Table("1.2.0"), make([]byte, 16<<10), []byte("\x00BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH\x00")),
			assess.Unknown, assess.Bundled, assess.Other, "Rebuild"},
	}
	for _, c := range cases {
		f, ok := assess.File(c.path, c.data)
		if !ok {
			t.Errorf("%s: no finding", c.name)
			continue
		}
		if f.Status != c.status || f.Kind != c.kind || f.Product != c.product {
			t.Errorf("%s: got %s %s %s (%s), want %s %s %s", c.name, f.Status, f.Kind, f.Product, f.Reason, c.status, c.kind, c.product)
		}
		if f.Reason == "" || f.Message == "" || f.Method == "" {
			t.Errorf("%s: missing reason, message or method: %+v", c.name, f)
		}
		if c.status == assess.Fixed && f.Fix != "" {
			t.Errorf("%s: fixed but has a fix: %q", c.name, f.Fix)
		}
		if c.status != assess.Fixed && !strings.Contains(f.Fix, c.fix) {
			t.Errorf("%s: fix %q does not contain %q", c.name, f.Fix, c.fix)
		}
	}
}

func TestFileNoDecoder(t *testing.T) {
	cases := map[string][]byte{
		"plain executable":        testbin.Executable([]byte("hello")),
		"imports the decoder":     testbin.ELF([]testbin.Symbol{{Name: "BrotliDecoderDecompressStream"}}, nil),
		"encoder only dictionary": testbin.Executable([]byte("timedownlifeleftbackcodedatashowonlysitecityopenjustlike")),
		"node with shared brotli": testbin.Executable(node("24.22.1")),
		"bun without brotli":      testbin.Executable([]byte("Bun v1.0.0 (abc) Linux")),
		"one decoder table only":  testbin.Executable(testbin.DecoderTables(0)[:16]),
		"tables far apart":        testbin.Executable(testbin.DecoderTables(4096)),
	}
	for name, data := range cases {
		if f, ok := assess.File("/usr/bin/x", data); ok {
			t.Errorf("%s: unexpected finding %+v", name, f)
		}
	}
}

func TestEnvoyStatus(t *testing.T) {
	for _, c := range []struct {
		v    string
		dev  bool
		want assess.Status
	}{
		{"1.37.7", false, assess.Vulnerable}, {"1.37.8", false, assess.Fixed}, {"1.35.9", false, assess.Vulnerable},
		{"1.40.0", false, assess.Fixed}, {"1.39.2", true, assess.Vulnerable}, {"1.39.5", true, assess.Fixed}, {"1.39.3", true, assess.Unknown},
		{"1.40.0", true, assess.Unknown}, {"1.40.1", true, assess.Fixed}, {"1.41.0", true, assess.Fixed},
	} {
		parts := strings.Split(c.v, ".")
		maj, _ := strconv.Atoi(parts[0])
		min, _ := strconv.Atoi(parts[1])
		pat, _ := strconv.Atoi(parts[2])
		if got, _ := assess.EnvoyStatusForTest(fingerprintV(maj, min, pat), c.dev); got != c.want {
			t.Errorf("%s dev=%v: got %s, want %s", c.v, c.dev, got, c.want)
		}
	}
}

func fingerprintV(a, b, c int) fingerprint.Version { return fingerprint.V(a, b, c) }
