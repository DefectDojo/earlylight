package fingerprint_test

import (
	"bytes"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/fingerprint"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/testbin"
)

func TestTablesPerRelease(t *testing.T) {
	cases := []struct {
		release               string
		prefixed, dist, block bool
	}{
		{"1.0.2", false, false, false},
		{"1.0.3", false, true, false},
		{"1.0.9", false, true, false},
		{"1.0.10", false, true, true},
		{"1.1.0", true, true, false},
		{"1.1.1", true, true, true},
		{"1.2.0", true, true, false},
		{"1.2.1", true, true, true},
	}
	for _, c := range cases {
		data := testbin.Executable([]byte("unrelated\x00strings\x00"), testbin.Table(c.release))
		ts := fingerprint.Tables(data)
		if len(ts) != 1 {
			t.Fatalf("%s: %d tables, want 1", c.release, len(ts))
		}
		got := ts[0]
		if got.Prefixed != c.prefixed || got.Distance != c.dist || got.BlockSwitch != c.block {
			t.Errorf("%s: got %+v, want prefixed=%v distance=%v block_switch=%v", c.release, got, c.prefixed, c.dist, c.block)
		}
		if got.Names < fingerprint.MinNames {
			t.Errorf("%s: %d names", c.release, got.Names)
		}
	}
}

func TestNotATable(t *testing.T) {
	// Node.js exports the error codes as BROTLI_DECODER_ERROR_* constants. They
	// never count as a decoder's own table.
	var consts bytes.Buffer
	for _, r := range []string{"1.2.1"} {
		for _, n := range bytes.Split(testbin.Table(r), []byte{0}) {
			if len(n) > 0 {
				consts.WriteString("\x00BROTLI_DECODER")
				consts.Write(n)
			}
		}
	}
	consts.WriteByte(0)
	cases := map[string][]byte{
		"constants only":  testbin.Executable(consts.Bytes()),
		"anchor alone":    testbin.Executable([]byte("\x00EXUBERANT_META_NIBBLE\x00DISTANCE\x00")),
		"inside a string": testbin.Executable([]byte("\x00XEXUBERANT_META_NIBBLE\x00")),
		"empty":           nil,
		"anchor at start": []byte("EXUBERANT_META_NIBBLE\x00"),
	}
	for name, data := range cases {
		if ts := fingerprint.Tables(data); len(ts) != 0 {
			t.Errorf("%s: found %+v", name, ts)
		}
	}
}

func TestTablesFarApart(t *testing.T) {
	// Two decoders in one file, an unfixed one far from a fixed one, are two tables.
	data := testbin.Executable(testbin.Table("1.2.0"), make([]byte, 64<<10), testbin.Table("1.2.1"))
	far := testbin.Executable(testbin.Table("1.2.0"), make([]byte, 300<<10), testbin.Table("1.2.1"))
	if ts := fingerprint.Tables(far); len(ts) != 2 || ts[0].BlockSwitch || !ts[1].BlockSwitch {
		t.Fatalf("far apart: %+v", ts)
	}
	ts := fingerprint.Tables(data)
	if len(ts) != 2 || ts[0].BlockSwitch || !ts[1].BlockSwitch {
		t.Fatalf("got %+v", ts)
	}
}

func TestStrayBlockSwitch(t *testing.T) {
	unfixed := testbin.Executable(testbin.Table("1.2.0"))
	if fingerprint.StrayBlockSwitch(unfixed, fingerprint.Tables(unfixed)) {
		t.Error("stray BLOCK_SWITCH in a plain unfixed table")
	}
	merged := testbin.Executable(testbin.Table("1.2.0"), make([]byte, 16<<10), []byte("\x00BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH\x00"))
	if !fingerprint.StrayBlockSwitch(merged, fingerprint.Tables(merged)) {
		t.Error("BLOCK_SWITCH elsewhere in the file not seen")
	}
	fixed := testbin.Executable(testbin.Table("1.2.1"))
	if fingerprint.StrayBlockSwitch(fixed, fingerprint.Tables(fixed)) {
		t.Error("the table's own BLOCK_SWITCH counted as stray")
	}
}

func TestExportsDecoder(t *testing.T) {
	def := []testbin.Symbol{{Name: "BrotliDecoderCreateInstance", Defined: true}, {Name: "BrotliDecoderDecompressStream", Defined: true}}
	imp := []testbin.Symbol{{Name: "BrotliDecoderDecompressStream"}, {Name: "BrotliDecoderDecompress"}}
	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"elf defines", testbin.ELF(def, nil), true},
		{"elf imports", testbin.ELF(imp, nil), false},
		{"macho defines", testbin.MachO(def, nil), true},
		{"macho imports", testbin.MachO(imp, nil), false},
		{"pe exports", testbin.PE([]string{"BrotliDecoderCreateInstance", "BrotliDecoderDecompressStream"}, nil), true},
		{"pe exports other", testbin.PE([]string{"BrotliEncoderCompress"}, []byte("BrotliDecoderDecompressStream\x00")), false},
		{"name in data only", testbin.Executable([]byte("BrotliDecoderDecompressStream\x00")), false},
		{"truncated elf", testbin.ELF(def, nil)[:100], false},
	}
	for _, c := range cases {
		if got := fingerprint.ExportsDecoder(c.data); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDotnetRuntime(t *testing.T) {
	cases := map[string]string{
		"@(#)Version 8.0.3326.52219 @Commit: da7a9be": "8.0.33",
		"@(#)Version 8.0.3226.50405 @Commit: b9a49e4": "8.0.32",
		"@(#)Version 9.0.2226.52218 @Commit: faaecba": "9.0.22",
		"@(#)Version 10.0.1426.1 @Commit: x":          "10.0.14",
		"@(#)Version 8.0.23.53103 @Commit: x":         "8.0.0",
		"@(#)Version 11.0.26.52214 @Commit: x":        "",
		"@(#)Version 4.6.1.0":                         "",
		"@(#)Version 8.0":                             "",
		"@(#)Version 8.0.3326":                        "",
		"Version 8.0.3326.1":                          "",
	}
	for in, want := range cases {
		v, ok := fingerprint.DotnetRuntime([]byte("\x00" + in + "\x00"))
		got := ""
		if ok {
			got = v.String()
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestNodeAndBunVersions(t *testing.T) {
	v, ok := fingerprint.NodeVersion([]byte("https://nodejs.org/download/release/v24.22.1/node-v24.22.1-headers.tar.gz"))
	if !ok || v != fingerprint.V(24, 22, 1) {
		t.Errorf("node: %v %v", v, ok)
	}
	if _, ok := fingerprint.NodeVersion([]byte("https://nodejs.org/download/release/v24.22.1/")); ok {
		t.Error("node: headers URL without the tarball name read as a version")
	}
	v, ok = fingerprint.BunVersion([]byte("Bun v1.4\x00Bun v1.4.3 (c6da4a4d3) Linux x64"))
	if !ok || v != fingerprint.V(1, 4, 3) {
		t.Errorf("bun: %v %v", v, ok)
	}
	if _, ok := fingerprint.BunVersion([]byte("Bun v1.4.3-canary")); ok {
		t.Error("bun: a banner without ' (' read as a version")
	}
}

func TestVersionLess(t *testing.T) {
	if !fingerprint.V(24, 22, 0).Less(fingerprint.V(24, 22, 1)) || fingerprint.V(24, 22, 1).Less(fingerprint.V(24, 22, 1)) ||
		!fingerprint.V(1, 4, 3).Less(fingerprint.V(1, 5, 0)) || fingerprint.V(2, 0, 0).Less(fingerprint.V(1, 9, 9)) {
		t.Error("Less")
	}
}

func TestHasDecoderTables(t *testing.T) {
	for gap, want := range map[int]bool{0: true, 16: true, 64: true, 240: true, 300: false} {
		if got := fingerprint.HasDecoderTables(testbin.Executable(testbin.DecoderTables(gap))); got != want {
			t.Errorf("gap %d: got %v", gap, got)
		}
	}
	if fingerprint.HasDecoderTables(testbin.Executable(testbin.DecoderTables(0)[:16])) {
		t.Error("one table alone counted")
	}
	if fingerprint.HasDecoderTables(nil) {
		t.Error("empty input")
	}
}

func TestCompoundAndDistance(t *testing.T) {
	ts := fingerprint.Tables(testbin.Executable(testbin.Table("1.0.2")))
	if len(ts) != 1 || !ts[0].Compound || ts[0].Distance {
		t.Fatalf("1.0.2: %+v", ts)
	}
	ts = fingerprint.Tables(testbin.Executable(testbin.Table("1.0.9")))
	if len(ts) != 1 || ts[0].Compound || !ts[0].Distance {
		t.Fatalf("1.0.9: %+v", ts)
	}
	if fingerprint.NamesDistance(testbin.Table("1.0.2")) || !fingerprint.NamesDistance([]byte("MAX_DISTANCE\x00")) {
		t.Error("NamesDistance")
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add(testbin.Table("1.0.9"))
	f.Add(testbin.Table("1.2.1"))
	f.Add(testbin.ELF([]testbin.Symbol{{Name: "BrotliDecoderDecompressStream", Defined: true}}, testbin.Table("1.1.0")))
	f.Add(testbin.PE([]string{"BrotliDecoderDecompressStream"}, []byte("@(#)Version 8.0.3326.1")))
	f.Add(testbin.MachO([]testbin.Symbol{{Name: "BrotliDecoderDecompress", Defined: true}}, []byte("Bun v1.4.3 (x)")))
	f.Add(testbin.DecoderTables(16))
	// Loaded sections, so the fuzzer reaches the layout, version and code checks.
	f.Add(testbin.ELFAt([]testbin.Symbol{{Name: "BrotliDecoderVersion", Defined: true}}, append([]byte{0xb8, 0x01, 0x20, 0x00, 0x01, 0xc3}, testbin.DecoderTables(16)...), 0x1000, 0x1000, 62))
	f.Add(testbin.ELFAt([]testbin.Symbol{{Name: "BrotliDecoderDecompressStream", Defined: true}}, append([]byte{0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xb8, 0xef, 0xff, 0xff, 0xff}, testbin.DecoderTables(0)...), 0x1000, 0x1000, 62))
	f.Fuzz(func(t *testing.T, data []byte) {
		ts := fingerprint.Tables(data)
		for _, tb := range ts {
			if tb.Names < fingerprint.MinNames || tb.Offset < 0 || tb.Offset >= len(data) {
				t.Fatalf("bad table %+v", tb)
			}
		}
		fingerprint.StrayBlockSwitch(data, ts)
		fingerprint.ExportsDecoder(data)
		fingerprint.DotnetRuntime(data)
		fingerprint.NodeVersion(data)
		fingerprint.BunVersion(data)
		fingerprint.HasDictionary(data)
		fingerprint.HasDecoderTables(data)
		fingerprint.NamesDistance(data)
		fingerprint.CodeMarker(data)
		fingerprint.DecoderVersion(data)
		fingerprint.PEFileVersion(data)
		fingerprint.EnvoyVersion(data)
		fingerprint.WasmMinus17(data)
	})
}
