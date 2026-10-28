package fingerprint

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/testbin"
)

func TestNodeVersionAnyReleaseURL(t *testing.T) {
	// Windows builds name the import library before the headers.
	b := []byte("https://nodejs.org/download/release/v24.22.0/win-x64/node.lib\x00x\x00https://nodejs.org/download/release/v24.22.0/node-v24.22.0-headers.tar.gz")
	if v, ok := NodeVersion(b); !ok || v != V(24, 22, 0) {
		t.Fatalf("got %v %v", v, ok)
	}
	if _, ok := NodeVersion([]byte("https://nodejs.org/download/release/v24.22.0/docs/")); ok {
		t.Error("a docs URL read as the build's release")
	}
}

func TestPEFileVersion(t *testing.T) {
	b := append([]byte("MZ"), make([]byte, 64)...)
	info := make([]byte, 16)
	copy(info, []byte{0xbd, 0x04, 0xef, 0xfe})
	binary.LittleEndian.PutUint32(info[8:], 8<<16|0)
	binary.LittleEndian.PutUint32(info[12:], 3326<<16|52219)
	b = append(b, info...)
	ma, mi, build, rev, ok := PEFileVersion(b)
	if !ok || ma != 8 || mi != 0 || build != 3326 || rev != 52219 {
		t.Fatalf("got %d.%d.%d.%d %v", ma, mi, build, rev, ok)
	}
}

func TestEnvoyVersion(t *testing.T) {
	stamp := "\x00" + strings.Repeat("a", 40) + "\x00Clean\x00"
	v, dev, ok := EnvoyVersion([]byte(stamp + "x\x001.37.8\x00y"))
	if !ok || dev || v != V(1, 37, 8) {
		t.Fatalf("got %v %v %v", v, dev, ok)
	}
	if v, dev, ok := EnvoyVersion([]byte(stamp + "\x001.39.5-dev\x00")); !ok || !dev || v != V(1, 39, 5) {
		t.Fatalf("dev: got %v %v %v", v, dev, ok)
	}
	if _, _, ok := EnvoyVersion([]byte("\x001.37.8\x00")); ok {
		t.Error("a version without Envoy's build stamp")
	}
	if _, _, ok := EnvoyVersion([]byte(stamp + "\x001.37.8\x00\x001.52.1\x00")); ok {
		t.Error("two candidate versions read as one")
	}
}

func TestReleaseFixed(t *testing.T) {
	for v, want := range map[Version][2]bool{
		V(1, 0, 2): {false, true}, V(1, 0, 9): {false, false}, V(1, 0, 10): {true, false}, V(1, 1, 0): {false, false},
		V(1, 1, 1): {true, false}, V(1, 2, 0): {false, false}, V(1, 2, 1): {true, false}, V(1, 3, 0): {true, false},
	} {
		f, p := ReleaseFixed(v)
		if [2]bool{f, p} != want {
			t.Errorf("%v: got %v %v", v, f, p)
		}
	}
}

func TestCountMov17(t *testing.T) {
	code := []byte{0xb8, 0xef, 0xff, 0xff, 0xff, 0x90, 0x41, 0xbb, 0xef, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xef, 0xff, 0xff, 0xff}
	if n := countMov17(code); n != 2 {
		t.Fatalf("got %d", n)
	}
}

func TestPortsAndWasm(t *testing.T) {
	if !RustPort([]byte("/root/.cargo/registry/src/index.crates.io/brotli-decompressor-5.0.3/src/decode.rs")) || RustPort([]byte("brotli")) {
		t.Error("RustPort")
	}
	if !IsElectron([]byte("x\x00ELECTRON_RUN_AS_NODE\x00")) || IsElectron([]byte("electron")) {
		t.Error("IsElectron")
	}
	// A module with one code section holding no i32.const -17.
	mod := append([]byte("\x00asm\x01\x00\x00\x00"), 10, 3, 1, 0x41, 0x05)
	if n, ok := WasmMinus17(mod); !ok || n != 0 {
		t.Fatalf("wasm: %d %v", n, ok)
	}
	if _, ok := WasmMinus17(append([]byte("\x00asm\x01\x00\x00\x00"), 10, 0xff)); ok {
		t.Error("a truncated module read")
	}
}

func TestDecoderVersionReadsTheConstant(t *testing.T) {
	// The data section is loaded at 0x1000 and the symbol points at its
	// first byte: mov eax, 0x1002001; ret.
	amd := testbin.ELFAt([]testbin.Symbol{{Name: "BrotliDecoderVersion", Defined: true}}, []byte{0xb8, 0x01, 0x20, 0x00, 0x01, 0xc3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0x1000, 0x1000, 62)
	if v, ok := DecoderVersion(amd); !ok || v != V(1, 2, 1) {
		t.Fatalf("amd64: %v %v", v, ok)
	}
	// movz w0, #0x2001; movk w0, #0x100, lsl #16; ret
	arm := []byte{}
	for _, w := range []uint32{0x52800000 | 0x2001<<5, 0x72a00000 | 0x100<<5, 0xd65f03c0, 0} {
		arm = binary.LittleEndian.AppendUint32(arm, w)
	}
	if v, ok := DecoderVersion(testbin.ELFAt([]testbin.Symbol{{Name: "BrotliDecoderVersion", Defined: true}}, arm, 0x2000, 0x2000, 183)); !ok || v != V(1, 2, 1) {
		t.Fatalf("arm64: %v %v", v, ok)
	}
}

// Section fields near 2^64 must not wrap into a valid-looking offset.
func TestOffsetsDoNotWrap(t *testing.T) {
	l := &layout{sections: []section{{va: 0x1000, off: 1<<63 - 1, size: 1<<63 - 1}}}
	if o, ok := l.offset(0x1000 + 1<<63 - 2); ok && o < 1<<62 {
		t.Fatalf("wrapped to %d", o)
	}
	l = &layout{base: 1 << 63, sections: []section{{va: 0, off: 1 << 63, size: 16}}}
	if _, ok := l.offset(4); ok {
		t.Fatal("a wrapping base+offset was accepted")
	}
}
