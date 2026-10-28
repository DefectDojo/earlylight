package fingerprint

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"regexp"
)

// section is one loaded section of an executable: where it is in the file
// and in memory.
type section struct {
	va, off, size uint64
	exec          bool
}

// layout is what the code checks need of an executable: its sections and its
// exported functions, for one architecture.
type layout struct {
	arch      string // "amd64" or "arm64"
	base      uint64 // file offset of this image (a fat Mach-O slice)
	imageBase uint64 // a PE's preferred load address: MSVC code addresses data by its RVA
	sections  []section
	exports   map[string]uint64 // name -> virtual address
}

// offset maps a virtual address to a file offset. Section fields come from
// the file, so every sum is checked for wrapping.
func (l *layout) offset(va uint64) (uint64, bool) {
	for _, s := range l.sections {
		if va >= s.va && va-s.va < s.size {
			o, ok := add(l.base, s.off, va-s.va)
			return o, ok
		}
	}
	return 0, false
}

func (l *layout) vaOf(off uint64) (uint64, bool) {
	for _, s := range l.sections {
		o, ok := add(l.base, s.off)
		if ok && off >= o && off-o < s.size {
			return add(s.va, off-o)
		}
	}
	return 0, false
}

// add sums offsets, reporting false when the sum wraps.
func add(xs ...uint64) (uint64, bool) {
	var t uint64
	for _, x := range xs {
		if t+x < t {
			return 0, false
		}
		t += x
	}
	return t, true
}

// maxExportsRead bounds the symbols read for exports.
const maxExportsRead = 1 << 20

// layouts reads the executables in data: one for an ELF, PE or thin Mach-O
// file, one per slice for a fat Mach-O. Unknown architectures are left out.
func layouts(data []byte) []*layout {
	r := bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil
		}
		l := &layout{exports: map[string]uint64{}}
		switch f.Machine {
		case elf.EM_X86_64:
			l.arch = "amd64"
		case elf.EM_AARCH64:
			l.arch = "arm64"
		default:
			return nil
		}
		for _, s := range f.Sections {
			if s.Type == elf.SHT_NOBITS || s.Addr == 0 || s.Flags&elf.SHF_ALLOC == 0 {
				continue
			}
			l.sections = append(l.sections, section{va: s.Addr, off: s.Offset, size: s.Size, exec: s.Flags&elf.SHF_EXECINSTR != 0})
		}
		if syms, err := f.DynamicSymbols(); err == nil {
			for i, sym := range syms {
				if i >= maxExportsRead {
					break
				}
				if sym.Section != elf.SHN_UNDEF && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
					l.exports[sym.Name] = sym.Value
				}
			}
		}
		return []*layout{l}
	case bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		ff, err := macho.NewFatFile(r)
		if err != nil {
			return nil
		}
		var out []*layout
		for _, a := range ff.Arches {
			if l := machoLayout(a.File); l != nil {
				l.base = uint64(a.Offset)
				out = append(out, l)
			}
		}
		return out
	case bytes.HasPrefix(data, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		f, err := macho.NewFile(r)
		if err != nil {
			return nil
		}
		if l := machoLayout(f); l != nil {
			return []*layout{l}
		}
	case bytes.HasPrefix(data, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return nil
		}
		l := &layout{exports: map[string]uint64{}}
		var imageBase uint64
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			imageBase = oh.ImageBase
		default:
			return nil
		}
		l.imageBase = imageBase
		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			l.arch = "amd64"
		case pe.IMAGE_FILE_MACHINE_ARM64:
			l.arch = "arm64"
		default:
			return nil
		}
		for _, s := range f.Sections {
			l.sections = append(l.sections, section{va: imageBase + uint64(s.VirtualAddress), off: uint64(s.Offset), size: uint64(min(s.Size, s.VirtualSize)),
				exec: s.Characteristics&0x20000000 != 0})
		}
		peExportAddrs(f, data, imageBase, l)
		return []*layout{l}
	}
	return nil
}

func machoLayout(f *macho.File) *layout {
	l := &layout{exports: map[string]uint64{}}
	switch f.Cpu {
	case macho.CpuAmd64:
		l.arch = "amd64"
	case macho.CpuArm64:
		l.arch = "arm64"
	default:
		return nil
	}
	for _, s := range f.Sections {
		if s.Offset == 0 {
			continue
		}
		l.sections = append(l.sections, section{va: s.Addr, off: uint64(s.Offset), size: s.Size, exec: s.Flags&0x80000400 != 0})
	}
	if f.Symtab != nil {
		for i, sym := range f.Symtab.Syms {
			if i >= maxExportsRead {
				break
			}
			if sym.Type&0x0e == 0x0e && sym.Type&0x01 != 0 && len(sym.Name) > 1 {
				l.exports[sym.Name[1:]] = sym.Value
			}
		}
	}
	return l
}

// peExportAddrs reads the export directory's names and addresses.
func peExportAddrs(f *pe.File, data []byte, imageBase uint64, l *layout) {
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || oh.NumberOfRvaAndSizes == 0 {
		return
	}
	dir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	off := func(rva uint32) (int, bool) {
		o, ok := l.offset(imageBase + uint64(rva))
		return int(o), ok && o < uint64(len(data))
	}
	d, ok := off(dir.VirtualAddress)
	if !ok || d+40 > len(data) {
		return
	}
	nNames := binary.LittleEndian.Uint32(data[d+24:])
	funcs, ok1 := off(binary.LittleEndian.Uint32(data[d+28:]))
	names, ok2 := off(binary.LittleEndian.Uint32(data[d+32:]))
	ords, ok3 := off(binary.LittleEndian.Uint32(data[d+36:]))
	if !ok1 || !ok2 || !ok3 {
		return
	}
	for i := 0; i < int(min(nNames, maxExports)); i++ {
		if names+4*i+4 > len(data) || ords+2*i+2 > len(data) {
			return
		}
		no, ok := off(binary.LittleEndian.Uint32(data[names+4*i:]))
		if !ok {
			continue
		}
		e := bytes.IndexByte(data[no:min(len(data), no+64)], 0)
		if e <= 0 {
			continue
		}
		ord := int(binary.LittleEndian.Uint16(data[ords+2*i:]))
		if funcs+4*ord+4 > len(data) {
			continue
		}
		l.exports[string(data[no:no+e])] = imageBase + uint64(binary.LittleEndian.Uint32(data[funcs+4*ord:]))
	}
}

// DecoderVersion reads the release an exported BrotliDecoderVersion returns:
// its body is a constant load and a return. It proves only what upstream
// numbering can: a fixed release (1.0.10, 1.1.1, 1.2.1 or later) or one that
// predates the flaw (before 1.0.3). A copy that says 1.0.3 to 1.2.0 may still
// be fixed (a vendor backport, or upstream master after February 27, 2026,
// which kept saying 1.2.0).
func DecoderVersion(data []byte) (Version, bool) {
	if !bytes.Contains(data, []byte("BrotliDecoderVersion")) {
		return Version{}, false
	}
	for _, l := range layouts(data) {
		va, ok := l.exports["BrotliDecoderVersion"]
		if !ok {
			continue
		}
		o, ok := l.offset(va)
		if !ok || o > uint64(len(data)) || uint64(len(data))-o < 16 {
			continue
		}
		code := data[o : o+16]
		var hex uint32
		found := false
		switch l.arch {
		case "amd64":
			c := bytes.TrimPrefix(code, []byte{0xf3, 0x0f, 0x1e, 0xfa}) // endbr64
			if len(c) >= 6 && c[0] == 0xb8 && c[5] == 0xc3 {            // mov eax, imm32; ret
				hex, found = binary.LittleEndian.Uint32(c[1:5]), true
			}
		case "arm64":
			// movz w0, #lo; movk w0, #hi, lsl #16; ret
			i0, i1, i2 := binary.LittleEndian.Uint32(code), binary.LittleEndian.Uint32(code[4:]), binary.LittleEndian.Uint32(code[8:])
			if i0&0xffe0001f == 0x52800000 && i1&0xffe0001f == 0x72a00000 && i2 == 0xd65f03c0 {
				hex, found = (i0>>5)&0xffff|((i1>>5)&0xffff)<<16, true
			}
		}
		if found {
			return V(int(hex>>24), int(hex>>12&0xfff), int(hex&0xfff)), true
		}
	}
	return Version{}, false
}

// ReleaseFixed reports whether an upstream release number is a fixed
// release, and whether it predates the flaw.
func ReleaseFixed(v Version) (fixed, predates bool) {
	switch {
	case v.Major > 1, v.Major == 1 && v.Minor > 2:
		return true, false
	case v.Major == 1 && v.Minor == 0 && v.Patch < 3:
		return false, true
	case v.Major == 1 && v.Minor == 0:
		return v.Patch >= 10, false
	case v.Major == 1:
		return v.Patch >= 1, false // 1.1.1, 1.2.1
	}
	return false, false
}

// The fix makes the six block-switch decoders return error -17
// (BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH); no release before it uses -17
// at all, since the code was reserved. On x86-64 that is a "mov r32, -17"
// immediate in the decoder's code.
var minus17 = []byte{0xef, 0xff, 0xff, 0xff}

// countMov17 counts "mov r32, -17" (b8+r imm32, or 41 b8+r imm32 for r8d to
// r15d). Go's regexp matches runes, not bytes, so this is a plain scan.
func countMov17(b []byte) int {
	n := 0
	for i := 0; ; {
		j := bytes.Index(b[i:], minus17)
		if j < 0 {
			return n
		}
		at := i + j
		if at >= 1 && b[at-1] >= 0xb8 && b[at-1] <= 0xbf {
			n++
		}
		i = at + 1
	}
}

// codeWindow is how far from an instruction that loads the decoder's
// code-length tables the decoder's functions are counted.
const codeWindow = 48 << 10

// maxCodeRefs bounds the table references followed in one file.
const maxCodeRefs = 16

// CodeMarker counts the "mov r32, -17" instructions in the x86-64 code around
// the instructions that load the decoder's code-length tables (RIP-relative
// lea). located is false when the decoder's code was not found that way (not
// x86-64, or no such reference), and then count means nothing. Measured on
// Envoy, Istio, Node.js and .NET for Windows, Electron and Python wheels:
// unfixed decoders have none, fixed ones three to twelve.
func CodeMarker(data []byte) (count int, located bool) {
	for _, l := range layouts(data) {
		if l.arch != "amd64" {
			continue
		}
		var targets []uint64
		for i, n := 0, 0; n < maxAnchors; n++ {
			j := bytes.Index(data[i:], prefixLength)
			if j < 0 {
				break
			}
			at := i + j
			i = at + 1
			lo, hi := max(0, at-tablesNear), min(len(data), at+len(prefixLength)+tablesNear)
			if !bytes.Contains(data[lo:hi], prefixValue) {
				continue
			}
			if va, ok := l.vaOf(uint64(at)); ok {
				targets = append(targets, va)
			}
		}
		if len(targets) == 0 {
			continue
		}
		refs := 0
		for _, s := range l.sections {
			if !s.exec {
				continue
			}
			start, ok1 := add(l.base, s.off)
			stop, ok2 := add(start, s.size)
			end := min(uint64(len(data)), stop)
			if !ok1 || !ok2 || start >= end {
				continue
			}
			text := data[start:end]
			count1 := func(k int) {
				refs++
				located = true
				w := text[max(0, k-codeWindow):min(len(text), k+codeWindow)]
				count = max(count, countMov17(w))
			}
			// MSVC addresses data by its RVA from the image base, and
			// non-PIE code by its absolute address: a 32-bit field equal to
			// either is a reference.
			for _, t := range targets {
				var fields [][]byte
				if l.imageBase != 0 && t-l.imageBase < 1<<32 {
					fields = append(fields, binary.LittleEndian.AppendUint32(nil, uint32(t-l.imageBase)))
				} else if t < 1<<31 {
					fields = append(fields, binary.LittleEndian.AppendUint32(nil, uint32(t)))
				}
				for _, fld := range fields {
					for i := 0; refs < maxCodeRefs; {
						j := bytes.Index(text[i:], fld)
						if j < 0 {
							break
						}
						count1(i + j)
						i += j + 1
					}
				}
			}
			for k := 0; k+7 <= len(text) && refs < maxCodeRefs; k++ {
				if (text[k] != 0x48 && text[k] != 0x4c) || text[k+1] != 0x8d || text[k+2]&0xc7 != 0x05 {
					continue
				}
				disp := int64(int32(binary.LittleEndian.Uint32(text[k+3:])))
				target := uint64(int64(s.va) + int64(k) + 7 + disp)
				if !nearTables(targets, target) {
					continue
				}
				count1(k)
			}
		}
		if located {
			return count, true
		}
	}
	for _, l := range layouts(data) {
		if l.arch == "arm64" {
			if n, ok := arm64Marker(data, l); ok {
				return n, true
			}
		}
	}
	return 0, false
}

// arm64Marker is CodeMarker for arm64: the decoder's code reaches its tables
// with ADRP and an ADD or LDRB of the low bits, and returns -17 with
// "movn wN, #16".
func arm64Marker(data []byte, l *layout) (int, bool) {
	var targets []uint64
	for i, n := 0, 0; n < maxAnchors; n++ {
		j := bytes.Index(data[i:], prefixLength)
		if j < 0 {
			break
		}
		at := i + j
		i = at + 1
		lo, hi := max(0, at-tablesNear), min(len(data), at+len(prefixLength)+tablesNear)
		if !bytes.Contains(data[lo:hi], prefixValue) {
			continue
		}
		if va, ok := l.vaOf(uint64(at)); ok {
			targets = append(targets, va)
		}
	}
	if len(targets) == 0 {
		return 0, false
	}
	hit := func(va uint64) bool { return nearTables(targets, va) }
	count, located, refs := 0, false, 0
	for _, s := range l.sections {
		if !s.exec {
			continue
		}
		start, ok1 := add(l.base, s.off)
		stop, ok2 := add(start, s.size)
		end := min(uint64(len(data)), stop)
		if !ok1 || !ok2 || start >= end {
			continue
		}
		text := data[start:end]
		for k := 0; k+4 <= len(text) && refs < maxCodeRefs; k += 4 {
			w := binary.LittleEndian.Uint32(text[k:])
			if w&0x9f000000 != 0x90000000 { // ADRP Xd, page
				continue
			}
			rd := w & 0x1f
			imm := int64((w>>29)&3 | (w>>5&0x7ffff)<<2)
			if imm&(1<<20) != 0 {
				imm -= 1 << 21
			}
			pc := s.va + uint64(k)
			page := uint64(int64(pc&^0xfff) + imm<<12)
			for m := k + 4; m < min(len(text)-3, k+20); m += 4 {
				x := binary.LittleEndian.Uint32(text[m:])
				var low uint64
				switch {
				case x&0xffc00000 == 0x91000000 && (x>>5)&0x1f == rd: // ADD Xd, Xn, #imm12
					low = uint64(x >> 10 & 0xfff)
				case x&0xffc00000 == 0x39400000 && (x>>5)&0x1f == rd: // LDRB Wt, [Xn, #imm12]
					low = uint64(x >> 10 & 0xfff)
				default:
					continue
				}
				if !hit(page + low) {
					continue
				}
				refs++
				located = true
				wlo, whi := max(0, k-codeWindow)&^3, min(len(text), k+codeWindow)
				n := 0
				for q := wlo; q+4 <= whi; q += 4 {
					if binary.LittleEndian.Uint32(text[q:])&0xffffffe0 == 0x12800200 { // movn wN, #16: -17
						n++
					}
				}
				count = max(count, n)
				break
			}
		}
	}
	return count, located
}

// PEFileVersion reads a PE file's VS_FIXEDFILEINFO file version.
func PEFileVersion(data []byte) (major, minor, build, rev int, ok bool) {
	if !bytes.HasPrefix(data, []byte("MZ")) {
		return 0, 0, 0, 0, false
	}
	sig := []byte{0xbd, 0x04, 0xef, 0xfe}
	i := bytes.Index(data, sig)
	if i < 0 || i+16 > len(data) {
		return 0, 0, 0, 0, false
	}
	ms := binary.LittleEndian.Uint32(data[i+8:])
	ls := binary.LittleEndian.Uint32(data[i+12:])
	return int(ms >> 16), int(ms & 0xffff), int(ls >> 16), int(ls & 0xffff), true
}

// envoyStamp is Envoy's build_scm_revision and build_scm_status, which the
// version string is built from.
var (
	envoyStamp   = regexp.MustCompile(`\x00[0-9a-f]{40}\x00(?:Clean|Modified)\x00`)
	envoyVersion = regexp.MustCompile(`\x00(1\.[0-9]{2}\.[0-9]{1,2})(-dev)?\x00`)
)

// EnvoyVersion reads an Envoy build's own release, from the version number
// linked next to its build stamp: only when the stamp is there and exactly
// one such number is. dev is true for an X.Y.Z-dev build, which contains
// X.Y.(Z-1) and later commits.
func EnvoyVersion(data []byte) (v Version, dev bool, ok bool) {
	if !envoyStamp.Match(data) {
		return Version{}, false, false
	}
	ms := envoyVersion.FindAllSubmatch(data, 3)
	if len(ms) != 1 {
		return Version{}, false, false
	}
	parsed, _, ok := parseVersion(ms[0][1])
	if !ok {
		return Version{}, false, false
	}
	return parsed, len(ms[0][2]) > 0, true
}

// IsElectron reports an Electron binary, whose Brotli decoder is
// Chromium's, not the bundled Node.js's.
func IsElectron(data []byte) bool { return bytes.Contains(data, []byte("ELECTRON_RUN_AS_NODE")) }

// RustPort reports a file built from the pure Rust Brotli crates (brotli,
// brotli-decompressor), whose decoder is a port, not Google's C code: it
// carries the same tables, but the C decoder's flaw is not in it.
func RustPort(data []byte) bool {
	return bytes.Contains(data, []byte("brotli-decompressor-")) || bytes.Contains(data, []byte("brotli-decompressor/src/"))
}

// IsWasm reports a WebAssembly module, which can carry the C decoder
// compiled to WASM.
func IsWasm(data []byte) bool { return bytes.HasPrefix(data, []byte("\x00asm\x01\x00\x00\x00")) }

// WasmMinus17 counts "i32.const -17" (0x41 0x6f) in a WebAssembly module's
// code section. ok is false when the module has no code section it can read.
// A fixed decoder returns -17 from its block-switch functions, so a module
// that carries the decoder and has none is unfixed; any other count proves
// nothing, since other code in the module can use -17 too.
func WasmMinus17(data []byte) (count int, ok bool) {
	if !IsWasm(data) {
		return 0, false
	}
	for i := 8; i < len(data); {
		id := data[i]
		size, n := uleb(data[i+1:])
		if n == 0 {
			return 0, false
		}
		start := i + 1 + n
		end := start + int(size)
		if size > uint64(len(data)) || end > len(data) || end < start {
			return 0, false
		}
		if id == 10 {
			return bytes.Count(data[start:end], []byte{0x41, 0x6f}), true
		}
		i = end
	}
	return 0, false
}

func uleb(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}

// nearTables reports whether va falls on the decoder's two code-length
// tables: code may address either one, or the start of the pair.
func nearTables(targets []uint64, va uint64) bool {
	for _, t := range targets {
		if va+tablesNear >= t && va <= t+uint64(len(prefixLength))+tablesNear {
			return true
		}
	}
	return false
}
