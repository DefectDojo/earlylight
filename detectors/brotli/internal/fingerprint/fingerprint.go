// Package fingerprint reads what a binary proves about the Brotli decoder it
// carries, without running it.
//
// The main evidence is the decoder's error-name table, the strings
// BrotliDecoderErrorString returns. The CVE-2026-111497 fix (google/brotli
// commit 0ed4268) made the block-switch decoder return a new error code,
// BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (-17), so every build with the fix,
// upstream or a vendor backport, has BLOCK_SWITCH in that table. DISTANCE
// (-16) arrived in Brotli 1.0.3, the first affected release. Brotli 1.0.x
// stores bare names ("DISTANCE"), 1.1.0 and later prefixed ones
// ("_ERROR_FORMAT_DISTANCE").
//
// Builds that strip the table (.NET 8, Bun, Envoy) are judged by the version
// stamps those products embed, or reported as unknown.
package fingerprint

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"strconv"
)

// Error names in the decoder's table, besides DISTANCE and BLOCK_SWITCH, with
// the prefix 1.1.0 and later put in front of each.
var tableNames = []struct{ prefix, name string }{
	{"_ERROR_FORMAT_", "EXUBERANT_NIBBLE"},
	{"_ERROR_FORMAT_", "RESERVED"},
	{"_ERROR_FORMAT_", "EXUBERANT_META_NIBBLE"},
	{"_ERROR_FORMAT_", "SIMPLE_HUFFMAN_ALPHABET"},
	{"_ERROR_FORMAT_", "SIMPLE_HUFFMAN_SAME"},
	{"_ERROR_FORMAT_", "CL_SPACE"},
	{"_ERROR_FORMAT_", "HUFFMAN_SPACE"},
	{"_ERROR_FORMAT_", "CONTEXT_MAP_REPEAT"},
	{"_ERROR_FORMAT_", "BLOCK_LENGTH_1"},
	{"_ERROR_FORMAT_", "BLOCK_LENGTH_2"},
	{"_ERROR_FORMAT_", "TRANSFORM"},
	{"_ERROR_FORMAT_", "DICTIONARY"},
	{"_ERROR_FORMAT_", "WINDOW_BITS"},
	{"_ERROR_FORMAT_", "PADDING_1"},
	{"_ERROR_FORMAT_", "PADDING_2"},
	{"_ERROR_", "COMPOUND_DICTIONARY"},
	{"_ERROR_", "DICTIONARY_NOT_SET"},
	{"_ERROR_", "INVALID_ARGUMENTS"},
	{"_ERROR_ALLOC_", "CONTEXT_MODES"},
	{"_ERROR_ALLOC_", "TREE_GROUPS"},
	{"_ERROR_ALLOC_", "CONTEXT_MAP"},
	{"_ERROR_ALLOC_", "RING_BUFFER_1"},
	{"_ERROR_ALLOC_", "RING_BUFFER_2"},
	{"_ERROR_ALLOC_", "BLOCK_TYPE_TREES"},
	{"_ERROR_", "UNREACHABLE"},
}

const (
	// anchor is the name every table is found by: no other software names a
	// string EXUBERANT_META_NIBBLE.
	anchor = "EXUBERANT_META_NIBBLE"
	// window is how far from the anchor the rest of the table may lie. The
	// whole table spans under 1 KiB in every build measured.
	window = 4096
	// prefixedWindow is the window for the 1.1.0 and later form, whose names
	// are specific enough to look further: Bun on Windows spreads its table
	// over about 90 KiB.
	prefixedWindow = 128 << 10
	// MinNames is how many names besides DISTANCE and BLOCK_SWITCH must sit
	// around the anchor for it to count as a decoder's table. Each release has
	// 23 to 25 of them.
	MinNames = 12
	// maxAnchors bounds the work on a hostile file full of anchors.
	maxAnchors = 64
)

// Table is one decoder error-name table found in a file.
type Table struct {
	Offset int
	// Prefixed is true for the 1.1.0 and later form, "_ERROR_FORMAT_DISTANCE".
	Prefixed bool
	// Names counts the other error names found with the anchor.
	Names int
	// Distance: the table has DISTANCE, so the decoder is Brotli 1.0.3 or later.
	Distance bool
	// BlockSwitch: the table has BLOCK_SWITCH, so the decoder has the fix.
	BlockSwitch bool
	// Compound: the table has COMPOUND_DICTIONARY, which Brotli 1.0.0 to
	// 1.0.3 and 1.1.0 and later have, and 1.0.4 to 1.0.10 do not.
	Compound bool
	lo, hi   int // the window its names were read from
}

// Tables returns every decoder error-name table in data. A table is the anchor
// as a whole C string, in the bare or the prefixed form, with at least
// MinNames other names around it in the same form. Names in other strings,
// such as the BROTLI_DECODER_ERROR_* constant names Node.js exports, never
// count: they do not start right after a NUL byte.
func Tables(data []byte) []Table {
	type anchorAt struct {
		at       int
		prefixed bool
	}
	var anchors []anchorAt
	for i, n := 0, 0; n < maxAnchors; n++ {
		j := bytes.Index(data[i:], []byte(anchor+"\x00"))
		if j < 0 {
			break
		}
		at := i + j
		i = at + len(anchor)
		switch {
		case hasSuffix(data[:at], "\x00_ERROR_FORMAT_"):
			anchors = append(anchors, anchorAt{at, true})
		case at > 0 && data[at-1] == 0:
			anchors = append(anchors, anchorAt{at, false})
		}
	}
	var out []Table
	for k, a := range anchors {
		lo, hi := bounds(len(data), a.at, a.prefixed)
		// Two decoders in one file: each name belongs to the nearer anchor.
		if k > 0 {
			lo = max(lo, (anchors[k-1].at+a.at)/2)
		}
		if k+1 < len(anchors) {
			hi = min(hi, (a.at+anchors[k+1].at)/2)
		}
		w := data[lo:hi]
		t := Table{Offset: a.at, Prefixed: a.prefixed}
		for _, n := range tableNames {
			if hasName(w, n.prefix, n.name, a.prefixed) {
				t.Names++
			}
		}
		if t.Names < MinNames {
			continue
		}
		t.Distance = hasName(w, "_ERROR_FORMAT_", "DISTANCE", a.prefixed)
		t.BlockSwitch = hasName(w, "_ERROR_FORMAT_", "BLOCK_SWITCH", a.prefixed)
		t.Compound = hasName(w, "_ERROR_", "COMPOUND_DICTIONARY", a.prefixed)
		t.lo, t.hi = lo, hi
		out = append(out, t)
	}
	return out
}

// bounds is the window around an anchor.
func bounds(n, at int, prefixed bool) (int, int) {
	wn := window
	if prefixed {
		wn = prefixedWindow
	}
	return max(0, at-wn), min(n, at+wn)
}

func hasName(w []byte, prefix, name string, prefixed bool) bool {
	s := "\x00" + name + "\x00"
	if prefixed {
		s = "\x00" + prefix + name + "\x00"
	}
	return bytes.Contains(w, []byte(s))
}

func hasSuffix(b []byte, s string) bool { return bytes.HasSuffix(b, []byte(s)) }

// StrayBlockSwitch reports whether data names BLOCK_SWITCH anywhere but as
// the whole error name of a table that has it: for example inside another
// string a linker merged it into, or as a constant name. A file with an
// unfixed table and such a name cannot be proven unfixed.
func StrayBlockSwitch(data []byte, tables []Table) bool {
	for i, n := 0, 0; n < maxAnchors; n++ {
		j := bytes.Index(data[i:], []byte("BLOCK_SWITCH\x00"))
		if j < 0 {
			return false
		}
		at := i + j
		i = at + 1
		own := false
		for _, t := range tables {
			if !t.BlockSwitch || at < t.lo || at >= t.hi {
				continue
			}
			if t.Prefixed && hasSuffix(data[:at], "\x00_ERROR_FORMAT_") || !t.Prefixed && at > 0 && data[at-1] == 0 {
				own = true
			}
		}
		if !own {
			return true
		}
	}
	return true // too many to check: assume one is stray
}

// decoderSymbols are the functions a library exports when it carries a
// Brotli decoder.
var decoderSymbols = []string{"BrotliDecoderDecompressStream", "BrotliDecoderDecompress"}

// ExportsDecoder reports whether an ELF, Mach-O or PE file defines and
// exports the Brotli decoder's entry points. A program that only imports them
// from a shared libbrotlidec does not carry a decoder of its own.
func ExportsDecoder(data []byte) bool {
	if !bytes.Contains(data, []byte("BrotliDecoderDecompress")) {
		return false
	}
	r := bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return false
		}
		syms, err := f.DynamicSymbols()
		if err != nil {
			return false
		}
		for _, s := range syms {
			if s.Section != elf.SHN_UNDEF && isDecoderSymbol(s.Name) {
				return true
			}
		}
	case bytes.HasPrefix(data, []byte{0xca, 0xfe, 0xba, 0xbe}):
		ff, err := macho.NewFatFile(r)
		if err != nil {
			return false
		}
		for _, a := range ff.Arches {
			if machoExports(a.File) {
				return true
			}
		}
	case bytes.HasPrefix(data, []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(data, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xcf}), bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xce}):
		f, err := macho.NewFile(r)
		if err != nil {
			return false
		}
		return machoExports(f)
	case bytes.HasPrefix(data, []byte("MZ")):
		return peExports(data)
	}
	return false
}

func isDecoderSymbol(name string) bool {
	for _, s := range decoderSymbols {
		if name == s {
			return true
		}
	}
	return false
}

// machoExports reports a defined external decoder symbol. Mach-O prefixes C
// names with an underscore.
func machoExports(f *macho.File) bool {
	if f.Symtab == nil {
		return false
	}
	const nExt, nType, nSect = 0x01, 0x0e, 0x0e
	for _, s := range f.Symtab.Syms {
		if s.Type&nExt != 0 && s.Type&nType == nSect && len(s.Name) > 1 && isDecoderSymbol(s.Name[1:]) {
			return true
		}
	}
	return false
}

// maxExports bounds the export names read from one PE file.
const maxExports = 1 << 16

// peExports reads the names in a PE file's export directory.
func peExports(data []byte) bool {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return false
	}
	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > 0 {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > 0 {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	}
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return false
	}
	off := func(rva uint32) (int, bool) {
		for _, s := range f.Sections {
			if rva >= s.VirtualAddress && rva-s.VirtualAddress < s.Size {
				o := int64(s.Offset) + int64(rva-s.VirtualAddress)
				if o >= 0 && o < int64(len(data)) {
					return int(o), true
				}
			}
		}
		return 0, false
	}
	d, ok := off(dir.VirtualAddress)
	if !ok || d+40 > len(data) {
		return false
	}
	n := binary.LittleEndian.Uint32(data[d+24:])
	names, ok := off(binary.LittleEndian.Uint32(data[d+32:]))
	if !ok {
		return false
	}
	for i := 0; i < int(min(n, maxExports)); i++ {
		p := names + 4*i
		if p+4 > len(data) {
			return false
		}
		o, ok := off(binary.LittleEndian.Uint32(data[p:]))
		if !ok {
			continue
		}
		e := bytes.IndexByte(data[o:min(len(data), o+64)], 0)
		if e > 0 && isDecoderSymbol(string(data[o:o+e])) {
			return true
		}
	}
	return false
}

// Version is a three-part release number.
type Version struct{ Major, Minor, Patch int }

// V returns the version major.minor.patch.
func V(major, minor, patch int) Version { return Version{Major: major, Minor: minor, Patch: patch} }

func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// Less reports whether v is an earlier release than w.
func (v Version) Less(w Version) bool {
	if v.Major != w.Major {
		return v.Major < w.Major
	}
	if v.Minor != w.Minor {
		return v.Minor < w.Minor
	}
	return v.Patch < w.Patch
}

// parseVersion reads "1.2.3" at the start of b, digits only, and returns the
// version and how many bytes it used.
func parseVersion(b []byte) (Version, int, bool) {
	var parts [3]int
	i := 0
	for k := range parts {
		start := i
		for i < len(b) && i-start < 6 && b[i] >= '0' && b[i] <= '9' {
			parts[k] = parts[k]*10 + int(b[i]-'0')
			i++
		}
		if i == start {
			return Version{}, 0, false
		}
		if k < 2 {
			if i >= len(b) || b[i] != '.' {
				return Version{}, 0, false
			}
			i++
		}
	}
	return V(parts[0], parts[1], parts[2]), i, true
}

// DotnetRuntime reads the runtime release from a .NET native library's
// "@(#)Version 8.0.3326.52219" stamp. The third field is the patch release
// times 100 plus the two-digit build year, so 3326 is 8.0.33; a GA build has
// only the year (8.0.23 is 8.0.0). Previews and release candidates of .NET 11
// and later do not follow the scheme and are not read.
func DotnetRuntime(data []byte) (Version, bool) {
	i := bytes.Index(data, []byte("@(#)Version "))
	if i < 0 {
		return Version{}, false
	}
	b := data[i+len("@(#)Version "):]
	v, n, ok := parseVersion(b)
	if !ok || n >= len(b) || b[n] != '.' || v.Major < 5 || v.Major > 10 {
		return Version{}, false
	}
	if v.Patch >= 100 {
		v.Patch /= 100
	} else {
		v.Patch = 0
	}
	return v, true
}

// NodeVersion reads an official Node.js build's own release from its headers
// download URL, process.release.headersUrl.
func NodeVersion(data []byte) (Version, bool) {
	const marker = "nodejs.org/download/release/v"
	for i, n := 0, 0; n < maxAnchors; n++ {
		j := bytes.Index(data[i:], []byte(marker))
		if j < 0 {
			break
		}
		at := i + j + len(marker)
		i = at
		b := data[at:]
		v, k, ok := parseVersion(b)
		// The headers, source and Windows import library URLs all name the
		// build's own release: .../v24.22.0/node-v24.22.0-headers.tar.gz,
		// .../v24.22.0/win-x64/node.lib.
		if ok && (bytes.HasPrefix(b[k:], []byte("/node-v")) || bytes.HasPrefix(b[k:], []byte("/win-"))) {
			return v, true
		}
	}
	return Version{}, false
}

// BunVersion reads a Bun build's release from its "Bun v1.4.4 (" banner,
// which executables compiled with bun build --compile also carry.
func BunVersion(data []byte) (Version, bool) {
	const marker = "Bun v"
	for i, n := 0, 0; n < maxAnchors; n++ {
		j := bytes.Index(data[i:], []byte(marker))
		if j < 0 {
			break
		}
		at := i + j + len(marker)
		i = at
		v, k, ok := parseVersion(data[at:])
		if ok && bytes.HasPrefix(data[at+k:], []byte(" (")) {
			return v, true
		}
	}
	return Version{}, false
}

// dictionary is the start of Brotli's built-in dictionary, which every
// encoder and decoder links.
const dictionary = "timedownlifeleftbackcodedatashowonlysitecityopenjustlike"

// HasDictionary reports whether data carries Brotli's built-in dictionary,
// so Brotli code is linked in, decoder or encoder.
func HasDictionary(data []byte) bool { return bytes.Contains(data, []byte(dictionary)) }

// NamesDistance reports whether any string in data ends in DISTANCE: the
// decoder's own error name, or another string a linker could have merged it
// into. Only a file with none at all proves a table without DISTANCE predates
// Brotli 1.0.3.
func NamesDistance(data []byte) bool { return bytes.Contains(data, []byte("DISTANCE\x00")) }

// The decoder reads code-length codes through two 16-entry tables that only
// the decoder has (c/dec/decode.c kCodeLengthPrefixLength and
// kCodeLengthPrefixValue, unchanged from 1.0.0 to 1.2.1). Compilers keep them
// as data next to each other, so they prove a decoder is linked in even when
// its error table and symbols are stripped. The encoder and the shared
// library (libbrotlicommon) have neither.
var (
	prefixLength = []byte{2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4}
	prefixValue  = []byte{0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5}
)

// tablesNear is how far apart the two tables may lie: 16 to 64 bytes in every
// build measured.
const tablesNear = 256

// HasDecoderTables reports whether data carries the Brotli decoder's
// code-length tables, both, within tablesNear bytes of each other.
func HasDecoderTables(data []byte) bool {
	for i, n := 0, 0; n < maxAnchors; n++ {
		j := bytes.Index(data[i:], prefixLength)
		if j < 0 {
			return false
		}
		at := i + j
		lo, hi := max(0, at-tablesNear), min(len(data), at+len(prefixLength)+tablesNear)
		if bytes.Contains(data[lo:hi], prefixValue) {
			return true
		}
		i = at + 1
	}
	return false
}
