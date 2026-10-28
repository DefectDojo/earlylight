// Package testbin builds the small binaries the Brotli detector's tests read:
// decoder error tables exactly as each upstream release lays them out, and
// ELF, PE and Mach-O files that define or import decoder symbols.
package testbin

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Upstream error names (c/include/brotli/decode.h) per release that changed
// them, as "PREFIX NAME". -17 BLOCK_SWITCH is the CVE-2026-111497 fix.
var (
	common = []string{
		"_ERROR_FORMAT_ EXUBERANT_NIBBLE", "_ERROR_FORMAT_ RESERVED", "_ERROR_FORMAT_ EXUBERANT_META_NIBBLE",
		"_ERROR_FORMAT_ SIMPLE_HUFFMAN_ALPHABET", "_ERROR_FORMAT_ SIMPLE_HUFFMAN_SAME", "_ERROR_FORMAT_ CL_SPACE",
		"_ERROR_FORMAT_ HUFFMAN_SPACE", "_ERROR_FORMAT_ CONTEXT_MAP_REPEAT", "_ERROR_FORMAT_ BLOCK_LENGTH_1",
		"_ERROR_FORMAT_ BLOCK_LENGTH_2", "_ERROR_FORMAT_ TRANSFORM", "_ERROR_FORMAT_ DICTIONARY",
		"_ERROR_FORMAT_ WINDOW_BITS", "_ERROR_FORMAT_ PADDING_1", "_ERROR_FORMAT_ PADDING_2",
	}
	tail = []string{
		"_ERROR_ DICTIONARY_NOT_SET", "_ERROR_ INVALID_ARGUMENTS", "_ERROR_ALLOC_ CONTEXT_MODES",
		"_ERROR_ALLOC_ TREE_GROUPS", "_ERROR_ALLOC_ CONTEXT_MAP", "_ERROR_ALLOC_ RING_BUFFER_1",
		"_ERROR_ALLOC_ RING_BUFFER_2", "_ERROR_ALLOC_ BLOCK_TYPE_TREES", "_ERROR_ UNREACHABLE",
	}
	success = []string{"_ NO_ERROR", "_ SUCCESS", "_ NEEDS_MORE_INPUT", "_ NEEDS_MORE_OUTPUT"}
)

func list(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var (
	distance    = []string{"_ERROR_FORMAT_ DISTANCE"}
	blockSwitch = []string{"_ERROR_FORMAT_ BLOCK_SWITCH"}
	compound    = []string{"_ERROR_ COMPOUND_DICTIONARY"}
)

// Releases maps a Brotli release to its error names and whether it stores
// them prefixed. 1.0.4 to 1.0.9 dropped COMPOUND_DICTIONARY; 1.1.0 brought
// it back and the prefixed form.
var Releases = map[string]struct {
	Names    []string
	Prefixed bool
}{
	"1.0.2":  {list(success, common, compound, tail), false},
	"1.0.3":  {list(success, common, distance, compound, tail), false},
	"1.0.9":  {list(success, common, distance, tail), false},
	"1.0.10": {list(success, common, distance, blockSwitch, tail), false},
	"1.1.0":  {list(success, common, distance, compound, tail), true},
	"1.1.1":  {list(success, common, distance, blockSwitch, compound, tail), true},
	"1.2.0":  {list(success, common, distance, compound, tail), true},
	"1.2.1":  {list(success, common, distance, blockSwitch, compound, tail), true},
}

// Table returns release's BrotliDecoderErrorString strings as a compiler
// lays them out: NUL-terminated, one after another, preceded by a NUL.
func Table(release string) []byte {
	r, ok := Releases[release]
	if !ok {
		panic("testbin: no release " + release)
	}
	var b bytes.Buffer
	b.WriteByte(0)
	for _, n := range r.Names {
		prefix, name, _ := strings.Cut(n, " ")
		if r.Prefixed {
			b.WriteString(prefix)
		}
		b.WriteString(name)
		b.WriteByte(0)
	}
	b.WriteString("INVALID")
	b.WriteByte(0)
	return b.Bytes()
}

// Symbol is one dynamic symbol: defined in the file, or imported.
type Symbol struct {
	Name    string
	Defined bool
}

// ELF returns a little-endian ELF64 shared object whose .dynsym holds syms,
// followed by extra (a table, a version stamp) in a data section.
func ELF(syms []Symbol, extra []byte) []byte { return ELFAt(syms, extra, 0, 0, 62) }

// ELFAt is ELF with the data section loaded at addr (0: not loaded), each
// defined symbol's value set to value, and the given machine (62 x86-64,
// 183 arm64). The data section is also marked executable, so extra can hold
// code.
func ELFAt(syms []Symbol, extra []byte, addr, value uint64, machine uint16) []byte {
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	var dynsym bytes.Buffer
	dynsym.Write(make([]byte, 24)) // the null symbol
	for _, s := range syms {
		name := uint32(dynstr.Len())
		dynstr.WriteString(s.Name)
		dynstr.WriteByte(0)
		shndx := uint16(0)
		if s.Defined {
			shndx = 4 // .data
		}
		var e [24]byte
		binary.LittleEndian.PutUint32(e[0:], name)
		e[4] = 0x12 // STB_GLOBAL, STT_FUNC
		binary.LittleEndian.PutUint16(e[6:], shndx)
		if s.Defined {
			binary.LittleEndian.PutUint64(e[8:], value)
		}
		dynsym.Write(e[:])
	}
	shstr := []byte("\x00.dynstr\x00.dynsym\x00.shstrtab\x00.data\x00")
	type sec struct {
		name, typ uint32
		data      []byte
		link      uint32
		entsize   uint64
	}
	secs := []sec{
		{},
		{name: 1, typ: 3, data: dynstr.Bytes()}, // SHT_STRTAB
		{name: 9, typ: 11, data: dynsym.Bytes(), link: 1, entsize: 24}, // SHT_DYNSYM
		{name: 17, typ: 3, data: shstr},
		{name: 27, typ: 1, data: extra}, // SHT_PROGBITS
	}
	var body bytes.Buffer
	offs := make([]uint64, len(secs))
	off := uint64(64)
	for i, s := range secs {
		offs[i] = off
		body.Write(s.data)
		off += uint64(len(s.data))
	}
	shoff := off
	var out bytes.Buffer
	var h [64]byte
	copy(h[:], "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(h[16:], 3) // ET_DYN
	binary.LittleEndian.PutUint16(h[18:], machine)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint64(h[40:], shoff)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[58:], 64)
	binary.LittleEndian.PutUint16(h[60:], uint16(len(secs)))
	binary.LittleEndian.PutUint16(h[62:], 3) // .shstrtab
	out.Write(h[:])
	out.Write(body.Bytes())
	for i, s := range secs {
		var sh [64]byte
		binary.LittleEndian.PutUint32(sh[0:], s.name)
		binary.LittleEndian.PutUint32(sh[4:], s.typ)
		if i > 0 {
			binary.LittleEndian.PutUint64(sh[24:], offs[i])
			binary.LittleEndian.PutUint64(sh[32:], uint64(len(s.data)))
		}
		binary.LittleEndian.PutUint32(sh[40:], s.link)
		binary.LittleEndian.PutUint64(sh[48:], 1)
		if i == 4 && addr != 0 {
			binary.LittleEndian.PutUint64(sh[8:], 0x6) // SHF_ALLOC|SHF_EXECINSTR
			binary.LittleEndian.PutUint64(sh[16:], addr)
		}
		binary.LittleEndian.PutUint64(sh[56:], s.entsize)
		if s.typ == 11 {
			binary.LittleEndian.PutUint32(sh[44:], 1) // sh_info: first global
			binary.LittleEndian.PutUint64(sh[48:], 8)
		}
		out.Write(sh[:])
	}
	return out.Bytes()
}

// PE returns a 64-bit PE DLL whose export directory names exports, followed
// by extra.
func PE(exports []string, extra []byte) []byte {
	const (
		lfanew  = 0x40
		fileAl  = 0x200
		sectRVA = 0x1000
	)
	// The .edata section: directory, name pointers, names, then extra.
	var sect bytes.Buffer
	dir := make([]byte, 40)
	sect.Write(dir)
	ptrs := sect.Len()
	sect.Write(make([]byte, 4*len(exports)))
	var nameRVAs []uint32
	for _, e := range exports {
		nameRVAs = append(nameRVAs, uint32(sectRVA+sect.Len()))
		sect.WriteString(e)
		sect.WriteByte(0)
	}
	sect.Write(extra)
	s := sect.Bytes()
	binary.LittleEndian.PutUint32(s[24:], uint32(len(exports)))
	binary.LittleEndian.PutUint32(s[32:], uint32(sectRVA+ptrs))
	for i, r := range nameRVAs {
		binary.LittleEndian.PutUint32(s[ptrs+4*i:], r)
	}
	for len(s)%fileAl != 0 {
		s = append(s, 0)
	}

	var out bytes.Buffer
	dos := make([]byte, lfanew)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], lfanew)
	out.Write(dos)
	out.WriteString("PE\x00\x00")
	var coff [20]byte
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint16(coff[16:], 240)
	binary.LittleEndian.PutUint16(coff[18:], 0x2022) // executable, large address aware, DLL
	out.Write(coff[:])
	opt := make([]byte, 240)
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000) // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], fileAl) // FileAlignment
	binary.LittleEndian.PutUint32(opt[56:], sectRVA+uint32(len(s)))
	binary.LittleEndian.PutUint32(opt[60:], fileAl) // SizeOfHeaders
	binary.LittleEndian.PutUint32(opt[108:], 16)    // NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(opt[112:], sectRVA)
	binary.LittleEndian.PutUint32(opt[116:], uint32(len(s)))
	out.Write(opt)
	var sh [40]byte
	copy(sh[:], ".edata")
	binary.LittleEndian.PutUint32(sh[8:], uint32(len(s)))
	binary.LittleEndian.PutUint32(sh[12:], sectRVA)
	binary.LittleEndian.PutUint32(sh[16:], uint32(len(s)))
	binary.LittleEndian.PutUint32(sh[20:], fileAl)
	binary.LittleEndian.PutUint32(sh[36:], 0x40000040) // initialized data, readable
	out.Write(sh[:])
	for out.Len() < fileAl {
		out.WriteByte(0)
	}
	out.Write(s)
	return out.Bytes()
}

// MachO returns a 64-bit Mach-O dylib whose symbol table holds syms
// (defined ones as exported N_SECT symbols), followed by extra.
func MachO(syms []Symbol, extra []byte) []byte {
	var strtab bytes.Buffer
	strtab.WriteByte(0)
	var nl bytes.Buffer
	for _, s := range syms {
		var e [16]byte
		binary.LittleEndian.PutUint32(e[0:], uint32(strtab.Len()))
		strtab.WriteString("_" + s.Name)
		strtab.WriteByte(0)
		if s.Defined {
			e[4], e[5] = 0x0f, 1 // N_SECT|N_EXT in section 1
		} else {
			e[4] = 0x01 // N_UNDF|N_EXT
		}
		nl.Write(e[:])
	}
	const hdr, symtabCmd = 32, 24
	symoff := hdr + symtabCmd
	stroff := symoff + nl.Len()
	var out bytes.Buffer
	var h [hdr]byte
	binary.LittleEndian.PutUint32(h[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(h[4:], 0x0100000c) // arm64
	binary.LittleEndian.PutUint32(h[12:], 6)         // MH_DYLIB
	binary.LittleEndian.PutUint32(h[16:], 1)
	binary.LittleEndian.PutUint32(h[20:], symtabCmd)
	out.Write(h[:])
	var c [symtabCmd]byte
	binary.LittleEndian.PutUint32(c[0:], 2) // LC_SYMTAB
	binary.LittleEndian.PutUint32(c[4:], symtabCmd)
	binary.LittleEndian.PutUint32(c[8:], uint32(symoff))
	binary.LittleEndian.PutUint32(c[12:], uint32(len(syms)))
	binary.LittleEndian.PutUint32(c[16:], uint32(stroff))
	binary.LittleEndian.PutUint32(c[20:], uint32(strtab.Len()))
	out.Write(c[:])
	out.Write(nl.Bytes())
	out.Write(strtab.Bytes())
	out.Write(extra)
	return out.Bytes()
}

// Executable returns extra behind an ELF header and padding: a file the
// engine reads as an executable, with no symbol tables.
func Executable(extra ...[]byte) []byte {
	b := append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 57)...)
	for _, e := range extra {
		b = append(b, e...)
		b = append(b, make([]byte, 64)...)
	}
	return b
}

// DecoderTables returns the decoder's two code-length tables
// (kCodeLengthPrefixLength, then kCodeLengthPrefixValue) as a compiler lays
// them out, with gap bytes between them.
func DecoderTables(gap int) []byte {
	b := []byte{2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4}
	b = append(b, make([]byte, gap)...)
	return append(b, 0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5)
}
