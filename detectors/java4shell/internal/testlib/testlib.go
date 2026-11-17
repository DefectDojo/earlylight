// Package testlib builds small stand-ins for Java VM libraries for tests: an
// executable header for the architecture, the HotSpot version line and,
// optionally, the AVX-512 VBMI decode stubs' names.
package testlib

import (
	"encoding/binary"
	"fmt"
)

// Lib describes a fake VM library.
type Lib struct {
	Format  string // elf (default), pe, macho, fat
	Machine string // x86-64 (default), aarch64, x86
	Version string // "" for no version line
	OS      string // linux (default)
	VBMI    bool
	VMName  string // OpenJDK 64-Bit Server VM (default)
	Extra   string // more bytes
}

// Build returns the file's bytes.
func Build(l Lib) []byte {
	if l.Machine == "" {
		l.Machine = "x86-64"
	}
	if l.OS == "" {
		l.OS = "linux"
	}
	if l.VMName == "" {
		l.VMName = "OpenJDK 64-Bit Server VM"
	}
	var b []byte
	switch l.Format {
	case "pe":
		b = make([]byte, 0x100)
		b[0], b[1] = 'M', 'Z'
		binary.LittleEndian.PutUint32(b[60:], 0x80)
		copy(b[0x80:], "PE\x00\x00")
		m := map[string]uint16{"x86-64": 0x8664, "aarch64": 0xaa64, "x86": 0x14c}[l.Machine]
		binary.LittleEndian.PutUint16(b[0x84:], m)
	case "macho":
		b = make([]byte, 32)
		binary.LittleEndian.PutUint32(b, 0xfeedfacf)
		binary.LittleEndian.PutUint32(b[4:], map[string]uint32{"x86-64": 0x01000007, "aarch64": 0x0100000c}[l.Machine])
	case "fat":
		b = make([]byte, 8+2*20)
		binary.BigEndian.PutUint32(b, 0xcafebabe)
		binary.BigEndian.PutUint32(b[4:], 2)
		binary.BigEndian.PutUint32(b[8:], 0x01000007)
		binary.BigEndian.PutUint32(b[28:], 0x0100000c)
	default:
		b = make([]byte, 64)
		copy(b, "\x7fELF\x02\x01\x01")
		m := map[string]uint16{"x86-64": 0x3e, "aarch64": 0xb7, "x86": 3}[l.Machine]
		binary.LittleEndian.PutUint16(b[18:], m)
	}
	cpu := map[string]string{"x86-64": "amd64", "aarch64": "aarch64", "x86": "x86"}[l.Machine]
	if l.Version != "" {
		b = append(b, 0)
		b = append(b, fmt.Sprintf("%s (%s) for %s-%s JRE (%s), built on 2026-10-20T00:00:00Z by \"admin\" with gcc 11.3.0", l.VMName, l.Version, l.OS, cpu, l.Version)...)
		b = append(b, 0)
	}
	if l.VBMI {
		b = append(b, "lookup_lo_base64\x00lookup_hi_base64\x00pack_vec_base64\x00join_0_1_base64\x00"...)
	}
	b = append(b, l.Extra...)
	return b
}

// Release returns a release file.
func Release(kv ...string) []byte {
	var out []byte
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, fmt.Sprintf("%s=%q\n", kv[i], kv[i+1])...)
	}
	return out
}
