// Package testelf builds the small ELF executables the sshole tests read.
package testelf

import (
	"bytes"
	"encoding/binary"
)

// ELF builds a little-endian ELF64 executable with an optional
// PT_INTERP, a .dynamic section listing needed libraries, and extra bytes
// (the strings an sshd carries) in a data section.
func ELF(interp string, needed []string, extra ...string) []byte {
	le := binary.LittleEndian
	var dynstr bytes.Buffer
	dynstr.WriteByte(0)
	var offs []uint32
	for _, n := range needed {
		offs = append(offs, uint32(dynstr.Len()))
		dynstr.WriteString(n)
		dynstr.WriteByte(0)
	}
	var dyn bytes.Buffer
	for _, o := range offs {
		binary.Write(&dyn, le, uint64(1)) // DT_NEEDED
		binary.Write(&dyn, le, uint64(o))
	}
	binary.Write(&dyn, le, uint64(0)) // DT_NULL
	binary.Write(&dyn, le, uint64(0))

	var data bytes.Buffer
	data.WriteByte(0)
	for _, e := range extra {
		data.WriteString(e)
		data.WriteByte(0)
	}
	shstr := []byte("\x00.interp\x00.dynstr\x00.dynamic\x00.data\x00.shstrtab\x00")
	name := func(s string) uint32 { return uint32(bytes.Index(shstr, []byte("\x00"+s+"\x00")) + 1) }

	const ehsize, phsize, shsize = 64, 56, 64
	nph := 1
	if interp != "" {
		nph = 2
	}
	off := uint64(ehsize + nph*phsize)
	interpB := []byte(interp + "\x00")
	interpOff := off
	if interp != "" {
		off += uint64(len(interpB))
	}
	dynstrOff := off
	off += uint64(dynstr.Len())
	off = (off + 7) &^ 7
	dynOff := off
	off += uint64(dyn.Len())
	dataOff := off
	off += uint64(data.Len())
	shstrOff := off
	off += uint64(len(shstr))
	off = (off + 7) &^ 7
	shOff := off

	var b bytes.Buffer
	b.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	b.Write(make([]byte, 8))
	binary.Write(&b, le, uint16(3))  // ET_DYN
	binary.Write(&b, le, uint16(62)) // x86-64
	binary.Write(&b, le, uint32(1))
	binary.Write(&b, le, uint64(0))
	binary.Write(&b, le, uint64(ehsize))
	binary.Write(&b, le, shOff)
	binary.Write(&b, le, uint32(0))
	binary.Write(&b, le, uint16(ehsize))
	binary.Write(&b, le, uint16(phsize))
	binary.Write(&b, le, uint16(nph))
	binary.Write(&b, le, uint16(shsize))
	binary.Write(&b, le, uint16(6))
	binary.Write(&b, le, uint16(5))
	ph := func(typ uint32, o, size uint64) {
		binary.Write(&b, le, typ)
		binary.Write(&b, le, uint32(4))
		binary.Write(&b, le, o)
		binary.Write(&b, le, o)
		binary.Write(&b, le, o)
		binary.Write(&b, le, size)
		binary.Write(&b, le, size)
		binary.Write(&b, le, uint64(8))
	}
	if interp != "" {
		ph(3, interpOff, uint64(len(interpB))) // PT_INTERP
	}
	ph(2, dynOff, uint64(dyn.Len())) // PT_DYNAMIC
	if interp != "" {
		b.Write(interpB)
	}
	b.Write(dynstr.Bytes())
	for uint64(b.Len()) < dynOff {
		b.WriteByte(0)
	}
	b.Write(dyn.Bytes())
	b.Write(data.Bytes())
	b.Write(shstr)
	for uint64(b.Len()) < shOff {
		b.WriteByte(0)
	}
	sh := func(nm, typ uint32, o, size uint64, link uint32, entsize uint64) {
		binary.Write(&b, le, nm)
		binary.Write(&b, le, typ)
		binary.Write(&b, le, uint64(2))
		binary.Write(&b, le, o)
		binary.Write(&b, le, o)
		binary.Write(&b, le, size)
		binary.Write(&b, le, link)
		binary.Write(&b, le, uint32(0))
		binary.Write(&b, le, uint64(1))
		binary.Write(&b, le, entsize)
	}
	b.Write(make([]byte, shsize)) // SHN_UNDEF
	if interp != "" {
		sh(name(".interp"), 1, interpOff, uint64(len(interpB)), 0, 0)
	} else {
		sh(name(".interp"), 0, 0, 0, 0, 0)
	}
	sh(name(".dynstr"), 3, dynstrOff, uint64(dynstr.Len()), 0, 0)
	sh(name(".dynamic"), 6, dynOff, uint64(dyn.Len()), 2, 16)
	sh(name(".data"), 1, dataOff, uint64(data.Len()), 0, 0)
	sh(name(".shstrtab"), 3, shstrOff, uint64(len(shstr)), 0, 0)
	return b.Bytes()
}

// SSHDStrings are what an Alpine 10.0 listener carries.
func SSHDStrings(release string, helpers ...string) []string {
	out := []string{"OpenSSH_" + release[:len(release)-2], "OpenSSH_" + release, "OpenSSH_7.4*", "OpenSSH_2*,OpenSSH_3*,OpenSSH_4*", "/etc/ssh/sshd_config", "Server listening on %s port %s."}
	return append(out, helpers...)
}
