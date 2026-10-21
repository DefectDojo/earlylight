package archive

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// isExecutable recognises ELF, PE and Mach-O (thin and fat) files.
func isExecutable(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch string(b[:4]) {
	case "\x7fELF", "\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe":
		return true
	}
	return b[0] == 'M' && b[1] == 'Z'
}

// isUPX looks for UPX's "UPX!" marker or its UPX0/UPX1 section names in the
// headers. The packed contents are compressed, so nothing inside them could
// have been found.
func isUPX(b []byte) bool {
	h := b[:min(len(b), 4096)]
	return bytes.Contains(h, []byte("UPX!")) || (bytes.Contains(h, []byte("UPX0")) && bytes.Contains(h, []byte("UPX1")))
}

// PyInstaller one-file executables are the bootloader followed by a CArchive:
// the entries, a table of contents, then a cookie. See PyInstaller's
// bootloader/src/pyi_archive.h. Every integer is big-endian.
//
//	cookie: magic[8] len[4] TOC[4] TOClen[4] pyvers[4]                (24 bytes, PyInstaller 2.0)
//	cookie: magic[8] len[4] TOC[4] TOClen[4] pyvers[4] pylibname[64]  (88 bytes, 2.1 to 6.x)
//	entry:  entrylen[4] pos[4] len[4] ulen[4] cflag[1] typcd[1] name[entrylen-18], NUL padded
//
// len is the whole package including the cookie, so the package starts at
// cookie end - len; TOC and entry positions are relative to that start.
const pyiMagic = "MEI\x0c\x0b\x0a\x0b\x0e"

type pyiEntry struct {
	pos, clen, ulen int64
	flag, typ       byte
	name            string
}

type pyiArchive struct {
	start int64
	toc   []pyiEntry
	err   error // the cookie is there but the archive could not be parsed
}

// findPyInstaller searches backwards for the cookie. The bootloader carries
// the magic as a constant too, and signatures or ELF section headers may
// follow the archive, so each occurrence is checked from the end and the
// first whose fields are plausible decides.
func findPyInstaller(b []byte) *pyiArchive {
	end := len(b)
	for {
		i := bytes.LastIndex(b[:end], []byte(pyiMagic))
		if i < 0 {
			return nil
		}
		end = i
		var firstErr error
		for _, size := range []int{88, 24} {
			a, err := parsePyInstaller(b, i, size)
			if a != nil {
				return a
			}
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return &pyiArchive{err: firstErr}
		}
	}
}

// parsePyInstaller returns the archive for a cookie of the given size at i, or
// an error if the cookie looks real but its table of contents does not parse.
// It returns nil, nil when the bytes at i are not a cookie at all.
func parsePyInstaller(b []byte, i, size int) (*pyiArchive, error) {
	if i+size > len(b) {
		return nil, nil
	}
	c := b[i : i+size]
	pkgLen := int64(binary.BigEndian.Uint32(c[8:]))
	tocOff := int64(binary.BigEndian.Uint32(c[12:]))
	tocLen := int64(binary.BigEndian.Uint32(c[16:]))
	pyver := binary.BigEndian.Uint32(c[20:])
	start := int64(i+size) - pkgLen
	if pkgLen < int64(size) || start < 0 || tocOff+tocLen > pkgLen-int64(size) || pyver < 20 || pyver >= 1000 {
		return nil, nil
	}
	if size == 88 {
		lib := c[24:88]
		if j := bytes.IndexByte(lib, 0); j >= 0 {
			lib = lib[:j]
		}
		if !strings.Contains(strings.ToLower(string(lib)), "python") {
			return nil, fmt.Errorf("python library name %q not recognised", lib)
		}
	}
	dataEnd := pkgLen - int64(size)
	toc := b[start+tocOff : start+tocOff+tocLen]
	a := &pyiArchive{start: start}
	for len(toc) > 0 {
		if len(toc) < 18 {
			return nil, errors.New("truncated table of contents")
		}
		n := int64(binary.BigEndian.Uint32(toc))
		if n < 18 || n > int64(len(toc)) {
			return nil, errors.New("bad table of contents entry length")
		}
		e := pyiEntry{
			pos:  int64(binary.BigEndian.Uint32(toc[4:])),
			clen: int64(binary.BigEndian.Uint32(toc[8:])),
			ulen: int64(binary.BigEndian.Uint32(toc[12:])),
			flag: toc[16],
			typ:  toc[17],
		}
		name := toc[18:n]
		if j := bytes.IndexByte(name, 0); j >= 0 {
			name = name[:j]
		}
		e.name = string(name)
		if e.pos+e.clen > dataEnd {
			return nil, fmt.Errorf("entry %q lies outside the archive", e.name)
		}
		a.toc = append(a.toc, e)
		toc = toc[n:]
	}
	if len(a.toc) == 0 {
		return nil, errors.New("empty table of contents")
	}
	return a, nil
}

// maxPyiEntries bounds the table of contents; real one-file apps list a few
// thousand entries at most.
const maxPyiEntries = 100_000

// walkPyInstaller visits each CArchive entry as "app!/<name>": data files
// such as certifi/cacert.pem, shared libraries and the PYZ module archive.
func (w *walker) walkPyInstaller(path string, data []byte, a *pyiArchive, depth int) {
	if a.err != nil {
		w.skip(path, "PyInstaller archive could not be parsed ("+a.err.Error()+"); bundled files not scanned")
		return
	}
	if len(a.toc) > maxPyiEntries {
		w.skip(path, fmt.Sprintf("PyInstaller archive lists %d entries (limit %d); bundled files not scanned", len(a.toc), maxPyiEntries))
		return
	}
	for _, e := range a.toc {
		if e.clen == 0 {
			continue // runtime options and dependency markers carry no data
		}
		member := join(path, e.name)
		raw := data[a.start+e.pos : a.start+e.pos+e.clen]
		// Entries may overlap, so stored ones are charged too: otherwise one
		// region listed many times would be scanned many times for free.
		if e.flag == 0 {
			if int64(len(raw)) > w.budget {
				w.skip(member, w.tooLarge())
				continue
			}
			w.budget -= int64(len(raw))
		}
		switch e.flag {
		case 0:
			w.walk(member, raw, depth+1)
		case 1:
			if e.ulen > w.lim.MaxMemberSize {
				w.skip(member, w.tooLarge())
				continue
			}
			zr, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				w.skip(member, "PyInstaller: "+err.Error())
				continue
			}
			// ulen is untrusted: zlib expands at most about 1032:1, so a larger
			// claim is a lie and must not size the first allocation.
			b, err := w.read(zr, min(e.ulen, e.clen*1032+1024), true)
			if err != nil {
				w.skip(member, w.reason("PyInstaller", err))
				continue
			}
			w.walk(member, b, depth+1)
		default:
			w.skip(member, fmt.Sprintf("PyInstaller entry stored with unsupported compression flag %d; not scanned", e.flag))
		}
	}
}
