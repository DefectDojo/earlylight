package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// walkAr reads a Unix ar archive: Debian packages (debian-binary,
// control.tar.*, data.tar.*) and static libraries. Both the GNU ("name/",
// "//" long-name table, "/123") and BSD ("#1/len") name variants are handled.
// Members are slices of data, so nothing is copied or charged.
func (w *walker) walkAr(path string, data []byte, depth int) {
	p := 8
	var longNames []byte
	for p < len(data) {
		if len(data)-p < 60 {
			if len(bytes.Trim(data[p:], "\n")) == 0 {
				return
			}
			w.skip(path, "ar: truncated member header; remaining members not scanned")
			return
		}
		h := data[p : p+60]
		if h[58] != '`' || h[59] != '\n' {
			w.skip(path, fmt.Sprintf("ar: bad member header at offset %d; remaining members not scanned", p))
			return
		}
		size, err := strconv.ParseInt(strings.TrimRight(string(h[48:58]), " "), 10, 64)
		if err != nil || size < 0 {
			w.skip(path, fmt.Sprintf("ar: bad member size at offset %d; remaining members not scanned", p))
			return
		}
		p += 60
		if size > int64(len(data)-p) {
			w.skip(path, "ar: member extends past the end of the archive; remaining members not scanned")
			return
		}
		body := data[p : p+int(size)]
		p += int(size) + int(size&1) // members are 2-byte aligned
		name := strings.TrimRight(string(h[:16]), " ")
		switch {
		case name == "//":
			longNames = body
			continue
		case name == "/" || name == "/SYM64/" || strings.HasPrefix(name, "__.SYMDEF"):
			continue // symbol tables
		case strings.HasPrefix(name, "#1/"):
			n, err := strconv.Atoi(name[3:])
			if err != nil || n < 0 || n > len(body) {
				w.skip(path, "ar: bad BSD long member name; remaining members not scanned")
				return
			}
			name = strings.TrimRight(string(body[:n]), "\x00")
			body = body[n:]
		case len(name) > 1 && name[0] == '/':
			off, err := strconv.Atoi(name[1:])
			if err != nil || off < 0 || off >= len(longNames) {
				w.skip(path, "ar: bad GNU long member name; remaining members not scanned")
				return
			}
			name = string(longNames[off:])
			if i := strings.IndexByte(name, '\n'); i >= 0 {
				name = name[:i]
			}
			name = strings.TrimSuffix(name, "/")
		default:
			name = strings.TrimSuffix(name, "/")
		}
		member := join(path, name)
		if strings.HasSuffix(name, ".lzma") {
			// Old Debian packages use raw lzma, which has no magic to sniff.
			w.walkLzma(member, body, depth+1)
			continue
		}
		w.walk(member, body, depth+1)
	}
}

func (w *walker) walkLzma(path string, data []byte, depth int) {
	w.visit(path, data)
	if depth >= w.lim.MaxDepth {
		w.skip(path, reasonDepth)
		return
	}
	r, done, err := w.decompressor(fLzma, data)
	if err != nil {
		w.skip(path, w.reason("lzma", err))
		return
	}
	defer done()
	w.walkStream(path, "lzma", r, depth+1)
}

// walkCpio reads a newc ("070701") or newc-with-checksum ("070702") cpio
// archive from r, visiting its regular files at depth+1.
func (w *walker) walkCpio(path, label string, r io.Reader, depth int) {
	fail := func(msg string) { w.skip(path, label+": "+msg+"; remaining members not scanned") }
	var hdr [110]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				fail("archive ends without a trailer")
			} else {
				w.skip(path, w.reason(label, err)+"; remaining members not scanned")
			}
			return
		}
		switch string(hdr[:6]) {
		case "070701", "070702":
		case "07070X":
			fail("stripped cpio (an RPM with files over 4 GB) is not supported")
			return
		default:
			fail("bad cpio header")
			return
		}
		var f [13]uint64
		for i := range f {
			v, err := strconv.ParseUint(string(hdr[6+8*i:14+8*i]), 16, 32)
			if err != nil {
				fail("bad cpio header field")
				return
			}
			f[i] = v
		}
		mode, size, namesize := f[1], int64(f[6]), int64(f[11])
		if namesize == 0 || namesize > 1<<16 {
			fail("bad cpio name length")
			return
		}
		nameBuf := make([]byte, namesize+(4-(110+namesize)%4)%4) // header and name are padded to 4
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			fail("truncated cpio header")
			return
		}
		name := string(nameBuf[:namesize])
		if i := strings.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		if name == "TRAILER!!!" {
			return
		}
		pad := (4 - size%4) % 4
		if mode&0o170000 != 0o100000 || size == 0 {
			if err := discard(r, size+pad); err != nil {
				w.skip(path, w.reason(label, err)+"; remaining members not scanned")
				return
			}
			continue
		}
		member := join(path, name)
		if size > w.lim.MaxMemberSize {
			w.skip(member, w.tooLarge())
			if err := discard(r, size+pad); err != nil {
				w.skip(path, w.reason(label, err)+"; remaining members not scanned")
				return
			}
			continue
		}
		b, err := w.read(io.LimitReader(r, size), size, false)
		if err == nil && int64(len(b)) < size {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			w.skip(member, w.reason(label, err))
			w.skip(path, label+": stopped reading; remaining members not scanned")
			return
		}
		if err := discard(r, pad); err != nil {
			w.skip(path, w.reason(label, err)+"; remaining members not scanned")
			return
		}
		w.walk(member, b, depth+1)
	}
}

func discard(r io.Reader, n int64) error {
	if n == 0 {
		return nil
	}
	m, err := io.CopyN(io.Discard, r, n)
	if m == n {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// RPM header tags used here.
const (
	rpmTagPayloadFormat     = 1124
	rpmTagPayloadCompressor = 1125
)

type rpmHeader struct {
	index []byte // 16-byte entries: tag, type, offset, count
	store []byte
}

// parseRPMHeader parses a header structure (magic, nindex, hsize, index,
// store) at the start of b and returns its total length.
func parseRPMHeader(b []byte) (rpmHeader, int, error) {
	if len(b) < 16 {
		return rpmHeader{}, 0, errors.New("truncated")
	}
	if !bytes.Equal(b[:4], []byte{0x8e, 0xad, 0xe8, 0x01}) {
		return rpmHeader{}, 0, errors.New("bad header magic")
	}
	nindex := int64(binary.BigEndian.Uint32(b[8:]))
	hsize := int64(binary.BigEndian.Uint32(b[12:]))
	if nindex > 1<<16 || hsize > 1<<28 {
		return rpmHeader{}, 0, errors.New("implausible header size")
	}
	total := 16 + 16*nindex + hsize
	if total > int64(len(b)) {
		return rpmHeader{}, 0, errors.New("header extends past the end of the file")
	}
	return rpmHeader{index: b[16 : 16+16*nindex], store: b[16+16*nindex : total]}, int(total), nil
}

// str returns a STRING tag's value, or "" if absent.
func (h rpmHeader) str(tag uint32) string {
	for i := 0; i+16 <= len(h.index); i += 16 {
		e := h.index[i : i+16]
		if binary.BigEndian.Uint32(e) != tag || binary.BigEndian.Uint32(e[4:]) != 6 {
			continue
		}
		off := binary.BigEndian.Uint32(e[8:])
		if uint64(off) >= uint64(len(h.store)) {
			return ""
		}
		s := h.store[off:]
		if j := bytes.IndexByte(s, 0); j >= 0 {
			s = s[:j]
		}
		return string(s)
	}
	return ""
}

// walkRPM reads an RPM package: the 96-byte lead, the signature header
// (padded to 8 bytes), the main header, then the payload, a compressed cpio
// archive whose members are visited as "pkg.rpm!/usr/...". Anything that
// cannot be parsed is reported; the package is never passed off as scanned.
func (w *walker) walkRPM(path string, data []byte, depth int) {
	fail := func(msg string) { w.skip(path, "rpm: "+msg+"; package contents not scanned") }
	if len(data) < 96 {
		fail("truncated lead")
		return
	}
	_, n, err := parseRPMHeader(data[96:])
	if err != nil {
		fail("signature header: " + err.Error())
		return
	}
	off := (96 + n + 7) &^ 7
	if off > len(data) {
		fail("signature header: truncated")
		return
	}
	hdr, n, err := parseRPMHeader(data[off:])
	if err != nil {
		fail("main header: " + err.Error())
		return
	}
	payload := data[off+n:]
	if pf := hdr.str(rpmTagPayloadFormat); pf != "" && pf != "cpio" {
		fail(fmt.Sprintf("payload format %q is not supported", pf))
		return
	}
	var f format
	switch {
	case isGzip(payload):
		f = fGzip
	case isZstd(payload):
		f = fZstd
	case isXz(payload):
		f = fXz
	case isBzip2(payload):
		f = fBzip2
	case isCpio(payload):
		w.walkCpio(path, "rpm payload", bytes.NewReader(payload), depth)
		return
	case hdr.str(rpmTagPayloadCompressor) == "lzma":
		f = fLzma
	default:
		fail(fmt.Sprintf("payload compression not recognised (header says %q)", hdr.str(rpmTagPayloadCompressor)))
		return
	}
	r, done, err := w.decompressor(f, payload)
	if err != nil {
		fail("payload: " + w.reason(f.String(), err))
		return
	}
	defer done()
	br := &counter{r: r, w: w}
	var head [6]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		fail("payload: " + w.reason(f.String(), err))
		return
	}
	if !isCpio(head[:]) {
		if string(head[:]) == "07070X" {
			fail("payload is stripped cpio (files over 4 GB), which is not supported")
		} else {
			fail("payload is not a newc cpio archive")
		}
		return
	}
	w.walkCpio(path, "rpm payload", io.MultiReader(bytes.NewReader(head[:]), br), depth)
}
