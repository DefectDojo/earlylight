package pkgdb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// rpm header tags and types used here (rpm/rpmtag.h).
const (
	tagHeaderImage      = 61
	tagHeaderSignatures = 62
	tagHeaderImmutable  = 63
	tagHeaderRegions    = 64
	tagName             = 1000
	tagVersion          = 1001
	tagRelease          = 1002
	tagEpoch            = 1003
	tagVendor           = 1011
	tagArch             = 1022
	tagOldFilenames     = 1027
	tagFileStates       = 1029
	tagFileDigests      = 1035
	tagFileFlags        = 1037
	tagSourceRPM        = 1044
	tagDirIndexes       = 1116
	tagBasenames        = 1117
	tagDirnames         = 1118
	tagFileDigestAlgo   = 5011

	typeNull        = 0
	typeChar        = 1
	typeInt8        = 2
	typeInt16       = 3
	typeInt32       = 4
	typeInt64       = 5
	typeString      = 6
	typeBin         = 7
	typeStringArray = 8
	typeI18NString  = 9

	rpmFileGhost = 1 << 6 // RPMFILE_GHOST

	// rpm's own limits (lib/header_internal.h): at most 0xffff tags and 256 MiB
	// of data per header.
	maxHeaderTags = 0xffff
	maxHeaderData = 0x0fffffff
)

type hdrEntry struct {
	typ   uint32
	count uint32
	data  []byte // exactly the entry's bytes
}

type rpmHeader map[uint32]hdrEntry

// parseHeaderBlob parses an rpm header blob as stored in the package
// database (no lead, no magic): int32 index count, int32 data length, the
// index entries (tag, type, offset, count; big-endian) and the data store.
// Every entry is bounds-checked; a later entry for a tag replaces an earlier
// one (rpm's "dribble" entries override the immutable region).
func parseHeaderBlob(blob []byte) (rpmHeader, error) {
	if len(blob) < 8 {
		return nil, errors.New("header blob shorter than 8 bytes")
	}
	il := binary.BigEndian.Uint32(blob[0:4])
	dl := binary.BigEndian.Uint32(blob[4:8])
	if il == 0 || il > maxHeaderTags {
		return nil, fmt.Errorf("header has %d tags", il)
	}
	if dl > maxHeaderData {
		return nil, fmt.Errorf("header data length %d exceeds rpm's limit", dl)
	}
	need := 8 + uint64(il)*16 + uint64(dl)
	if uint64(len(blob)) != need {
		return nil, fmt.Errorf("header blob is %d bytes, its index says %d", len(blob), need)
	}
	index := blob[8 : 8+il*16]
	store := blob[8+il*16:]
	h := rpmHeader{}
	for i := uint32(0); i < il; i++ {
		e := index[i*16 : i*16+16]
		tag := binary.BigEndian.Uint32(e[0:4])
		typ := binary.BigEndian.Uint32(e[4:8])
		off := binary.BigEndian.Uint32(e[8:12])
		cnt := binary.BigEndian.Uint32(e[12:16])
		switch tag {
		case tagHeaderImage, tagHeaderSignatures, tagHeaderImmutable, tagHeaderRegions:
			continue // region markers; their trailers live in the store
		}
		if typ == typeNull {
			continue
		}
		if typ > typeI18NString {
			return nil, fmt.Errorf("tag %d has unknown type %d", tag, typ)
		}
		if cnt == 0 {
			return nil, fmt.Errorf("tag %d has count 0", tag)
		}
		if off >= dl {
			return nil, fmt.Errorf("tag %d offset %d outside data of %d bytes", tag, off, dl)
		}
		n, err := entryLen(store[off:], typ, cnt)
		if err != nil {
			return nil, fmt.Errorf("tag %d: %w", tag, err)
		}
		h[tag] = hdrEntry{typ: typ, count: cnt, data: store[off : off+n]}
	}
	return h, nil
}

// entryLen returns the byte length of an entry starting at b.
func entryLen(b []byte, typ, cnt uint32) (uint32, error) {
	var size uint64
	switch typ {
	case typeChar, typeInt8, typeBin:
		size = 1
	case typeInt16:
		size = 2
	case typeInt32:
		size = 4
	case typeInt64:
		size = 8
	case typeString:
		if cnt != 1 {
			return 0, errors.New("string with count != 1")
		}
		fallthrough
	case typeStringArray, typeI18NString:
		var n uint32
		for k := uint32(0); k < cnt; k++ {
			i := bytes.IndexByte(b[n:], 0)
			if i < 0 {
				return 0, errors.New("unterminated string")
			}
			n += uint32(i) + 1
		}
		return n, nil
	}
	if size*uint64(cnt) > uint64(len(b)) {
		return 0, errors.New("data runs past the end of the header")
	}
	return uint32(size * uint64(cnt)), nil
}

func (h rpmHeader) str(tag uint32) (string, bool, error) {
	e, ok := h[tag]
	if !ok {
		return "", false, nil
	}
	if e.typ != typeString && e.typ != typeI18NString && e.typ != typeStringArray {
		return "", true, fmt.Errorf("tag %d is type %d, not a string", tag, e.typ)
	}
	i := bytes.IndexByte(e.data, 0)
	return string(e.data[:i]), true, nil
}

func (h rpmHeader) strings(tag uint32) ([]string, bool, error) {
	e, ok := h[tag]
	if !ok {
		return nil, false, nil
	}
	if e.typ != typeStringArray && e.typ != typeI18NString && !(e.typ == typeString && e.count == 1) {
		return nil, true, fmt.Errorf("tag %d is type %d, not a string array", tag, e.typ)
	}
	out := make([]string, 0, e.count)
	d := e.data
	for k := uint32(0); k < e.count; k++ {
		i := bytes.IndexByte(d, 0)
		out = append(out, string(d[:i]))
		d = d[i+1:]
	}
	return out, true, nil
}

func (h rpmHeader) int32s(tag uint32) ([]uint32, bool, error) {
	e, ok := h[tag]
	if !ok {
		return nil, false, nil
	}
	if e.typ != typeInt32 {
		return nil, true, fmt.Errorf("tag %d is type %d, not int32", tag, e.typ)
	}
	out := make([]uint32, e.count)
	for k := range out {
		out[k] = binary.BigEndian.Uint32(e.data[4*k:])
	}
	return out, true, nil
}

func (h rpmHeader) bytesOf(tag uint32) ([]byte, bool, error) {
	e, ok := h[tag]
	if !ok {
		return nil, false, nil
	}
	if e.typ != typeChar && e.typ != typeInt8 && e.typ != typeBin {
		return nil, true, fmt.Errorf("tag %d is type %d, not char/int8", tag, e.typ)
	}
	return e.data, true, nil
}

// rpm digest algorithm numbers (PGPHASHALGO_*).
var rpmDigestAlgos = map[uint32]string{1: "md5", 2: "sha1", 3: "ripemd160", 5: "md2", 6: "tiger192", 7: "haval-5-160", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}

var rpmDigestLen = map[string]int{"md5": 16, "sha1": 20, "ripemd160": 20, "md2": 16, "tiger192": 24, "haval-5-160": 20, "sha256": 32, "sha384": 48, "sha512": 64, "sha224": 28}

// rpm file states (RPMFILE_STATE_*): only "normal" and "netshared" files are
// this package's content on disk.
const (
	fileStateNormal    = 0
	fileStateNetShared = 3
)

// headerPackage turns a header into an installed package. warn collects
// non-fatal issues (digests unusable); err means the header is unusable.
func headerPackage(h rpmHeader, db string) (inst Installed, warn []string, err error) {
	get := func(tag uint32, required bool) string {
		if err != nil {
			return ""
		}
		s, ok, e := h.str(tag)
		if e != nil {
			err = e
		} else if !ok && required {
			err = fmt.Errorf("no tag %d", tag)
		}
		return s
	}
	name := get(tagName, true)
	ver := get(tagVersion, true)
	rel := get(tagRelease, true)
	arch := get(tagArch, false)
	vendor := get(tagVendor, false)
	srpm := get(tagSourceRPM, false)
	if err != nil {
		return inst, nil, err
	}
	evr := ver + "-" + rel
	if ep, ok, e := h.int32s(tagEpoch); e != nil {
		return inst, nil, e
	} else if ok && ep[0] != 0 {
		evr = strconv.FormatUint(uint64(ep[0]), 10) + ":" + evr
	}
	src := sourceName(srpm)
	if src == "" {
		src = name
	}
	inst.Package = Package{Format: RPM, Name: name, Version: evr, Source: src, Vendor: vendor, Arch: arch, DB: db}

	paths, err := headerPaths(h)
	if err != nil {
		return inst, nil, fmt.Errorf("%s-%s: file list: %w", name, evr, err)
	}
	digests, _, e := h.strings(tagFileDigests)
	if e != nil || (digests != nil && len(digests) != len(paths)) {
		warn = append(warn, fmt.Sprintf("%s-%s: file digests unreadable (%d for %d files)", name, evr, len(digests), len(paths)))
		digests = nil
	}
	algo := "md5" // rpm's default when the header has no FILEDIGESTALGO
	if a, ok, e := h.int32s(tagFileDigestAlgo); e != nil {
		warn = append(warn, fmt.Sprintf("%s-%s: %v", name, evr, e))
		digests = nil
	} else if ok {
		if algo, ok = rpmDigestAlgos[a[0]]; !ok {
			warn = append(warn, fmt.Sprintf("%s-%s: unknown file digest algorithm %d", name, evr, a[0]))
			digests = nil
		}
	}
	states, _, e := h.bytesOf(tagFileStates)
	if e != nil || (states != nil && len(states) != len(paths)) {
		states = nil
	}
	flags, _, e := h.int32s(tagFileFlags)
	if e != nil || (flags != nil && len(flags) != len(paths)) {
		flags = nil
	}
	bad := 0
	inst.Files = make([]File, len(paths))
	for i, p := range paths {
		f := File{Path: clean(p)}
		onDisk := true
		if states != nil && states[i] != fileStateNormal && states[i] != fileStateNetShared {
			onDisk = false // replaced, not installed (nodocs), wrong color
		}
		if flags != nil && flags[i]&rpmFileGhost != 0 {
			onDisk = false
		}
		if digests != nil && digests[i] != "" && onDisk {
			d, e := hex.DecodeString(digests[i])
			if e != nil || len(d) != rpmDigestLen[algo] {
				bad++
			} else {
				f.Algo, f.Digest = algo, d
			}
		}
		inst.Files[i] = f
	}
	if bad > 0 {
		warn = append(warn, fmt.Sprintf("%s-%s: %d malformed file digests", name, evr, bad))
	}
	return inst, warn, nil
}

func headerPaths(h rpmHeader) ([]string, error) {
	base, okB, err := h.strings(tagBasenames)
	if err != nil {
		return nil, err
	}
	if !okB {
		old, ok, err := h.strings(tagOldFilenames)
		if err != nil || !ok {
			return nil, err // no files at all is fine
		}
		return old, nil
	}
	dirs, _, err := h.strings(tagDirnames)
	if err != nil {
		return nil, err
	}
	idx, _, err := h.int32s(tagDirIndexes)
	if err != nil {
		return nil, err
	}
	if len(idx) != len(base) {
		return nil, fmt.Errorf("%d basenames but %d dir indexes", len(base), len(idx))
	}
	out := make([]string, len(base))
	for i, b := range base {
		if int64(idx[i]) >= int64(len(dirs)) {
			return nil, fmt.Errorf("dir index %d out of range", idx[i])
		}
		out[i] = dirs[idx[i]] + b
	}
	return out, nil
}

// sourceName returns the source package name of a SOURCERPM value:
// "php-pecl-apcu-5.1.23-1.el9.src.rpm" -> "php-pecl-apcu".
func sourceName(srpm string) string {
	s := strings.TrimSuffix(srpm, ".rpm")
	if s == srpm {
		return ""
	}
	if i := strings.LastIndexByte(s, '.'); i >= 0 && (s[i+1:] == "src" || s[i+1:] == "nosrc") {
		s = s[:i]
	} else {
		return ""
	}
	for k := 0; k < 2; k++ {
		i := strings.LastIndexByte(s, '-')
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}
