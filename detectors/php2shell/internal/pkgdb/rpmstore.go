package pkgdb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// rpmBlob is one package header read from a database, keyed by the
// database's package index (hnum / instance number).
type rpmBlob struct {
	key  uint32
	data []byte
	err  error // this record could not be read; the others may still be fine
}

// ---- Berkeley DB hash (rpm < 4.16 "Packages") ----

const (
	bdbHashMagic    = 0x061561
	bdbPageHashMeta = 8
	bdbPageHashUns  = 2  // P_HASH_UNSORTED
	bdbPageHash     = 13 // P_HASH
	bdbPageOverflow = 7
	bdbItemKeyData  = 1 // H_KEYDATA
	bdbItemOffPage  = 3 // H_OFFPAGE
	bdbPageHeader   = 26
	maxBDBRecord    = maxHeaderData + 8 + maxHeaderTags*16
)

// readBDB reads every record of a Berkeley DB hash database held in memory,
// by walking each hash bucket's page chain as Berkeley DB does
// (BUCKET_TO_PAGE with the spares table), following overflow chains for large
// records. It handles both byte orders. A structural error in the metadata or
// a bucket chain makes the database unreadable (error); a bad record is
// returned with its own err. warn is set when the record count in the hash
// metadata (nelem, which includes rpm's record 0) differs from the records
// found, a sign of an inconsistent database.
func readBDB(db []byte) (blobs []rpmBlob, warn string, err error) {
	blobs, nelem, total, err := readBDBRecords(db)
	if err == nil && nelem != total {
		warn = fmt.Sprintf("hash metadata counts %d records but the buckets hold %d", nelem, total)
	}
	return blobs, warn, err
}

func readBDBRecords(db []byte) (out []rpmBlob, nelem, total uint32, err error) {
	if len(db) < 512 {
		return nil, 0, 0, errors.New("file shorter than a Berkeley DB metadata page")
	}
	var bo binary.ByteOrder = binary.LittleEndian
	switch {
	case binary.LittleEndian.Uint32(db[12:]) == bdbHashMagic:
	case binary.BigEndian.Uint32(db[12:]) == bdbHashMagic:
		bo = binary.BigEndian
	default:
		return nil, 0, 0, errors.New("not a Berkeley DB hash database (bad magic)")
	}
	if db[25] != bdbPageHashMeta {
		return nil, 0, 0, fmt.Errorf("metadata page has type %d, not hash metadata", db[25])
	}
	if db[24] != 0 {
		return nil, 0, 0, errors.New("encrypted Berkeley DB")
	}
	psize := bo.Uint32(db[20:])
	if psize < 512 || psize > 65536 || psize&(psize-1) != 0 {
		return nil, 0, 0, fmt.Errorf("bad page size %d", psize)
	}
	lastPg := bo.Uint32(db[32:])
	if uint64(lastPg+1)*uint64(psize) > uint64(len(db)) {
		return nil, 0, 0, fmt.Errorf("database truncated: last page %d of %d bytes needs %d bytes, file has %d", lastPg, psize, uint64(lastPg+1)*uint64(psize), len(db))
	}
	maxBucket := bo.Uint32(db[72:])
	if maxBucket > lastPg {
		return nil, 0, 0, fmt.Errorf("max bucket %d beyond last page %d", maxBucket, lastPg)
	}
	var spares [32]uint32
	for i := range spares {
		spares[i] = bo.Uint32(db[96+4*i:])
	}
	page := func(n uint32) ([]byte, error) {
		if n == 0 || n > lastPg {
			return nil, fmt.Errorf("page %d out of range", n)
		}
		return db[uint64(n)*uint64(psize) : uint64(n+1)*uint64(psize)], nil
	}
	log2 := func(n uint32) uint32 {
		var i uint32
		for limit := uint64(1); limit < uint64(n); limit <<= 1 {
			i++
		}
		return i
	}
	visited := map[uint32]bool{}
	nelem = bo.Uint32(db[88:])
	for b := uint32(0); b <= maxBucket; b++ {
		l := log2(b + 1)
		if l >= 32 {
			return nil, 0, 0, fmt.Errorf("bucket %d out of range", b)
		}
		pg := uint64(b) + uint64(spares[l])
		for pg != 0 {
			if pg > uint64(lastPg) {
				return nil, 0, 0, fmt.Errorf("bucket %d: page %d out of range", b, pg)
			}
			n := uint32(pg)
			if visited[n] {
				return nil, 0, 0, fmt.Errorf("bucket %d: page %d reached twice (loop or shared chain)", b, n)
			}
			visited[n] = true
			p, err := page(n)
			if err != nil {
				return nil, 0, 0, err
			}
			if t := p[25]; t != bdbPageHash && t != bdbPageHashUns {
				return nil, 0, 0, fmt.Errorf("bucket %d: page %d has type %d, not a hash page", b, n, t)
			}
			recs, nrec, err := bdbHashPage(p, psize, bo, page, visited)
			if err != nil {
				return nil, 0, 0, fmt.Errorf("page %d: %w", n, err)
			}
			out = append(out, recs...)
			total += nrec
			pg = uint64(bo.Uint32(p[16:]))
		}
	}
	return out, nelem, total, nil
}

func bdbHashPage(p []byte, psize uint32, bo binary.ByteOrder, page func(uint32) ([]byte, error), visited map[uint32]bool) ([]rpmBlob, uint32, error) {
	n := uint32(bo.Uint16(p[20:]))
	if n%2 != 0 {
		return nil, 0, fmt.Errorf("odd number of items (%d)", n)
	}
	if bdbPageHeader+2*n > psize {
		return nil, 0, fmt.Errorf("%d items do not fit the page", n)
	}
	item := func(i uint32) ([]byte, error) {
		off := uint32(bo.Uint16(p[bdbPageHeader+2*i:]))
		end := psize
		if i > 0 {
			end = uint32(bo.Uint16(p[bdbPageHeader+2*(i-1):]))
		}
		if off < bdbPageHeader+2*n || off >= end || end > psize {
			return nil, fmt.Errorf("item %d at bad offset %d", i, off)
		}
		return p[off:end], nil
	}
	var out []rpmBlob
	for i := uint32(0); i < n; i += 2 {
		k, err := item(i)
		if err != nil {
			return nil, 0, err
		}
		v, err := item(i + 1)
		if err != nil {
			return nil, 0, err
		}
		if k[0] != bdbItemKeyData || len(k) != 5 {
			return nil, 0, fmt.Errorf("item %d: unexpected key (type %d, %d bytes)", i, k[0], len(k))
		}
		key := bo.Uint32(k[1:])
		r := rpmBlob{key: key}
		switch v[0] {
		case bdbItemKeyData:
			r.data = v[1:]
		case bdbItemOffPage:
			if len(v) < 12 {
				return nil, 0, fmt.Errorf("item %d: short off-page reference", i+1)
			}
			r.data, r.err = bdbOverflow(bo.Uint32(v[4:]), bo.Uint32(v[8:]), bo, page, visited)
		default:
			r.err = fmt.Errorf("record %d: unsupported item type %d", key, v[0])
		}
		if key == 0 {
			continue // record 0 holds rpm's next instance number, not a header
		}
		out = append(out, r)
	}
	return out, n / 2, nil
}

func bdbOverflow(pg, total uint32, bo binary.ByteOrder, page func(uint32) ([]byte, error), visited map[uint32]bool) ([]byte, error) {
	if total > maxBDBRecord {
		return nil, fmt.Errorf("record of %d bytes exceeds rpm's header limit", total)
	}
	buf := make([]byte, 0, total)
	for pg != 0 {
		if visited[pg] {
			return nil, fmt.Errorf("overflow page %d reached twice", pg)
		}
		visited[pg] = true
		p, err := page(pg)
		if err != nil {
			return nil, err
		}
		if p[25] != bdbPageOverflow {
			return nil, fmt.Errorf("overflow chain reaches page %d of type %d", pg, p[25])
		}
		used := uint32(bo.Uint16(p[22:]))
		if bdbPageHeader+used > uint32(len(p)) || uint32(len(buf))+used > total {
			return nil, fmt.Errorf("overflow page %d: %d bytes used do not fit", pg, used)
		}
		buf = append(buf, p[bdbPageHeader:bdbPageHeader+used]...)
		pg = bo.Uint32(p[16:])
	}
	if uint32(len(buf)) != total {
		return nil, fmt.Errorf("overflow chain holds %d bytes, record is %d", len(buf), total)
	}
	return buf, nil
}

// ---- NDB (SUSE "Packages.db", rpm lib/backend/ndb/rpmpkg.c) ----

const (
	ndbMagic     = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	ndbSlotMagic = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbBlobHead  = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24
	ndbBlobTail  = 'B' | 'l'<<8 | 'b'<<16 | 'E'<<24
	ndbPage      = 4096
	ndbBlk       = 16
)

func adler32(a uint32, b []byte) uint32 {
	s1, s2 := a&0xffff, (a>>16)&0xffff
	for len(b) > 0 {
		n := len(b)
		if n > 5552 {
			n = 5552
		}
		for _, c := range b[:n] {
			s1 += uint32(c)
			s2 += s1
		}
		s1 %= 65521
		s2 %= 65521
		b = b[n:]
	}
	return s2<<16 | s1
}

// readNDB reads every package blob of an rpm ndb database held in memory,
// with the checks rpm's rpmpkgReadSlots and rpmpkgVerifyblob make (slot
// magic, ranges, blob head and tail, length, adler32).
func readNDB(db []byte) ([]rpmBlob, error) {
	le := binary.LittleEndian
	if len(db) < 32 || le.Uint32(db) != ndbMagic {
		return nil, errors.New("not an rpm ndb database (bad magic)")
	}
	if v := le.Uint32(db[4:]); v != 0 {
		return nil, fmt.Errorf("unsupported ndb version %d", v)
	}
	if len(db)%ndbBlk != 0 {
		return nil, fmt.Errorf("size %d is not a multiple of %d", len(db), ndbBlk)
	}
	npages := le.Uint32(db[12:])
	if npages == 0 || uint64(npages)*ndbPage > uint64(len(db)) {
		return nil, fmt.Errorf("%d slot pages do not fit a %d-byte file", npages, len(db))
	}
	fileBlks := uint64(len(db) / ndbBlk)
	minBlk := uint64(npages) * (ndbPage / ndbBlk)
	seen := map[uint32]bool{}
	var out []rpmBlob
	for o := uint64(32); o < uint64(npages)*ndbPage; o += 16 {
		s := db[o : o+16]
		if le.Uint32(s) != ndbSlotMagic {
			return nil, fmt.Errorf("slot at offset %d has a bad magic", o)
		}
		idx, off, cnt := le.Uint32(s[4:]), uint64(le.Uint32(s[8:])), uint64(le.Uint32(s[12:]))
		if off == 0 {
			continue // free slot
		}
		if off+cnt > fileBlks {
			return nil, fmt.Errorf("slot for package %d points past the end of the file (truncated database)", idx)
		}
		if idx == 0 || cnt == 0 || off < minBlk {
			return nil, fmt.Errorf("bad slot at offset %d", o)
		}
		if seen[idx] {
			return nil, fmt.Errorf("package index %d in two slots", idx)
		}
		seen[idx] = true
		out = append(out, ndbBlob(db[off*ndbBlk:(off+cnt)*ndbBlk], idx))
	}
	return out, nil
}

func ndbBlob(b []byte, idx uint32) rpmBlob {
	le := binary.LittleEndian
	r := rpmBlob{key: idx}
	if len(b) < 16+12 {
		r.err = fmt.Errorf("package %d: blob too small", idx)
		return r
	}
	if le.Uint32(b) != ndbBlobHead || le.Uint32(b[4:]) != idx {
		r.err = fmt.Errorf("package %d: bad blob header", idx)
		return r
	}
	bl := uint64(le.Uint32(b[12:]))
	if uint64(len(b)/ndbBlk) != (16+bl+12+ndbBlk-1)/ndbBlk {
		r.err = fmt.Errorf("package %d: blob length %d does not match its %d blocks", idx, bl, len(b)/ndbBlk)
		return r
	}
	tail := b[len(b)-12:]
	if le.Uint32(tail[8:]) != ndbBlobTail || uint64(le.Uint32(tail[4:])) != bl {
		r.err = fmt.Errorf("package %d: bad blob trailer", idx)
		return r
	}
	if sum := adler32(adler32(1, b[:16]), b[16:len(b)-12]); sum != le.Uint32(tail) {
		r.err = fmt.Errorf("package %d: checksum mismatch (corrupt blob)", idx)
		return r
	}
	r.data = b[16 : 16+bl]
	return r
}
