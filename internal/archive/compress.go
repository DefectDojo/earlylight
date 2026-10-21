package archive

import (
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

var xzMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// windowCap bounds the history a decoder may allocate (zstd window, xz and
// lzma dictionary). xz -9 uses 64 MiB, so that is always allowed; otherwise it
// is the member limit, since no back-reference can reach further than the
// largest content kept.
func (w *walker) windowCap() int64 {
	return min(max(w.lim.MaxMemberSize, 64<<20), 1<<31-1)
}

func (w *walker) zstdOptions() []zstd.DOption {
	c := uint64(w.windowCap())
	return []zstd.DOption{
		zstd.WithDecoderConcurrency(1), // no goroutines, no per-core buffers
		zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(c),
		zstd.WithDecoderMaxMemory(c),
	}
}

// decompressor opens a decompressing stream over data. done releases it.
func (w *walker) decompressor(f format, data []byte) (io.Reader, func(), error) {
	src := bytes.NewReader(data)
	switch f {
	case fGzip:
		zr, err := gzip.NewReader(src)
		if err != nil {
			return nil, nil, err
		}
		zr.Multistream(true)
		return zr, func() { zr.Close() }, nil
	case fZstd:
		d, err := zstd.NewReader(src, w.zstdOptions()...)
		if err != nil {
			return nil, nil, err
		}
		return d, d.Close, nil
	case fXz:
		// The xz decoder allocates each block's declared dictionary up front,
		// so check every block header before handing it the stream.
		if err := xzCheckDicts(data, w.windowCap()); err != nil {
			return nil, nil, err
		}
		xr, err := xz.NewReader(src)
		if err != nil {
			return nil, nil, err
		}
		return xr, func() {}, nil
	case fBzip2:
		return bzip2.NewReader(src), func() {}, nil
	case fLzma:
		lr, err := lzma.ReaderConfig{DictCap: int(w.windowCap())}.NewReader(src)
		if err != nil {
			return nil, nil, err
		}
		return lr, func() {}, nil
	}
	return nil, nil, fmt.Errorf("no decompressor for %s", f)
}

// registerZip adds the zip compression methods the standard library lacks
// but real archives use: bzip2 (12) and zstd (93).
func (w *walker) registerZip(zr *zip.Reader) {
	zr.RegisterDecompressor(12, func(r io.Reader) io.ReadCloser { return io.NopCloser(bzip2.NewReader(r)) })
	opts := w.zstdOptions()
	zr.RegisterDecompressor(93, func(r io.Reader) io.ReadCloser {
		d, err := zstd.NewReader(r, opts...)
		if err != nil {
			return io.NopCloser(errReader{err})
		}
		return d.IOReadCloser()
	})
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

var errXzLayout = errors.New("xz: stream layout not recognised (truncated or corrupt file)")

// xzCheckDicts finds every block of an .xz file through each stream's index,
// reading streams from the end of the file, and rejects any LZMA2 dictionary
// larger than maxDict.
func xzCheckDicts(b []byte, maxDict int64) error {
	end := len(b)
	for end > 0 {
		// Stream padding is a multiple of four zero bytes.
		for end >= 4 && b[end-1] == 0 && b[end-2] == 0 && b[end-3] == 0 && b[end-4] == 0 {
			end -= 4
		}
		if end == 0 {
			return nil
		}
		if end < 32 {
			return errXzLayout
		}
		foot := b[end-12 : end]
		if foot[10] != 'Y' || foot[11] != 'Z' {
			return errXzLayout
		}
		backward := (int64(binary.LittleEndian.Uint32(foot[4:8])) + 1) * 4
		idxStart := int64(end-12) - backward
		if idxStart < 12 {
			return errXzLayout
		}
		idx := b[idxStart : end-12]
		if idx[0] != 0 {
			return errXzLayout
		}
		p := 1
		n, k := binary.Uvarint(idx[p:])
		if k <= 0 || n > uint64(len(idx)) {
			return errXzLayout
		}
		p += k
		sizes := make([]int64, 0, n)
		unpadded := make([]int64, 0, n)
		var blocks int64
		for i := uint64(0); i < n; i++ {
			unpaddedSize, k := binary.Uvarint(idx[p:])
			if k <= 0 || unpaddedSize > uint64(len(b)) {
				return errXzLayout
			}
			p += k
			if _, k = binary.Uvarint(idx[p:]); k <= 0 {
				return errXzLayout
			}
			p += k
			u := (int64(unpaddedSize) + 3) &^ 3
			sizes = append(sizes, u)
			unpadded = append(unpadded, int64(unpaddedSize))
			blocks += u
			if blocks > int64(len(b)) {
				return errXzLayout
			}
		}
		start := idxStart - blocks - 12
		if start < 0 || !bytes.HasPrefix(b[start:], xzMagic) {
			return errXzLayout
		}
		// The decoder reads blocks front to back and only checks the index after
		// the last one, so the index alone cannot say where it will read the next
		// block header. Each block before the last must declare its compressed
		// size, and that size must agree with the index: then the decoder's next
		// header is exactly the one checked here.
		checkLen := xzCheckSize(b[start+7] & 0x0f)
		if checkLen < 0 {
			return errXzLayout
		}
		pos := start + 12
		for i, u := range sizes {
			hdr, comp, err := xzBlockHeader(b[pos:idxStart], maxDict)
			if err != nil {
				return err
			}
			if i < len(sizes)-1 {
				if comp < 0 {
					return fmt.Errorf("xz: multi-block stream whose block %d does not declare its size; not decompressed", i+1)
				}
				if int64(hdr)+comp+int64(checkLen) != unpadded[i] {
					return errXzLayout
				}
			}
			pos += u
		}
		end = int(start)
	}
	return nil
}

// xzCheckSize is the length of a block's integrity check for the stream flags'
// check type: none, CRC32, CRC64 or SHA-256 (-1 for an unknown type).
func xzCheckSize(t byte) int {
	switch t {
	case 0x00:
		return 0
	case 0x01:
		return 4
	case 0x04:
		return 8
	case 0x0a:
		return 32
	}
	return -1
}

func xzCheckBlock(b []byte, maxDict int64) error {
	_, _, err := xzBlockHeader(b, maxDict)
	return err
}

// xzBlockHeader checks one block header's dictionary sizes and returns the
// header length and the compressed size the header declares (-1 if absent).
func xzBlockHeader(b []byte, maxDict int64) (hdr int, compressed int64, err error) {
	compressed = -1
	if len(b) < 2 || b[0] == 0 {
		return 0, 0, errXzLayout
	}
	size := (int(b[0]) + 1) * 4
	if size > len(b) {
		return 0, 0, errXzLayout
	}
	h := b[1:size]
	flags := h[0]
	p := 1
	for _, bit := range []byte{0x40, 0x80} { // compressed and uncompressed sizes
		if flags&bit != 0 {
			v, k := binary.Uvarint(h[p:])
			if k <= 0 {
				return 0, 0, errXzLayout
			}
			if bit == 0x40 {
				if v > uint64(len(b)) {
					return 0, 0, errXzLayout
				}
				compressed = int64(v)
			}
			p += k
		}
	}
	for range int(flags&3) + 1 {
		id, k := binary.Uvarint(h[p:])
		if k <= 0 {
			return 0, 0, errXzLayout
		}
		p += k
		psize, k := binary.Uvarint(h[p:])
		if k <= 0 || psize > uint64(len(h)-p-k) {
			return 0, 0, errXzLayout
		}
		p += k
		props := h[p : p+int(psize)]
		p += int(psize)
		if id != 0x21 { // LZMA2; the other filters (BCJ, delta) need no dictionary
			continue
		}
		if len(props) != 1 || props[0] > 40 {
			return 0, 0, errXzLayout
		}
		dict := int64(1<<32 - 1)
		if bits := props[0]; bits < 40 {
			dict = int64(2|bits&1) << (bits/2 + 11)
		}
		if dict > maxDict {
			return 0, 0, fmt.Errorf("xz: dictionary of %d bytes exceeds the %d byte limit; not decompressed", dict, maxDict)
		}
	}
	return size, compressed, nil
}
