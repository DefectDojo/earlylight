// Package archive opens the containers that trust stores hide in, so the
// certificates packed inside them are scanned too: zip-family archives (jar,
// war, ear, whl, apk, zip), tar, cpio and ar archives, gzip, zstd, xz and bzip2
// streams, Debian and RPM packages, and PyInstaller one-file executables.
//
// Members are reported as "outer!/inner", nested as deep as MaxDepth.
// Decompressed content keeps its file's name, so a tarball's members appear as
// "app.tar.zst!/member". Expansion is bounded per member and per top-level
// file while reading, never by trusting a declared size, so a hostile archive
// cannot exhaust memory. Anything not opened, because of a limit or because it
// could not be parsed, is reported as skipped, never silently ignored.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits on expansion.
type Limits struct {
	MaxDepth       int   // nesting levels opened below the file itself
	MaxMemberSize  int64 // largest single decompressed member
	MaxArchiveSize int64 // total decompressed bytes per top-level file
}

// DefaultLimits are generous for real software and small enough for a laptop
// or a CI runner. Peak memory for one file stays near MaxArchiveSize plus one
// member being read.
var DefaultLimits = Limits{MaxDepth: 4, MaxMemberSize: 256 << 20, MaxArchiveSize: 1 << 30}

// Visit receives the file itself and every member found inside it.
type Visit func(path string, data []byte)

// Skip reports something that could not be opened.
type Skip func(path, reason string)

const (
	reasonDepth = "archive nested deeper than the depth limit; members not scanned"
	reasonUPX   = "packed with UPX; unpack with `upx -d` and rescan, contents not checked"
)

// Walk calls visit for data and, if data is an archive, for each member, recursively.
func Walk(path string, data []byte, lim Limits, visit Visit, skip Skip) {
	w := &walker{lim: lim, budget: lim.MaxArchiveSize, visit: visit, skip: skip}
	w.walk(path, data, 0)
}

type walker struct {
	lim    Limits
	budget int64 // decompressed bytes still allowed for this top-level file
	visit  Visit
	skip   Skip
}

type format int

const (
	fNone format = iota
	fZip
	fGzip
	fZstd
	fXz
	fBzip2
	fLzma // only by name or RPM header, it has no reliable magic
	fTar
	fCpio
	fAr
	fRPM
	fPyInstaller
	fUPX
)

func (f format) String() string {
	return [...]string{"", "zip", "gzip", "zstd", "xz", "bzip2", "lzma", "tar", "cpio", "ar", "rpm", "PyInstaller", "UPX"}[f]
}

// sniff identifies data by its magic bytes. For PyInstaller executables it
// also returns the parsed archive, or the reason it could not be parsed.
func sniff(b []byte) (format, *pyiArchive) {
	switch {
	case isZip(b):
		return fZip, nil
	case isGzip(b):
		return fGzip, nil
	case isZstd(b):
		return fZstd, nil
	case isXz(b):
		return fXz, nil
	case isBzip2(b):
		return fBzip2, nil
	case isRPM(b):
		return fRPM, nil
	case isAr(b):
		return fAr, nil
	case isCpio(b):
		return fCpio, nil
	case isTar(b):
		return fTar, nil
	case isExecutable(b):
		if a := findPyInstaller(b); a != nil {
			return fPyInstaller, a
		}
		if isUPX(b) {
			return fUPX, nil
		}
	}
	return fNone, nil
}

func (w *walker) walk(path string, data []byte, depth int) {
	w.visit(path, data)
	f, pyi := sniff(data)
	switch f {
	case fNone:
		return
	case fUPX:
		w.skip(path, reasonUPX)
		return
	}
	if depth >= w.lim.MaxDepth {
		w.skip(path, reasonDepth)
		return
	}
	switch f {
	case fZip:
		w.walkZip(path, data, depth)
	case fGzip, fZstd, fXz, fBzip2:
		w.walkCompressed(path, f, data, depth)
	case fTar:
		w.walkTar(path, "tar", bytes.NewReader(data), depth, true)
	case fCpio:
		w.walkCpio(path, "cpio", bytes.NewReader(data), depth)
	case fAr:
		w.walkAr(path, data, depth)
	case fRPM:
		w.walkRPM(path, data, depth)
	case fPyInstaller:
		w.walkPyInstaller(path, data, pyi, depth)
	}
}

func isZip(b []byte) bool {
	return bytes.HasPrefix(b, []byte("PK\x03\x04")) || bytes.HasPrefix(b, []byte("PK\x05\x06"))
}
func isGzip(b []byte) bool { return len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b }
func isTar(b []byte) bool {
	return len(b) >= 512 && (bytes.Equal(b[257:262], []byte("ustar")))
}
func isZstd(b []byte) bool { return bytes.HasPrefix(b, []byte{0x28, 0xb5, 0x2f, 0xfd}) }
func isXz(b []byte) bool   { return bytes.HasPrefix(b, xzMagic) }

// isBzip2 wants the stream header and then a block or end-of-stream marker, so
// a text file that happens to start with "BZh5" is not taken for one.
func isBzip2(b []byte) bool {
	if len(b) < 10 || !bytes.HasPrefix(b, []byte("BZh")) || b[3] < '1' || b[3] > '9' {
		return false
	}
	m := b[4:10]
	return bytes.Equal(m, []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}) || bytes.Equal(m, []byte{0x17, 0x72, 0x45, 0x38, 0x50, 0x90})
}
func isRPM(b []byte) bool { return bytes.HasPrefix(b, []byte{0xed, 0xab, 0xee, 0xdb}) }
func isAr(b []byte) bool  { return bytes.HasPrefix(b, []byte("!<arch>\n")) }
func isCpio(b []byte) bool {
	return bytes.HasPrefix(b, []byte("070701")) || bytes.HasPrefix(b, []byte("070702"))
}

var (
	errTooLarge = errors.New("decompressed size exceeds the member size limit")
	errBudget   = errors.New("decompressed content exceeds the per-file limit")
)

// reason turns a read error into a skip reason. label names the format being
// read; errors that already carry a prefix keep theirs.
func (w *walker) reason(label string, err error) string {
	switch {
	case errors.Is(err, errBudget):
		return fmt.Sprintf("total decompressed content exceeds the per-file limit of %d bytes; the rest was not scanned", w.lim.MaxArchiveSize)
	case errors.Is(err, errTooLarge):
		return w.tooLarge()
	}
	msg := err.Error()
	if label == "" || strings.HasPrefix(msg, label+":") {
		return msg
	}
	return label + ": " + msg
}

func (w *walker) tooLarge() string {
	return fmt.Sprintf("member larger than the size limit (%d bytes); not scanned", w.lim.MaxMemberSize)
}

// read reads r to EOF, failing as soon as the content passes the member limit.
// hint is the declared size, used only to size the first allocation, so a
// lying header costs at most one member-sized allocation. Without a hint the
// content is read in chunks and joined once at the end: a bomb that runs past
// the limit holds no more than the limit, never the doubling garbage of a
// growing buffer. When charge is set the bytes count against the per-file
// budget here; streams already wrapped in a counter pass false.
func (w *walker) read(r io.Reader, hint int64, charge bool) ([]byte, error) {
	limit := w.lim.MaxMemberSize
	bounded := errTooLarge
	if charge && w.budget < limit {
		limit, bounded = w.budget, errBudget
	}
	limit = max(limit, 0)
	size := int64(64 << 10)
	if hint >= 0 {
		size = hint + 1 // room to see EOF in the same chunk
	}
	var chunks [][]byte
	var total int64
	for {
		c := make([]byte, min(size, limit+1-total))
		n, err := readChunk(r, c)
		chunks = append(chunks, c[:n])
		total += int64(n)
		if total > limit {
			return nil, bounded
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		size = min(max(size, 64<<10)*2, 16<<20)
	}
	if charge {
		w.budget -= total
	}
	if len(chunks) == 1 {
		c := chunks[0]
		// A short read leaves a large first allocation behind a small slice:
		// copy it so a lying size hint cannot keep that memory alive.
		if int64(cap(c)) > 2*total+(64<<10) {
			return bytes.Clone(c), nil
		}
		return c, nil
	}
	out := make([]byte, 0, total)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out, nil
}

// readChunk fills c from r. It returns io.EOF only for a clean end of r, so
// a truncated stream's io.ErrUnexpectedEOF is still reported.
func readChunk(r io.Reader, c []byte) (int, error) {
	n, idle := 0, 0
	for n < len(c) {
		m, err := r.Read(c[n:])
		n += m
		if err != nil {
			return n, err
		}
		if idle = idle + 1; m > 0 {
			idle = 0
		} else if idle > 100 {
			return n, io.ErrNoProgress
		}
	}
	return n, nil
}

// counter charges every byte that comes out of a decompressor to the budget.
type counter struct {
	r io.Reader
	w *walker
}

func (c *counter) Read(p []byte) (int, error) {
	if c.w.budget <= 0 {
		// Out of budget: fine if the stream is also at its end.
		var one [1]byte
		n, err := c.r.Read(one[:])
		if n == 0 {
			return 0, err
		}
		return 0, errBudget
	}
	if int64(len(p)) > c.w.budget {
		p = p[:c.w.budget]
	}
	n, err := c.r.Read(p)
	c.w.budget -= int64(n)
	return n, err
}

// walkCompressed decompresses data as a stream. A tar or cpio archive inside
// is read member by member, so a large tarball needs memory for its largest
// member, not for the whole tarball.
func (w *walker) walkCompressed(path string, f format, data []byte, depth int) {
	r, done, err := w.decompressor(f, data)
	if err != nil {
		w.skip(path, w.reason(f.String(), err))
		return
	}
	defer done()
	w.walkStream(path, f.String(), r, depth+1)
}

// walkStream handles the content of a decompressed stream, which keeps the
// file's own path.
func (w *walker) walkStream(path, label string, r io.Reader, depth int) {
	br := bufio.NewReaderSize(&counter{r: r, w: w}, 64<<10)
	head, _ := br.Peek(512)
	if depth < w.lim.MaxDepth {
		switch {
		case isTar(head):
			w.walkTar(path, label, br, depth, false)
			return
		case isCpio(head):
			w.walkCpio(path, label, br, depth)
			return
		}
	}
	b, err := w.read(br, -1, false)
	if err != nil {
		w.skip(path, w.reason(label, err))
		return
	}
	w.walk(path, b, depth)
}

func (w *walker) walkZip(path string, data []byte, depth int) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		w.skip(path, "zip: "+err.Error())
		return
	}
	w.registerZip(zr)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		member := join(path, f.Name)
		if f.Flags&0x1 != 0 {
			w.skip(member, "encrypted zip member; not scanned")
			continue
		}
		if f.UncompressedSize64 > uint64(w.lim.MaxMemberSize) {
			w.skip(member, fmt.Sprintf("member larger than the size limit (declares %d bytes); not scanned", f.UncompressedSize64))
			continue
		}
		rc, err := f.Open()
		if err != nil {
			w.skip(member, w.reason("zip", err))
			continue
		}
		hint := int64(f.UncompressedSize64)
		if f.Method != zip.Store {
			// Deflate cannot expand more than about 1032:1.
			hint = min(hint, int64(min(f.CompressedSize64, 1<<40))*1032+1024)
		}
		b, err := w.read(rc, hint, true)
		rc.Close()
		if err != nil {
			w.skip(member, w.reason("zip", err))
			continue
		}
		w.walk(member, b, depth+1)
	}
}

// walkTar reads a tar archive from r, which is either an in-memory file or a
// decompressed stream (already charged to the budget). An in-memory tar is
// charged per member, because sparse entries expand beyond the file's own size.
func (w *walker) walkTar(path, label string, r io.Reader, depth int, charge bool) {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			w.skip(path, w.reason(label, err)+"; remaining members not scanned")
			return
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA { //nolint:staticcheck // old archives use TypeRegA
			continue
		}
		member := join(path, h.Name)
		if h.Size > w.lim.MaxMemberSize {
			w.skip(member, w.tooLarge())
			continue
		}
		b, err := w.read(tr, h.Size, charge)
		if err != nil {
			w.skip(member, w.reason(label, err))
			continue
		}
		w.walk(member, b, depth+1)
	}
}

// join builds a member path. The member name is chosen by whoever built the
// archive, so characters that could forge a line or a different-looking path
// in a report are escaped. "..", a leading "/" and the like are kept as they
// are: the "!/" in front already shows the path is inside the archive.
func join(path, name string) string {
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	return path + "!/" + sanitize(name)
}

// sanitize escapes invalid UTF-8, control characters (NUL, newline, escape),
// invisible format characters (bidi overrides, zero-width marks) and line
// separators, Go style (\x00, ‮). Everything else is kept.
func sanitize(name string) string {
	clean := true
	for _, r := range name {
		if unsafeRune(r) {
			clean = false
			break
		}
	}
	if clean {
		return name
	}
	var sb strings.Builder
	for i := 0; i < len(name); {
		r, n := utf8.DecodeRuneInString(name[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&sb, `\x%02x`, name[i])
		case unsafeRune(r) && r < 0x80:
			fmt.Fprintf(&sb, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&sb, `\u%04x`, r)
		default:
			sb.WriteString(name[i : i+n])
		}
		i += n
	}
	return sb.String()
}

func unsafeRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
		unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r)
}
