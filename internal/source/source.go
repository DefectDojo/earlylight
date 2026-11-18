// Package source feeds files to the engine from a directory tree or a container
// image's flattened filesystem, and records every file it could not read so a
// scan never claims coverage it did not have.
//
// Every regular file is read in full unless Options.Read narrows it down. The
// decision is made from the path and the file's first bytes, so detectors that
// only care about executables or a few named files never pay for the rest,
// and a file larger than its readers' own limit is never read past those
// first bytes.
package source

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// File is one regular file's absolute path (within the scanned root) and content.
type File struct {
	Path string
	Data []byte
	// Executable is true when the file starts like an ELF, Mach-O or PE file.
	Executable bool
}

// Skip records a file or directory that was not scanned, and why.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	// Excluded is true for deliberate exclusions (pseudo-filesystems, container
	// storage), which do not make a scan incomplete.
	Excluded bool `json:"excluded,omitempty"`
	// DetectorFailed is true when a detector crashed on the file. It is
	// always a coverage gap.
	DetectorFailed bool `json:"detector_failed,omitempty"`
}

// Options control what is read.
type Options struct {
	// MaxFileSize: files larger than this are skipped and recorded.
	MaxFileSize int64
	// Exclude lists absolute path prefixes inside the root to skip entirely.
	Exclude []string
	// Uncounted (Tar) lists path prefixes whose files are still read but not
	// counted as scanned: an image's /proc, /sys and /dev, which some
	// detectors skip and others read.
	Uncounted []string
	// Read decides from a file's path, first bytes and executable flag whether
	// to read it in full, and the readers' own limit on it: what they look
	// for is never larger (0 or less: MaxFileSize). A file over a limit
	// below MaxFileSize is not read past its first bytes. Nil reads every
	// file.
	Read func(abs string, head []byte, executable bool) (read bool, limit int64)
	// Over records a file Read chose that is over the limit Read set (own)
	// or over MaxFileSize, with its size (-1 when it was found larger while
	// reading). A file over its own limit is recorded with what Over returns
	// (a deliberate exclusion when Over is nil); one over MaxFileSize is
	// always recorded as such, and Over adds what it returns.
	Over func(abs string, size int64, own bool) []Skip
	// Unread receives each file the walk met and could not read (it could
	// not be opened or read, or changed while it was read), and each
	// directory whose contents could not be listed (dir), besides the
	// record of it.
	Unread func(abs string, dir bool)
	// IsExecutable decides from a file's first bytes whether it is an executable.
	IsExecutable func(head []byte) bool
	// Symlink receives every symbolic link (absolute path, target as written).
	Symlink func(abs, target string)
	// Hardlink receives every tar hard link (absolute path, absolute path of the
	// file it names, which appeared earlier in the stream).
	Hardlink func(abs, target string)
}

// DefaultExcludes are pseudo-filesystems, applied when scanning a system root.
// Pseudo-filesystems mounted anywhere else are also detected by type (pseudoFS).
var DefaultExcludes = []string{"/proc/", "/sys/", "/dev/"}

// ContainerStorage holds container image layers. Lower layers keep files that the
// running image replaced, so scanning them as a filesystem reports copies nothing
// uses. Scan the images themselves instead.
var ContainerStorage = []string{"/var/lib/docker/", "/var/lib/containerd/", "/var/lib/containers/", "/var/snap/docker/common/var-lib-docker/"}

// bound is the most read of a file: the readers' own limit when it is
// below MaxFileSize, and whether that limit is the one that applies.
func (o Options) bound(limit int64) (int64, bool) {
	if limit > 0 && (o.MaxFileSize <= 0 || limit < o.MaxFileSize) {
		return limit, true
	}
	return o.MaxFileSize, false
}

// unread records a file or directory the walk met and could not read, and
// tells Unread.
func (o Options) unread(abs, reason string, dir bool) Skip {
	if o.Unread != nil {
		o.Unread(abs, dir)
	}
	return Skip{Path: abs, Reason: reason}
}

// tooLarge records a file over the limit that applies to it; size is -1
// when it was found larger while reading.
func (o Options) tooLarge(abs string, size, most int64, own bool) []Skip {
	var told []Skip
	switch {
	case own && o.Over != nil:
		return o.Over(abs, size, true)
	case o.Over != nil:
		told = o.Over(abs, size, false)
	}
	switch {
	case own && size < 0:
		return []Skip{{Path: abs, Reason: fmt.Sprintf("excluded: larger than the %d-byte limit set for this file, found while reading", most), Excluded: true}}
	case own:
		return []Skip{{Path: abs, Reason: fmt.Sprintf("excluded: larger than the %d-byte limit set for this file (%d bytes)", most, size), Excluded: true}}
	case size < 0:
		return append([]Skip{{Path: abs, Reason: fmt.Sprintf("larger than --max-file-size (%d bytes) while reading", most)}}, told...)
	}
	return append([]Skip{{Path: abs, Reason: fmt.Sprintf("larger than --max-file-size (%d bytes)", size)}}, told...)
}

// Visitor receives each file read. Returning an error stops the walk.
type Visitor func(File) error

const headSize = 4096

func excluded(p string, ex []string) bool {
	for _, e := range ex {
		if p == strings.TrimSuffix(e, "/") || strings.HasPrefix(p, e) {
			return true
		}
	}
	return false
}

// Dir walks root without following symlinks. Paths passed to visit are absolute
// within root ("/etc/ssl/certs/ca-certificates.crt" for root "/" and for an
// extracted image at "./rootfs"). A single file keeps its real absolute path.
func Dir(root string, opts Options, visit Visitor) ([]Skip, int, error) {
	var skips []Skip
	n := 0
	root = filepath.Clean(root)
	// A symlinked root ("/etc" on macOS, merged-usr "/lib") is walked at its target.
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, 0, err
	}
	if !info.IsDir() {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, 0, err
		}
		n++
		return skips, n, readOne(root, filepath.ToSlash(abs), info, opts, visit, &skips)
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		rel, _ := filepath.Rel(root, p)
		abs := path.Clean("/" + filepath.ToSlash(rel))
		if werr != nil {
			skips = append(skips, opts.unread(abs, werr.Error(), d == nil || d.IsDir()))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if excluded(abs, opts.Exclude) {
			if d.IsDir() {
				skips = append(skips, Skip{Path: abs, Reason: "excluded: " + excludeReason(abs), Excluded: true})
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() && p != root && pseudoFS(p) {
			skips = append(skips, Skip{Path: abs, Reason: "excluded: pseudo-filesystem", Excluded: true})
			return fs.SkipDir
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if opts.Symlink != nil {
				if t, err := os.Readlink(p); err == nil {
					opts.Symlink(abs, filepath.ToSlash(t))
				}
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			skips = append(skips, opts.unread(abs, err.Error(), false))
			return nil
		}
		n++
		return readOne(p, abs, fi, opts, visit, &skips)
	})
	return skips, n, err
}

func excludeReason(p string) string {
	for _, e := range ContainerStorage {
		if strings.HasPrefix(p+"/", e) {
			return "container storage (image layers); scan the images themselves"
		}
	}
	return "pseudo-filesystem"
}

func readOne(osPath, abs string, fi fs.FileInfo, opts Options, visit Visitor, skips *[]Skip) error {
	// The file can be swapped between the walk and the open (a live system,
	// a shared /tmp). Never follow a symlink, never block on a FIFO, and read
	// only the regular file the walk saw.
	f, err := os.OpenFile(osPath, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		*skips = append(*skips, opts.unread(abs, err.Error(), false))
		return nil
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || !os.SameFile(st, fi) {
		*skips = append(*skips, opts.unread(abs, "changed while it was being scanned (no longer the same regular file); not read", false))
		return nil
	}
	head := make([]byte, headSize)
	k, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		*skips = append(*skips, opts.unread(abs, err.Error(), false))
		return nil
	}
	head = head[:k]
	exe := opts.IsExecutable != nil && opts.IsExecutable(head)
	var lim int64
	if opts.Read != nil {
		var read bool
		if read, lim = opts.Read(abs, head, exe); !read {
			return nil
		}
	}
	most, own := opts.bound(lim)
	if most > 0 && fi.Size() > most {
		*skips = append(*skips, opts.tooLarge(abs, fi.Size(), most, own)...)
		return nil
	}
	// Enforce the limit while reading: some files (FUSE mounts) report size 0
	// and are much larger, or endless.
	var r io.Reader = f
	if most > 0 {
		r = io.LimitReader(f, most+1-int64(k))
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		*skips = append(*skips, opts.unread(abs, err.Error(), false))
		return nil
	}
	data := append(head, rest...)
	if most > 0 && int64(len(data)) > most {
		*skips = append(*skips, opts.tooLarge(abs, -1, most, own)...)
		return nil
	}
	return visit(File{Path: abs, Data: data, Executable: exe})
}

// Tar reads a flattened filesystem tar stream (an image's final filesystem, or a
// `docker export`). Whiteouts must already be applied by the caller. Hard links
// name a file that appears earlier in the stream, so they are not read again.
func Tar(r io.Reader, opts Options, visit Visitor) ([]Skip, int, error) {
	var skips []Skip
	n := 0
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return skips, n, nil
		}
		if err != nil {
			return skips, n, fmt.Errorf("reading image filesystem: %w", err)
		}
		abs := path.Clean("/" + h.Name)
		if excluded(abs, opts.Exclude) {
			continue
		}
		switch h.Typeflag {
		case tar.TypeSymlink:
			if opts.Symlink != nil {
				opts.Symlink(abs, h.Linkname)
			}
			continue
		case tar.TypeLink:
			if opts.Hardlink != nil {
				opts.Hardlink(abs, path.Clean("/"+h.Linkname))
			}
			continue
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA appears in old images
		default:
			continue
		}
		if !excluded(abs, opts.Uncounted) {
			n++
		}
		head := make([]byte, headSize)
		k, err := io.ReadFull(tr, head)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return skips, n, fmt.Errorf("reading %s: %w", abs, err)
		}
		head = head[:k]
		exe := opts.IsExecutable != nil && opts.IsExecutable(head)
		var lim int64
		if opts.Read != nil {
			var read bool
			if read, lim = opts.Read(abs, head, exe); !read {
				continue
			}
		}
		most, own := opts.bound(lim)
		if most > 0 && h.Size > most {
			skips = append(skips, opts.tooLarge(abs, h.Size, most, own)...)
			continue
		}
		var rr io.Reader = tr
		if most > 0 {
			rr = io.LimitReader(tr, most+1-int64(k))
		}
		rest, err := io.ReadAll(rr)
		if err != nil {
			return skips, n, fmt.Errorf("reading %s: %w", abs, err)
		}
		data := append(head, rest...)
		if most > 0 && int64(len(data)) > most {
			skips = append(skips, opts.tooLarge(abs, -1, most, own)...)
			continue
		}
		if err := visit(File{Path: abs, Data: data, Executable: exe}); err != nil {
			return skips, n, err
		}
	}
}
