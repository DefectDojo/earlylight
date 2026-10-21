// Package source feeds files to the scanner from a directory tree or a container
// image's flattened filesystem, and records every file it could not read so a
// scan never claims coverage it did not have.
//
// Only two kinds of file are read in full: executables (ELF, Mach-O, PE), which
// may be PHP runtimes, and the package-database files the caller asks for.
// Everything else is identified from its first bytes and passed over.
package source

import (
	"archive/tar"
	"bytes"
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
}

// Options control what is read.
type Options struct {
	// MaxFileSize: executables larger than this are skipped and recorded.
	MaxFileSize int64
	// Exclude lists absolute path prefixes inside the root to skip entirely.
	Exclude []string
	// Wanted selects non-executable files to read in full (package databases).
	Wanted func(abs string) bool
	// IsExecutable decides from a file's first bytes whether to read it.
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
// runs. Scan the images themselves with `php2shell-scan image`.
var ContainerStorage = []string{"/var/lib/docker/", "/var/lib/containerd/", "/var/lib/containers/", "/var/snap/docker/common/var-lib-docker/"}

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

// upx reports a UPX-packed executable: its code and strings are compressed, so a
// PHP runtime inside could not be recognised.
func upx(head []byte) bool {
	return bytes.Contains(head, []byte("UPX!")) || (bytes.Contains(head, []byte("UPX0")) && bytes.Contains(head, []byte("UPX1")))
}

// Dir walks root without following symlinks. Paths passed to visit are absolute
// within root ("/usr/bin/php" for root "/" and for an extracted image at "./rootfs").
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
			skips = append(skips, Skip{Path: abs, Reason: werr.Error()})
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
			skips = append(skips, Skip{Path: abs, Reason: err.Error()})
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
			return "container storage (image layers); scan images with `php2shell-scan image`"
		}
	}
	return "pseudo-filesystem"
}

func readOne(osPath, abs string, fi fs.FileInfo, opts Options, visit Visitor, skips *[]Skip) error {
	f, err := os.Open(osPath)
	if err != nil {
		*skips = append(*skips, Skip{Path: abs, Reason: err.Error()})
		return nil
	}
	defer f.Close()
	head := make([]byte, headSize)
	k, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		*skips = append(*skips, Skip{Path: abs, Reason: err.Error()})
		return nil
	}
	head = head[:k]
	exe := opts.IsExecutable != nil && opts.IsExecutable(head)
	if !exe && (opts.Wanted == nil || !opts.Wanted(abs)) {
		return nil
	}
	if exe && upx(head) {
		*skips = append(*skips, Skip{Path: abs, Reason: "UPX-packed executable: its contents are compressed and cannot be checked"})
		return nil
	}
	if opts.MaxFileSize > 0 && fi.Size() > opts.MaxFileSize {
		*skips = append(*skips, Skip{Path: abs, Reason: fmt.Sprintf("larger than --max-file-size (%d bytes)", fi.Size())})
		return nil
	}
	// Enforce the limit while reading: some files (FUSE mounts) report size 0
	// and are much larger, or endless.
	var r io.Reader = f
	if opts.MaxFileSize > 0 {
		r = io.LimitReader(f, opts.MaxFileSize+1-int64(k))
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		*skips = append(*skips, Skip{Path: abs, Reason: err.Error()})
		return nil
	}
	data := append(head, rest...)
	if opts.MaxFileSize > 0 && int64(len(data)) > opts.MaxFileSize {
		*skips = append(*skips, Skip{Path: abs, Reason: fmt.Sprintf("larger than --max-file-size (%d bytes) while reading", opts.MaxFileSize)})
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
		n++
		head := make([]byte, headSize)
		k, err := io.ReadFull(tr, head)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return skips, n, fmt.Errorf("reading %s: %w", abs, err)
		}
		head = head[:k]
		exe := opts.IsExecutable != nil && opts.IsExecutable(head)
		if !exe && (opts.Wanted == nil || !opts.Wanted(abs)) {
			continue
		}
		if exe && upx(head) {
			skips = append(skips, Skip{Path: abs, Reason: "UPX-packed executable: its contents are compressed and cannot be checked"})
			continue
		}
		if opts.MaxFileSize > 0 && h.Size > opts.MaxFileSize {
			skips = append(skips, Skip{Path: abs, Reason: fmt.Sprintf("larger than --max-file-size (%d bytes)", h.Size)})
			continue
		}
		var rr io.Reader = tr
		if opts.MaxFileSize > 0 {
			rr = io.LimitReader(tr, opts.MaxFileSize+1-int64(k))
		}
		rest, err := io.ReadAll(rr)
		if err != nil {
			return skips, n, fmt.Errorf("reading %s: %w", abs, err)
		}
		data := append(head, rest...)
		if opts.MaxFileSize > 0 && int64(len(data)) > opts.MaxFileSize {
			skips = append(skips, Skip{Path: abs, Reason: fmt.Sprintf("larger than --max-file-size (%d bytes) while reading", opts.MaxFileSize)})
			continue
		}
		if err := visit(File{Path: abs, Data: data, Executable: exe}); err != nil {
			return skips, n, err
		}
	}
}
