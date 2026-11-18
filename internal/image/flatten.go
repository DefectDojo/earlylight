package image

// Flattening follows go-containerregistry's mutate.Extract (Apache-2.0,
// see THIRD_PARTY_NOTICES.txt), with one change: every entry name is made
// relative to the root first, so "/usr/sbin/sshd" and "usr/sbin/sshd" in
// two layers are one file, as a container runtime extracts them. Without
// it, both are written, the lower layer's copy after the upper one, and a
// whiteout spelled one way does not hide a file spelled the other.

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	whiteoutPrefix = ".wh."
	opaqueWhiteout = ".wh..wh..opq"
)

// flatten returns an image's filesystem as one tar stream, top layer first:
// the first entry for a path is the file, and each path appears once.
func flatten(img v1.Image) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(extract(img, pw)) }()
	return pr
}

func extract(img v1.Image, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	fileMap := map[string]bool{}
	opaqueDirs := map[string]bool{}
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("retrieving image layers: %w", err)
	}
	for i := len(layers) - 1; i >= 0; i-- {
		if err := extractLayer(tw, fileMap, opaqueDirs, layers[i]); err != nil {
			return err
		}
	}
	return nil
}

// rootName is an entry name relative to the root, "" for the root itself.
func rootName(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

func extractLayer(tw *tar.Writer, fileMap, opaqueDirs map[string]bool, layer v1.Layer) error {
	layerOpaque := map[string]bool{}
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("reading layer contents: %w", err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		if unsafeArchivePath(h.Name) {
			return fmt.Errorf("unsafe tar path %q", h.Name)
		}
		h.Name = rootName(h.Name)
		if h.Name == "" {
			continue // the root directory
		}
		if (h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink) && unsafeRelativeLink(h.Name, h.Linkname) {
			continue
		}
		h.Format = tar.FormatPAX
		base, dir := path.Base(h.Name), path.Dir(h.Name)
		if base == opaqueWhiteout {
			layerOpaque[dir] = true
			continue
		}
		tombstone := strings.HasPrefix(base, whiteoutPrefix)
		if tombstone {
			base = base[len(whiteoutPrefix):]
		}
		name := h.Name
		if h.Typeflag != tar.TypeDir {
			name = path.Join(dir, base)
		}
		if _, ok := fileMap[name]; ok && !tombstone {
			continue
		}
		if inWhiteoutDir(fileMap, name) || inOpaqueDir(opaqueDirs, name) {
			continue
		}
		fileMap[name] = tombstone || h.Typeflag != tar.TypeDir
		if tombstone {
			continue
		}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if h.Size > 0 {
			if _, err := io.CopyN(tw, tr, h.Size); err != nil {
				return err
			}
		}
	}
	for d := range layerOpaque {
		opaqueDirs[d] = true
	}
	// Drain the layer so its digest is verified.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("verifying layer: %w", err)
	}
	return nil
}

func inOpaqueDir(opaqueDirs map[string]bool, file string) bool {
	for file != "" {
		dir := path.Dir(file)
		if file == dir {
			break
		}
		if opaqueDirs[dir] {
			return true
		}
		file = dir
	}
	return false
}

func inWhiteoutDir(fileMap map[string]bool, file string) bool {
	for file != "" {
		dir := path.Dir(file)
		if file == dir {
			break
		}
		if fileMap[dir] {
			return true
		}
		file = dir
	}
	return false
}

func unsafeArchivePath(name string) bool {
	clean := cleanArchivePath(name)
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(name, "\\") {
		return true
	}
	return hasWindowsDrivePrefix(clean)
}

func unsafeRelativeLink(name, linkname string) bool {
	clean := cleanArchivePath(linkname)
	if path.IsAbs(clean) {
		return false
	}
	if hasWindowsDrivePrefix(clean) {
		return true
	}
	return strings.HasPrefix(path.Clean(path.Join(path.Dir(name), clean)), "..")
}

func cleanArchivePath(name string) string {
	return path.Clean(strings.ReplaceAll(name, "\\", "/"))
}

func hasWindowsDrivePrefix(name string) bool {
	return len(name) >= 2 && ('A' <= name[0] && name[0] <= 'Z' || 'a' <= name[0] && name[0] <= 'z') && name[1] == ':'
}
