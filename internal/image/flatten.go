package image

// Flattening follows go-containerregistry's mutate.Extract (Apache-2.0,
// see THIRD_PARTY_NOTICES.txt), changed to agree with what a container
// runtime extracts (docker export is the ground truth):
//
//   - Every entry name is made relative to the root first, so
//     "/usr/sbin/sshd" and "usr/sbin/sshd" in two layers are one file, and a
//     whiteout spelled one way hides a file spelled the other.
//   - A symbolic link is kept whatever its target: one with more "../" than
//     its depth resolves at the root, and dropping it would resurrect the
//     lower layer's file at its path.
//   - A file, link or other non-directory a layer puts where an upper layer
//     has a directory removed the lower layers' directory there (directory,
//     file, directory over three layers): their entries under it are hidden.
//   - A hard link keeps the content of the file it named when that file is
//     hidden by an upper layer (RUN ln /a /b; RUN rm /a): the layer is read
//     again for it.
//
// What the layers do not settle cheaply (two entries for one path in one
// layer, a hard link to a file not in its layer, a write or whiteout
// through a directory that is a symbolic link) is listed as unresolved:
// the scan treats those paths as not read. A file an upper layer wrote
// through a lower layer's link is the exception when nothing else claims
// the path it landed on: the container has that file, so it stays read
// under the name it was written with (throughLinks).

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	whiteoutPrefix = ".wh."
	opaqueWhiteout = ".wh..wh..opq"
)

// flatten returns an image's filesystem as one tar stream, top layer first:
// the first entry for a path is the file, and each path appears once. The
// function returns the paths left unresolved, once the stream has ended.
func flatten(img v1.Image) (io.ReadCloser, func() []string) {
	pr, pw := io.Pipe()
	f := &flattener{fileMap: map[string]bool{}, opaqueDirs: map[string]bool{}, written: map[string]int{},
		tombs: map[string]bool{}, links: map[string]flatLink{}, unresolved: map[string]bool{}}
	done := make(chan struct{})
	var out []string
	go func() {
		defer close(done)
		err := f.extract(img, pw)
		for p := range f.unresolved {
			out = append(out, "/"+p)
		}
		sort.Strings(out)
		pw.CloseWithError(err)
	}()
	return pr, func() []string {
		// The reader stops at the tar trailer: take the rest, so the
		// writer can finish, and wait for it.
		io.Copy(io.Discard, pr)
		<-done
		return out
	}
}

type flattener struct {
	tw         *tar.Writer
	fileMap    map[string]bool // path -> hides what is below it (non-directory or whiteout)
	opaqueDirs map[string]bool
	cur        int                 // the layer being read (0 is the lowest)
	written    map[string]int      // non-directories written, and whiteouts: path -> layer
	tombs      map[string]bool     // of those, the whiteouts
	links      map[string]flatLink // symbolic links written
	unresolved map[string]bool
}

// flatLink is a symbolic link written to the stream: its target and layer.
type flatLink struct {
	to    string
	layer int
}

func (f *flattener) extract(img v1.Image, w io.Writer) error {
	f.tw = tar.NewWriter(w)
	defer f.tw.Close()
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("retrieving image layers: %w", err)
	}
	for i := len(layers) - 1; i >= 0; i-- {
		f.cur = i
		if err := f.layer(layers[i]); err != nil {
			return err
		}
	}
	f.throughLinks()
	return nil
}

// rootName is an entry name relative to the root, "" for the root itself.
// A backslash stays: it is an ordinary character in a file name, and a
// file named "usr\lib" is not the directory usr/lib.
func rootName(name string) string {
	return strings.TrimPrefix(path.Clean("/"+name), "/")
}

func (f *flattener) layer(layer v1.Layer) error {
	layerOpaque := map[string]bool{}
	inLayer := map[string]bool{}     // names this layer has (value: a directory)
	hidden := map[string]bool{}      // regular files of this layer not written
	here := map[string]bool{}        // regular files of this layer written
	pending := map[string][]string{} // hidden file -> hard links to fill from it
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
		if h.Typeflag == tar.TypeLink {
			h.Linkname = rootName(h.Linkname) // tar hard links name a path from the root
		}
		h.Format = tar.FormatPAX
		base, dir := path.Base(h.Name), path.Dir(h.Name)
		if dir == "." {
			dir = ""
		}
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
		isDir := h.Typeflag == tar.TypeDir && !tombstone
		if prev, ok := inLayer[name]; ok && !(prev && isDir) {
			// Two entries for one path in one layer: the runtime keeps the
			// last, this stream the first.
			f.unresolved[name] = true
		}
		inLayer[name] = isDir
		regular := h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA //nolint:staticcheck
		if hides, ok := f.fileMap[name]; ok && !tombstone {
			if !hides && !isDir {
				// An upper layer has a directory where this layer has a
				// file: this layer removed the lower directory there.
				layerOpaque[name] = true
			}
			if regular {
				hidden[name] = true
			}
			continue
		}
		if inWhiteoutDir(f.fileMap, name) || inOpaqueDir(f.opaqueDirs, name) {
			if regular {
				hidden[name] = true
			}
			continue
		}
		f.fileMap[name] = tombstone || !isDir
		if tombstone {
			f.written[name], f.tombs[name] = f.cur, true
			continue
		}
		if h.Typeflag == tar.TypeLink {
			switch {
			case hidden[h.Linkname]:
				// It names a file an upper layer hides: it keeps that file's
				// content, written once the layer is read again.
				pending[h.Linkname] = append(pending[h.Linkname], name)
				f.written[name] = f.cur
				continue
			case !here[h.Linkname]:
				f.unresolved[name] = true // not a file of its own layer
			}
		}
		if err := f.tw.WriteHeader(h); err != nil {
			return err
		}
		if h.Size > 0 {
			if _, err := io.CopyN(f.tw, tr, h.Size); err != nil {
				return err
			}
		}
		if regular {
			here[name] = true
		}
		if !isDir {
			f.written[name] = f.cur
		}
		if h.Typeflag == tar.TypeSymlink {
			f.links[name] = flatLink{h.Linkname, f.cur}
		}
	}
	for d := range layerOpaque {
		f.opaqueDirs[d] = true
	}
	// Drain the layer so its digest is verified.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return fmt.Errorf("verifying layer: %w", err)
	}
	if len(pending) > 0 {
		return f.fillLinks(layer, pending)
	}
	return nil
}

// fillLinks writes each hard link to a hidden file as a copy of that file,
// read from the layer again.
func (f *flattener) fillLinks(layer v1.Layer, pending map[string][]string) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("reading layer contents: %w", err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for len(pending) > 0 {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		name := rootName(h.Name)
		links, ok := pending[name]
		if !ok || h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA { //nolint:staticcheck
			continue
		}
		delete(pending, name)
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return err
		}
		for _, l := range links {
			hh := *h
			hh.Name, hh.Typeflag, hh.Linkname, hh.Format = l, tar.TypeReg, "", tar.FormatPAX
			if err := f.tw.WriteHeader(&hh); err != nil {
				return err
			}
			if _, err := f.tw.Write(b); err != nil {
				return err
			}
		}
	}
	for _, links := range pending {
		for _, l := range links {
			f.unresolved[l] = true // the file it names was not found
		}
	}
	return nil
}

// throughLinks finds the entries an upper layer wrote, or whited out,
// under a directory that is a symbolic link in the final filesystem: the
// runtime wrote through the link, to the path it names.
//
// The path it names is unresolved: a lower layer's file there was replaced
// or removed, and the stream names the new one elsewhere. The entry itself
// is unresolved too. Two cases are certain, and keep what was read:
//
//   - The entry is the file: a file (not a whiteout) written by a layer
//     above the link's, landing on a path that no link leads on from, that
//     no other such write lands on, and that no layer at or above the
//     write's names directly. It stays read under the name it was written
//     with; dropping it would lose what an image built with paths written
//     as they are (lib/libx.so under a lib -> usr/lib link) holds.
//   - A layer above every such write names the path itself: that entry is
//     the file, and only the writes through the link are unresolved.
func (f *flattener) throughLinks() {
	if len(f.links) == 0 {
		return
	}
	type write struct {
		name  string
		layer int
		sure  bool // above the link's layer, and not a whiteout
	}
	lands := map[string][]write{}
	for name, layer := range f.written {
		for a := path.Dir(name); a != "." && a != "/" && a != ""; a = path.Dir(a) {
			l, ok := f.links[a]
			if !ok {
				continue
			}
			to := l.to
			if !path.IsAbs(to) {
				to = path.Join(path.Dir(a), to)
			}
			at := ""
			if r := rootName(to); r != "" {
				at = path.Join(r, strings.TrimPrefix(name, a+"/"))
			}
			lands[at] = append(lands[at], write{name, layer, l.layer < layer && !f.tombs[name]})
			break
		}
	}
	for at, ws := range lands {
		// through: the one write through a link is the file. direct: a
		// layer above every such write named the path itself afterwards,
		// and that entry is the file.
		through, direct := false, false
		if at != "" && !f.linked(at) {
			top := -1
			for _, w := range ws {
				top = max(top, w.layer)
			}
			d, ok := f.written[at]
			through = len(ws) == 1 && ws[0].sure && (!ok || d < top)
			direct = ok && d > top
		}
		if at != "" && !direct {
			f.unresolved[at] = true
		}
		if !through {
			for _, w := range ws {
				f.unresolved[w.name] = true
			}
		}
	}
}

// linked reports whether name, or a directory above it, is a symbolic
// link in the stream.
func (f *flattener) linked(name string) bool {
	for a := name; a != "." && a != "/" && a != ""; a = path.Dir(a) {
		if _, ok := f.links[a]; ok {
			return true
		}
	}
	return false
}

func inOpaqueDir(opaqueDirs map[string]bool, file string) bool {
	for file != "" && file != "." {
		dir := path.Dir(file)
		if dir == "." {
			dir = ""
		}
		if opaqueDirs[dir] {
			return true
		}
		if file == dir {
			break
		}
		file = dir
	}
	return false
}

func inWhiteoutDir(fileMap map[string]bool, file string) bool {
	for file != "" {
		dir := path.Dir(file)
		if file == dir || dir == "." {
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

func cleanArchivePath(name string) string {
	return path.Clean(strings.ReplaceAll(name, "\\", "/"))
}

func hasWindowsDrivePrefix(name string) bool {
	return len(name) >= 2 && ('A' <= name[0] && name[0] <= 'Z' || 'a' <= name[0] && name[0] <= 'z') && name[1] == ':'
}
