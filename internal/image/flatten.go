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
// A path one layer names twice as a regular file is written twice, the
// second entry marked as the one the runtime keeps (ReplacesRecord).
//
// What the layers do not settle cheaply (two entries of other kinds for one
// path in one layer, a hard link to a file not in its layer, a whiteout
// through a directory that is a symbolic link) is listed as unresolved:
// the scan treats those paths as not read. Files written through a link
// are settled where the layers allow it: the one the runtime applied last
// stays read under the name it was written with (throughLinks).

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
	f := &flattener{fileMap: map[string]bool{}, opaqueDirs: map[string]bool{}, opaqueAt: map[string]int{}, written: map[string]flatWrite{},
		links: map[string]flatLink{}, unresolved: map[string]bool{}}
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
	opaqueAt   map[string]int       // the highest layer with an opaque marker in each directory
	cur        int                  // the layer being read (0 is the lowest)
	seq        int                  // the entry being read, counted through the layer
	written    map[string]flatWrite // non-directories written, and whiteouts
	links      map[string]flatLink  // symbolic links written
	unresolved map[string]bool
}

// flatWrite is where an entry that was written (or a whiteout) comes from:
// its layer and its place in the layer, which is the order the runtime
// applies entries in.
type flatWrite struct {
	layer, seq int
	tomb       bool
}

// later reports whether w is applied after o.
func (w flatWrite) later(o flatWrite) bool {
	return w.layer > o.layer || w.layer == o.layer && w.seq > o.seq
}

// ReplacesRecord marks, in the flattened stream, a second entry for a
// path: one layer named the path twice as a regular file, and the later
// entry is the file the runtime keeps. A reader that takes the first entry
// for a path takes this one instead.
const ReplacesRecord = "EARLYLIGHT.replaces"

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
	inLayer := map[string]bool{} // names this layer has (value: a directory)
	hidden := map[string]bool{}  // regular files of this layer not written
	here := map[string]bool{}    // regular files of this layer written
	plain := map[string]bool{}   // of those, the ones named only as regular files so far
	f.seq = 0
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
		f.seq++
		if base == opaqueWhiteout {
			layerOpaque[dir] = true
			if _, ok := f.opaqueAt[dir]; !ok {
				f.opaqueAt[dir] = f.cur
			}
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
		regular := (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA) && !tombstone //nolint:staticcheck
		if prev, ok := inLayer[name]; ok && !(prev && isDir) {
			if regular && plain[name] {
				// The path again as a regular file: the runtime keeps this
				// entry. It is written too, marked as the one that replaces
				// the first.
				h.PAXRecords = map[string]string{ReplacesRecord: "1"}
				if err := f.tw.WriteHeader(h); err != nil {
					return err
				}
				if h.Size > 0 {
					if _, err := io.CopyN(f.tw, tr, h.Size); err != nil {
						return err
					}
				}
				f.written[name] = flatWrite{layer: f.cur, seq: f.seq}
				continue
			}
			// Two entries of other kinds for one path in one layer: the
			// runtime keeps the last, this stream the first.
			f.unresolved[name] = true
			plain[name] = false
		}
		inLayer[name] = isDir
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
			f.written[name] = flatWrite{layer: f.cur, seq: f.seq, tomb: true}
			continue
		}
		if h.Typeflag == tar.TypeLink {
			switch {
			case hidden[h.Linkname]:
				// It names a file an upper layer hides: it keeps that file's
				// content, written once the layer is read again.
				pending[h.Linkname] = append(pending[h.Linkname], name)
				f.written[name] = flatWrite{layer: f.cur, seq: f.seq}
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
			here[name], plain[name] = true, true
		}
		if !isDir {
			f.written[name] = flatWrite{layer: f.cur, seq: f.seq}
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

// throughLinks finds the entries a layer wrote, or whited out, under a
// directory that is a symbolic link in the final filesystem: the runtime
// wrote through the link, to the path it names.
//
// Each such entry is placed where it landed, by following the links one
// path component at a time as the runtime did (a chain of links, a link to
// the root, ".." in a target). Everything that landed on one path, and the
// entry that names the path itself, is then one file, and the entry the
// runtime applied last is it: a higher layer's, or a later one of the same
// layer. That entry stays read under the name it was written with; the
// others are stale and unresolved. Losing them all would lose what an image
// built with paths written as they are (lib/libx.so under a lib -> usr/lib
// link) holds.
//
// What stays unresolved, every name and the landing path with it:
//
//   - an entry that cannot be placed: a link of its own layer or a higher
//     one on the way (the link may not have been there yet), a loop;
//   - a landing path whose last entry through a link is a whiteout;
//   - a landing path under a directory that a layer above the write
//     removed, replaced or made opaque: the file is gone with it.
//
// The landing path of an entry that stays read is listed too: what the
// stream holds there, if anything, is an older file.
func (f *flattener) throughLinks() {
	if len(f.links) == 0 {
		return
	}
	type member struct {
		name string
		w    flatWrite
	}
	groups := map[string][]member{}
	for name, w := range f.written {
		if !f.underLink(name) {
			continue
		}
		at, ok := f.land(name, w.layer)
		if !ok {
			f.unresolved[name] = true
			if t := f.textual(name); t != "" {
				f.unresolved[t] = true
			}
			continue
		}
		groups[at] = append(groups[at], member{name, w})
	}
	for at, ms := range groups {
		if w, ok := f.written[at]; ok && !f.underLink(at) {
			ms = append(ms, member{at, w})
		}
		win := ms[0]
		for _, m := range ms[1:] {
			if m.w.later(win.w) {
				win = m
			}
		}
		if win.name != at && (win.w.tomb || f.removedAbove(at, win.w.layer)) {
			// Nothing certain is left of what landed here.
			for _, m := range ms {
				f.unresolved[m.name] = true
			}
			f.unresolved[at] = true
			continue
		}
		for _, m := range ms {
			if m.name != win.name {
				f.unresolved[m.name] = true
			}
		}
		if win.name != at {
			f.unresolved[at] = true
		}
	}
}

// underLink reports whether a directory above name is a symbolic link in
// the stream.
func (f *flattener) underLink(name string) bool {
	for a := path.Dir(name); a != "." && a != "/" && a != ""; a = path.Dir(a) {
		if _, ok := f.links[a]; ok {
			return true
		}
	}
	return false
}

// textual is where name would land by joining the first link above it with
// the rest of the name, without following anything further: the path the
// stream is told not to trust when name cannot be placed.
func (f *flattener) textual(name string) string {
	for a := path.Dir(name); a != "." && a != "/" && a != ""; a = path.Dir(a) {
		l, ok := f.links[a]
		if !ok {
			continue
		}
		to := l.to
		if !path.IsAbs(to) {
			to = path.Join(path.Dir(a), to)
		}
		return path.Join(rootName(to), strings.TrimPrefix(name, a+"/"))
	}
	return ""
}

// land returns the path an entry named name, written by layer, landed on:
// the directories above it resolved through the stream's links, one
// component at a time. ok is false when a link on the way is not from a
// layer below (it may not have been there when the entry was written), and
// for a loop.
func (f *flattener) land(name string, layer int) (string, bool) {
	rest := strings.Split(path.Dir(name), "/")
	cur := ""
	for hops := 0; len(rest) > 0; {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if cur = path.Dir(cur); cur == "." {
				cur = ""
			}
			continue
		}
		next := path.Join(cur, c)
		l, ok := f.links[next]
		if !ok {
			cur = next
			continue
		}
		if hops++; hops > 40 || l.layer >= layer {
			return "", false
		}
		if path.IsAbs(l.to) {
			cur = ""
		}
		rest = append(strings.Split(l.to, "/"), rest...)
	}
	return path.Join(cur, path.Base(name)), true
}

// removedAbove reports whether a layer above layer took away a directory
// above at: named it as a file, a link or a whiteout, or put an opaque
// marker in it.
func (f *flattener) removedAbove(at string, layer int) bool {
	for a := path.Dir(at); ; a = path.Dir(a) {
		if a == "." || a == "/" {
			a = ""
		}
		if o, ok := f.opaqueAt[a]; ok && o > layer {
			return true
		}
		if a == "" {
			return false
		}
		if w, ok := f.written[a]; ok && w.layer > layer {
			return true
		}
	}
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
