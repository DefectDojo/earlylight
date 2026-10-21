package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/DefectDojo/earlylight/internal/archive"
	"github.com/DefectDojo/earlylight/internal/image"
	"github.com/DefectDojo/earlylight/internal/source"
)

// Target is one scanned thing: a directory, an image or a server.
type Target struct {
	Name     string        `json:"target"`
	Type     TargetKind    `json:"type"`
	Digest   string        `json:"digest,omitempty"`
	Platform string        `json:"platform,omitempty"`
	Root     string        `json:"root,omitempty"` // filesystem scans: SARIF paths are relative to it
	Files    int           `json:"files_scanned"`
	Findings []Finding     `json:"findings"`
	Skipped  []source.Skip `json:"skipped"`
	Error    string        `json:"error,omitempty"`
}

// Count returns how many findings have verdict v.
func (t *Target) Count(v Verdict) int {
	n := 0
	for _, f := range t.Findings {
		if f.Verdict == v {
			n++
		}
	}
	return n
}

// Gaps counts skipped files that are real coverage gaps: not deliberate
// exclusions (pseudo-filesystems, container storage) and not test fixtures,
// which are malformed on purpose.
func (t *Target) Gaps() int {
	n := 0
	for _, s := range t.Skipped {
		// The test-fixture exemption applies to real paths only: names inside an
		// archive are chosen by whoever built it, so they never earn it.
		fixture := strings.Contains(s.Path, "/testdata/") && !strings.Contains(s.Path, "!/")
		if s.Excluded || strings.HasPrefix(s.Reason, "excluded:") || fixture {
			continue
		}
		n++
	}
	return n
}

// Options control a run.
type Options struct {
	MaxFileSize int64
	Platform    string        // image platform, e.g. linux/amd64
	AsRoot      bool          // fs: treat the directory as a system root
	Timeout     time.Duration // host: connect timeout
}

// targetCtx is the TargetContext the engine builds while it walks a target.
type targetCtx struct {
	kind      TargetKind
	seen      map[string]bool
	env       []string
	symlinks  map[string]string // absolute path -> target as written
	hardlinks map[string]string // absolute path -> absolute path it names
}

func newTargetCtx(kind TargetKind) *targetCtx {
	return &targetCtx{kind: kind, seen: map[string]bool{}, symlinks: map[string]string{}, hardlinks: map[string]string{}}
}

func (c *targetCtx) Kind() TargetKind     { return c.kind }
func (c *targetCtx) Exists(p string) bool { return c.seen[p] }
func (c *targetCtx) Env() []string        { return c.env }
func (c *targetCtx) Aliases(p string) []string {
	out := []string{p}
	seen := map[string]bool{p: true}
	add := func(q string) {
		if !seen[q] {
			seen[q] = true
			out = append(out, q)
		}
	}
	for a, b := range c.hardlinks {
		if b == p {
			add(a)
		}
		if a == p {
			add(b)
		}
	}
	// A path reached through a symlinked directory or file: resolve every
	// symlink whose target, made absolute, is p or a parent of p.
	for link, to := range c.symlinks {
		abs := to
		if !strings.HasPrefix(abs, "/") {
			abs = path.Join(path.Dir(link), to)
		}
		abs = path.Clean(abs)
		if abs == p {
			add(link)
		} else if strings.HasPrefix(p, abs+"/") {
			add(link + strings.TrimPrefix(p, abs))
		}
	}
	return out
}

// walker hands one target's files to every scan.
type walker struct {
	dets    []Detector
	scans   []Scan
	ctx     *targetCtx
	lim     archive.Limits
	members bool // some detector wants archive members
	t       *Target
}

func newWalker(dets []Detector, kind TargetKind, t *Target, opts Options) *walker {
	w := &walker{ctx: newTargetCtx(kind), lim: archive.DefaultLimits, t: t}
	if opts.MaxFileSize > 0 {
		w.lim.MaxMemberSize = opts.MaxFileSize
	}
	for _, d := range dets {
		if !d.Manifest().Supports(kind) {
			continue
		}
		w.dets = append(w.dets, d)
		w.scans = append(w.scans, d.NewScan(kind))
		if d.Manifest().Archives {
			w.members = true
		}
	}
	return w
}

// sourceOptions builds the walker's read filter: a file is read when any
// detector wants it, and every file when any detector has no filter.
func (w *walker) sourceOptions(opts Options) source.Options {
	so := source.Options{
		MaxFileSize:  opts.MaxFileSize,
		IsExecutable: archive.IsExecutable,
		Symlink:      func(p, t string) { w.ctx.symlinks[p] = t },
		Hardlink:     func(p, t string) { w.ctx.hardlinks[p] = t },
	}
	var readers []Reader
	for _, d := range w.dets {
		r, ok := d.(Reader)
		if !ok {
			return so // this detector wants everything
		}
		readers = append(readers, r)
	}
	so.Read = func(p string, head []byte, exe bool) bool {
		for _, r := range readers {
			if r.Wants(p, head, exe) {
				return true
			}
		}
		return false
	}
	return so
}

func (w *walker) visit(f source.File) error {
	w.t.Files++
	w.ctx.seen[f.Path] = true
	if !w.members {
		w.send(File{Path: f.Path, Data: f.Data, Executable: f.Executable}, nil)
		return nil
	}
	first := true // Walk visits the file itself first, then what it unpacks
	archive.Walk(f.Path, f.Data, w.lim,
		func(p string, b []byte) {
			member := !first
			first = false
			ff := File{Path: p, Data: b, Member: member, Executable: !member && f.Executable}
			w.send(ff, func(i int) bool { return member && !w.dets[i].Manifest().Archives })
		},
		func(p, reason string) { w.t.Skipped = append(w.t.Skipped, source.Skip{Path: p, Reason: reason}) })
	return nil
}

// send gives f to every scan, except those skip(i) rules out.
func (w *walker) send(f File, skip func(int) bool) {
	for i, s := range w.scans {
		if skip != nil && skip(i) {
			continue
		}
		for _, sk := range w.visitSafely(i, s, f) {
			w.t.Skipped = append(w.t.Skipped, source.Skip{Path: sk.Path, Reason: sk.Reason})
		}
	}
}

// visitSafely runs one detector on one file. A detector that panics on a
// hostile file loses that file, reported as not scanned, and the scan goes on.
func (w *walker) visitSafely(i int, s Scan, f File) (skips []Skip) {
	defer func() {
		if r := recover(); r != nil {
			skips = []Skip{{Path: f.Path, Reason: fmt.Sprintf("detector %s failed on this file (%v); not checked", w.dets[i].Manifest().ID, r)}}
		}
	}()
	return s.Visit(f)
}

func (w *walker) finish() {
	for i, s := range w.scans {
		fs, err := finishSafely(s, w.ctx)
		if err != nil {
			w.t.Error = fmt.Sprintf("detector %s failed: %v", w.dets[i].Manifest().ID, err)
			return
		}
		w.t.Findings = append(w.t.Findings, check(w.dets[i].Manifest().ID, fs)...)
	}
}

func finishSafely(s Scan, ctx TargetContext) (fs []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return s.Finish(ctx), nil
}

// ScanFS scans a directory or file. With AsRoot (always for "/"), the directory
// is treated as a system root, for example a host mounted at /host or an
// extracted image, and paths are reported inside it. Otherwise paths are the
// real absolute paths, so location rules see /etc/ssl/... even when scanning
// /etc/ssl.
func ScanFS(dets []Detector, root string, opts Options) *Target {
	t := &Target{Name: root, Type: Filesystem}
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	real, _ = filepath.Abs(real)
	asRoot := opts.AsRoot || real == "/"
	t.Name = real
	w := newWalker(dets, Filesystem, t, opts)
	so := w.sourceOptions(opts)
	if asRoot {
		so.Exclude = append(append([]string{}, source.DefaultExcludes...), source.ContainerStorage...)
	} else {
		t.Root = real
	}
	isDir := false
	if info, err := os.Stat(real); err == nil && info.IsDir() {
		isDir = true
	}
	skips, _, err := source.Dir(real, so, func(f source.File) error {
		if !asRoot && isDir {
			f.Path = path.Join(filepath.ToSlash(real), f.Path)
		}
		return w.visit(f)
	})
	t.Skipped = append(t.Skipped, skips...)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	if t.Files == 0 {
		t.Error = "no files were scanned (the path is empty or nothing in it could be read)"
		return t
	}
	w.finish()
	return t
}

// ScanImage scans a container image: a registry reference, docker-archive:FILE
// (from docker save), or rootfs:FILE / rootfs:- (a flat filesystem tar from
// docker export).
func ScanImage(dets []Detector, ref string, opts Options) *Target {
	t := &Target{Name: ref, Type: Image}
	w := newWalker(dets, Image, t, opts)
	var rc io.ReadCloser
	if p, ok := strings.CutPrefix(ref, "rootfs:"); ok {
		if p == "-" {
			rc = io.NopCloser(os.Stdin)
		} else {
			f, err := os.Open(p)
			if err != nil {
				t.Error = err.Error()
				return t
			}
			rc = f
		}
	} else {
		o, err := image.Open(ref, opts.Platform)
		if err != nil {
			t.Error = err.Error()
			return t
		}
		rc, t.Digest, t.Platform, w.ctx.env = o.FS, o.Digest, o.Platform, o.Env
	}
	defer rc.Close()
	skips, _, err := source.Tar(rc, w.sourceOptions(opts), w.visit)
	t.Skipped = append(t.Skipped, skips...)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	if t.Files == 0 {
		t.Error = "the image contained no regular files"
		return t
	}
	w.finish()
	return t
}

// ScanHost runs every detector that probes live hosts against addr (host,
// host:port or a URL).
func ScanHost(dets []Detector, addr string, opts Options) *Target {
	if u, err := url.Parse(addr); err == nil && u.Scheme != "" && u.Host != "" {
		addr = u.Host
	}
	t := &Target{Name: addr, Type: Host}
	ran := false
	for _, d := range dets {
		p, ok := d.(Prober)
		if !ok || !d.Manifest().Supports(Host) {
			continue
		}
		ran = true
		name, checked, fs, err := p.Probe(context.Background(), addr, opts.Timeout)
		if name != "" {
			t.Name = name
		}
		if err != nil {
			var ne interface{ Timeout() bool }
			if errors.As(err, &ne) && ne.Timeout() {
				t.Error = "timed out connecting to " + t.Name
			} else {
				t.Error = err.Error()
			}
			return t
		}
		t.Files += checked
		t.Findings = append(t.Findings, check(d.Manifest().ID, fs)...)
	}
	if !ran {
		t.Error = "none of the selected detectors check network hosts"
	}
	return t
}
