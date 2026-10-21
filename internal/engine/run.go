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
	Files    int           `json:"files_scanned"`  // regular files examined
	Read     int           `json:"files_read"`     // of those, read in full and checked
	Findings []Finding     `json:"findings"`
	Skipped  []source.Skip `json:"skipped"`
	// Problems are things a detector could not read fully (a damaged package
	// database), which weaken its verdicts without stopping the scan.
	Problems []string `json:"problems,omitempty"`
	// Annotations are facts about the whole target (its OS release).
	Annotations map[string]any `json:"annotations,omitempty"`
	// Incomplete says why the scan could not finish (a registry failed).
	Incomplete string `json:"incomplete,omitempty"`
	Error      string `json:"error,omitempty"`
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
		// The test-fixture exemption applies only to paths the operator controls:
		// real files on a scanned filesystem. Image paths and archive member names
		// are chosen by whoever built them, and a detector failure is never exempt.
		fixture := t.Type == Filesystem && strings.Contains(s.Path, "/testdata/") &&
			!strings.Contains(s.Path, "!/") && !s.DetectorFailed
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
	Platform    string // image platform, e.g. linux/amd64
	AsRoot      bool   // fs: treat the directory itself as a system root
	// SystemRoot (fs) is the directory holding the system the scanned path
	// belongs to, "/" by default. Paths are reported inside it, and detectors
	// can read its package databases even when only a subdirectory is walked.
	SystemRoot string
	Timeout    time.Duration // host: connect timeout; repo: registry timeout per request
	// Repository scans and fixes.
	Offline    bool     // no registry lookups
	PublicOnly bool     // contact only public registry addresses
	Platforms  []string // the platforms that are built; empty means every platform
	DryRun     bool     // fix: print changes without writing them
}

// targetCtx is the TargetContext the engine builds while it walks a target.
type targetCtx struct {
	kind      TargetKind
	t         *Target
	sysRoot   string // fs scans below the system root: its OS path
	seen      map[string]bool
	env       []string
	symlinks  map[string]string // absolute path -> target as written
	hardlinks map[string]string // absolute path -> absolute path it names
}

func newTargetCtx(kind TargetKind, t *Target) *targetCtx {
	return &targetCtx{kind: kind, t: t, seen: map[string]bool{}, symlinks: map[string]string{}, hardlinks: map[string]string{}}
}

func (c *targetCtx) SystemRoot() string { return c.sysRoot }
func (c *targetCtx) Links() (map[string]string, map[string]string) {
	return c.symlinks, c.hardlinks
}
func (c *targetCtx) Problem(msg string) { c.t.Problems = append(c.t.Problems, msg) }
func (c *targetCtx) Annotate(key string, v any) {
	if c.t.Annotations == nil {
		c.t.Annotations = map[string]any{}
	}
	c.t.Annotations[key] = v
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
	// prefix is prepended to walked paths: the scanned directory's path inside
	// the system root ("/" when the walk starts at the root). single is set
	// when the target is one file, whose path is the prefix itself.
	prefix string
	single bool
}

// abs turns a walked path into its path inside the system root.
func (w *walker) abs(p string) string {
	switch {
	case w.prefix == "" || w.prefix == "/":
		return p
	case w.single:
		return w.prefix
	}
	return path.Clean(w.prefix + "/" + p)
}

func newWalker(dets []Detector, kind TargetKind, t *Target, opts Options) *walker {
	w := &walker{ctx: newTargetCtx(kind, t), lim: archive.DefaultLimits, t: t}
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
		Symlink:      func(p, t string) { w.ctx.symlinks[w.abs(p)] = t },
		Hardlink:     func(p, t string) { w.ctx.hardlinks[w.abs(p)] = w.abs(t) },
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
			if r.Wants(w.abs(p), head, exe) {
				return true
			}
		}
		return false
	}
	return so
}

func (w *walker) visit(f source.File) error {
	f.Path = w.abs(f.Path)
	w.ctx.seen[f.Path] = true
	w.t.Read++
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
			w.t.Skipped = append(w.t.Skipped, source.Skip{Path: sk.Path, Reason: sk.Reason, DetectorFailed: sk.failed})
		}
	}
}

// visitSafely runs one detector on one file. A detector that panics on a
// hostile file loses that file, reported as not scanned, and the scan goes on.
func (w *walker) visitSafely(i int, s Scan, f File) (skips []Skip) {
	defer func() {
		if r := recover(); r != nil {
			skips = []Skip{{Path: f.Path, Reason: fmt.Sprintf("detector %s failed on this file (%v); not checked", w.dets[i].Manifest().ID, r), failed: true}}
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

// ScanFS scans a directory or file. Paths are reported inside a system root:
// "/" by default, so location rules see /etc/ssl/... even when scanning
// /etc/ssl; the directory itself with AsRoot (a host mounted at /host, an
// extracted image); or SystemRoot when the scanned path lies below it. A walk
// that starts at its system root skips pseudo-filesystems and container storage.
func ScanFS(dets []Detector, root string, opts Options) *Target {
	t := &Target{Name: root, Type: Filesystem}
	real, err := realPath(root)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	t.Name = real
	sysRoot := "/"
	switch {
	case opts.SystemRoot != "":
		if sysRoot, err = realPath(opts.SystemRoot); err != nil {
			t.Error = err.Error()
			return t
		}
		if fi, err := os.Stat(sysRoot); err != nil || !fi.IsDir() {
			t.Error = opts.SystemRoot + " is not a directory"
			return t
		}
	case opts.AsRoot:
		sysRoot = real
	}
	rel, err := filepath.Rel(sysRoot, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Error = fmt.Sprintf("%s is outside the system root %s", root, sysRoot)
		return t
	}
	w := newWalker(dets, Filesystem, t, opts)
	w.prefix = path.Clean("/" + filepath.ToSlash(rel))
	if info, err := os.Stat(real); err == nil && !info.IsDir() {
		w.single = true
	}
	so := w.sourceOptions(opts)
	if w.prefix == "/" {
		so.Exclude = append(append([]string{}, source.DefaultExcludes...), source.ContainerStorage...)
	} else {
		t.Root = w.prefix // SARIF paths are relative to the scanned directory
		w.ctx.sysRoot = sysRoot
	}
	skips, n, err := source.Dir(real, so, w.visit)
	t.Skipped, t.Files = append(t.Skipped, skips...), n
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

func realPath(p string) (string, error) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	return filepath.Abs(r)
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
	so := w.sourceOptions(opts)
	so.Uncounted = source.DefaultExcludes
	skips, n, err := source.Tar(rc, so, w.visit)
	t.Skipped, t.Files = append(t.Skipped, skips...), n
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
		t.Read += checked
		t.Findings = append(t.Findings, check(d.Manifest().ID, fs)...)
	}
	if !ran {
		t.Error = "none of the selected detectors check network hosts"
	}
	return t
}
