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
	"github.com/DefectDojo/earlylight/internal/netguard"
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
	gap := map[string]bool{} // a path is counted once, however many records it has
	for _, s := range t.Skipped {
		// The test-fixture exemption applies only to paths the operator controls:
		// real files on a scanned filesystem. Image paths and archive member names
		// are chosen by whoever built them, and a detector failure is never exempt.
		fixture := t.Type == Filesystem && strings.Contains(s.Path, "/testdata/") &&
			!strings.Contains(s.Path, "!/") && !s.DetectorFailed
		if s.Excluded || strings.HasPrefix(s.Reason, "excluded:") || fixture || gap[s.Path] {
			continue
		}
		gap[s.Path] = true
		n++
	}
	return n
}

// SkippedPaths counts the paths that were not scanned, each once: a file
// over the limits of two detectors has a record for each.
func (t *Target) SkippedPaths() int {
	seen := map[string]bool{}
	for _, s := range t.Skipped {
		seen[s.Path] = true
	}
	return len(seen)
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
	// Override replaces the image's Entrypoint or Cmd for detectors that
	// read the container's command (a Compose or Kubernetes setting).
	Override *CommandOverride
	// Guarded opens registry images through the address-checking
	// transport (image references from a source tree), honouring
	// PublicOnly, and refuses local archives.
	Guarded bool
}

// CommandOverride is a deployment's replacement for an image's Entrypoint
// and Cmd. A nil field keeps the image's own; Compose's entrypoint without
// command also clears Cmd (ClearCmd).
type CommandOverride struct {
	Entrypoint, Cmd *[]string
	ClearCmd        bool
}

// Apply returns the command the container runs.
func (o *CommandOverride) Apply(entrypoint, cmd []string) []string {
	if o == nil {
		return append(append([]string(nil), entrypoint...), cmd...)
	}
	if o.Entrypoint != nil {
		entrypoint = *o.Entrypoint
		if o.ClearCmd {
			cmd = nil
		}
	}
	if o.Cmd != nil {
		cmd = *o.Cmd
	}
	return append(append([]string(nil), entrypoint...), cmd...)
}

// targetCtx is the TargetContext the engine builds while it walks a target.
type targetCtx struct {
	kind      TargetKind
	t         *Target
	sysRoot   string // fs scans below the system root: its OS path
	seen      map[string]bool
	env       []string
	cmd       []string
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
func (c *targetCtx) Command() []string    { return c.cmd }
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
	ids     []string // each detector's ID
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
	// limited is the path of the last file read, and limits each scan's own
	// limit on it, for handing it out (Limiter).
	limited string
	limits  []fileLimit
	// exclusions are the exclusion records made for each scan, by path, so
	// a gap the scan reports at the end replaces its exclusion.
	exclusions []map[string]string
	// linked counts the hard links that name each path.
	linked map[string]int
}

// fileLimit is one detector's own limit on one file, and whether it asked
// for the file.
type fileLimit struct {
	bytes int64
	wants bool
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
		w.ids = append(w.ids, d.Manifest().ID)
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
		Hardlink:     func(p, t string) { w.setHardlink(w.abs(p), w.abs(t)) },
	}
	type headScan struct {
		id string
		h  HeadVisitor
	}
	var heads []headScan
	for i, s := range w.scans {
		if h, ok := s.(HeadVisitor); ok {
			heads = append(heads, headScan{w.dets[i].Manifest().ID, h})
		}
	}
	visitHead := func(p string, head []byte) {
		for _, h := range heads {
			w.visitHeadSafely(h.id, h.h, w.abs(p), head)
		}
	}
	readers := make([]Reader, len(w.dets)) // nil: the detector wants everything
	limiters := make([]Limiter, len(w.dets))
	all, limited := false, false
	for i, d := range w.dets {
		var ok bool
		if readers[i], ok = d.(Reader); !ok {
			all = true
		}
		if limiters[i], ok = d.(Limiter); ok {
			limited = true
		}
		if _, ok := w.scans[i].(LimitVisitor); ok {
			limited = true // it is told about files it asked for and did not get
		}
	}
	var decide func(p string, head []byte, exe bool) (bool, int64)
	switch {
	case limited:
		w.limits = make([]fileLimit, len(w.dets))
		decide = func(p string, head []byte, exe bool) (bool, int64) {
			return w.limit(p, head, exe, readers, limiters)
		}
		so.Over = func(p string, size int64, own bool) []source.Skip { return w.tooLarge(w.abs(p), size, own) }
	case all:
		decide = func(string, []byte, bool) (bool, int64) { return true, 0 }
	default:
		decide = func(p string, head []byte, exe bool) (bool, int64) {
			for _, r := range readers {
				if r.Wants(p, head, exe) {
					return true, 0
				}
			}
			return false, 0
		}
	}
	so.Read = func(p string, head []byte, exe bool) (bool, int64) {
		abs := w.abs(p)
		if w.ctx.seen[abs] {
			// The path comes round again in a docker export: this entry
			// is the file (a flattened image never repeats a path).
			w.replaced(abs)
		}
		// A path that was a link is a file now.
		delete(w.ctx.symlinks, abs)
		w.setHardlink(abs, "")
		// The file exists whether or not any detector reads it, so Exists
		// does not depend on which detectors ran.
		w.ctx.seen[abs] = true
		visitHead(p, head)
		return decide(abs, head, exe)
	}
	so.Other = func(p string) {
		if abs := w.abs(p); w.ctx.seen[abs] {
			w.replaced(abs)
		}
	}
	so.Unread = func(p string, dir bool) {
		abs := w.abs(p)
		if !dir {
			w.ctx.seen[abs] = true // it exists, read or not
		}
		for i, s := range w.scans {
			if uv, ok := s.(UnreadVisitor); ok {
				w.safely(i, abs, func() { uv.VisitUnread(abs, dir) })
			}
		}
	}
	return so
}

// replaced handles a file at p that a later entry replaces (a docker
// export names a path again, as a file, directory or link): every scan
// forgets what it kept of p, unless a hard link names p. A hard link keeps
// the earlier file's content (it names the file, not the path), so what
// was found in it stays, under p.
func (w *walker) replaced(p string) {
	if w.linked[p] > 0 {
		return
	}
	w.forget(p)
	delete(w.ctx.seen, p)
}

// setHardlink records that p is a hard link to t ("": p is no longer a
// link), keeping a count of the links that name each path.
func (w *walker) setHardlink(p, t string) {
	if old, ok := w.ctx.hardlinks[p]; ok {
		if w.linked[old]--; w.linked[old] <= 0 {
			delete(w.linked, old)
		}
		delete(w.ctx.hardlinks, p)
	}
	if t == "" {
		return
	}
	if w.linked == nil {
		w.linked = map[string]int{}
	}
	w.ctx.hardlinks[p] = t
	w.linked[t]++
}

// forget tells every scan to drop what it kept of p.
func (w *walker) forget(p string) {
	for i, s := range w.scans {
		if f, ok := s.(Forgetter); ok {
			w.safely(i, p, func() { f.Forget(p) })
		}
	}
}

// safely runs one of scan i's hooks on p; a panic is recorded as the
// detector failing on p.
func (w *walker) safely(i int, p string, f func()) {
	defer func() {
		if r := recover(); r != nil {
			w.t.Skipped = append(w.t.Skipped, source.Skip{Path: p, Reason: fmt.Sprintf("detector %s failed on this file (%v); not checked", w.ids[i], r), DetectorFailed: true})
		}
	}()
	f()
}

// limit decides whether to read a file when some detector has limits of its
// own: it is read when any detector wants it, as far as the largest limit of
// those that do (--max-file-size when one has none). Each detector's limit
// is kept for handing the file out.
func (w *walker) limit(p string, head []byte, exe bool, readers []Reader, limiters []Limiter) (bool, int64) {
	w.limited = p
	read, unlimited := false, false
	var most int64
	for i := range w.dets {
		l := fileLimit{wants: readers[i] == nil || readers[i].Wants(p, head, exe)}
		if limiters[i] != nil {
			l.bytes = limiters[i].Limit(p, head, exe)
		}
		w.limits[i] = l
		switch {
		case !l.wants:
		case l.bytes <= 0:
			read, unlimited = true, true
		default:
			read = true
			most = max(most, l.bytes)
		}
	}
	if unlimited {
		return read, 0
	}
	return read, most
}

// tooLarge records a file that was not read (size -1 when found larger
// while reading). Over the limit of every detector that wants it (own), it
// is recorded for each of them; over --max-file-size, the source records
// it as a gap, and each detector that wanted it is only told
// (VisitOverLimit), so a verdict never rests on its absence.
func (w *walker) tooLarge(p string, size int64, own bool) []source.Skip {
	var out []source.Skip
	for i, l := range w.limits {
		switch {
		case !l.wants:
		case own && l.bytes > 0 && (size < 0 || size > l.bytes):
			out = append(out, w.overLimit(i, p, size)...)
		case !own:
			if lv, ok := w.scans[i].(LimitVisitor); ok {
				for _, sk := range w.visitOverLimitSafely(i, lv, p, size) {
					if sk.failed {
						out = append(out, source.Skip{Path: sk.Path, Reason: sk.Reason, DetectorFailed: true})
					}
				}
			}
		}
	}
	return out
}

// overLimit records that scan i did not check p, which is over its limit:
// what its VisitOverLimit returns (coverage gaps), or else a deliberate
// exclusion.
func (w *walker) overLimit(i int, p string, size int64) []source.Skip {
	if lv, ok := w.scans[i].(LimitVisitor); ok {
		if skips := w.visitOverLimitSafely(i, lv, p, size); len(skips) > 0 {
			out := make([]source.Skip, len(skips))
			for k, sk := range skips {
				out[k] = source.Skip{Path: sk.Path, Reason: sk.Reason, DetectorFailed: sk.failed}
			}
			return out
		}
	}
	what := fmt.Sprintf("(%d bytes)", size)
	if size < 0 {
		what = "(found while reading)"
	}
	reason := fmt.Sprintf("excluded: larger than the %d-byte limit of %s for this file %s", w.limits[i].bytes, w.ids[i], what)
	if w.exclusions == nil {
		w.exclusions = make([]map[string]string, len(w.scans))
	}
	if w.exclusions[i] == nil {
		w.exclusions[i] = map[string]string{}
	}
	w.exclusions[i][p] = reason
	return []source.Skip{{Path: p, Excluded: true, Reason: reason}}
}

// visitOverLimitSafely runs one detector's VisitOverLimit, containing a
// panic as Visit does.
func (w *walker) visitOverLimitSafely(i int, lv LimitVisitor, p string, size int64) (skips []Skip) {
	defer func() {
		if r := recover(); r != nil {
			skips = []Skip{{Path: p, Reason: fmt.Sprintf("detector %s failed on this file (%v); not checked", w.ids[i], r), failed: true}}
		}
	}()
	return lv.VisitOverLimit(p, size)
}

// over reports whether f is over scan i's own limit, which keeps it from
// that detector.
func (w *walker) over(i int, f File) bool {
	if f.Member || f.Path != w.limited || w.limits == nil {
		return false
	}
	l := w.limits[i]
	return l.bytes > 0 && int64(len(f.Data)) > l.bytes
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
			if member {
				ff.Outer = f.Path
			}
			w.send(ff, func(i int) bool { return member && !w.dets[i].Manifest().Archives })
		},
		func(p, reason string) { w.t.Skipped = append(w.t.Skipped, source.Skip{Path: p, Reason: reason}) })
	return nil
}

// send gives f to every scan, except those skip(i) rules out and those
// whose own limit it is over: read for another detector, it is recorded
// as not checked by each one that asked for it.
func (w *walker) send(f File, skip func(int) bool) {
	for i, s := range w.scans {
		if skip != nil && skip(i) {
			continue
		}
		if w.over(i, f) {
			if w.limits[i].wants {
				w.t.Skipped = append(w.t.Skipped, w.overLimit(i, f.Path, int64(len(f.Data)))...)
			}
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

// visitHeadSafely runs one detector's VisitHead on one file. A detector
// that panics on a hostile file loses that file, reported as not scanned,
// and the scan goes on, as with Visit.
func (w *walker) visitHeadSafely(id string, h HeadVisitor, p string, head []byte) {
	defer func() {
		if r := recover(); r != nil {
			w.t.Skipped = append(w.t.Skipped, source.Skip{Path: p, Reason: fmt.Sprintf("detector %s failed on this file (%v); not checked", id, r), DetectorFailed: true})
		}
	}()
	h.VisitHead(p, head)
}

func (w *walker) finish() {
	defer func() { w.t.Skipped = oneRecordPerPath(w.t.Skipped) }()
	for i, s := range w.scans {
		fs, err := finishSafely(s, w.ctx)
		if err != nil {
			w.t.Error = fmt.Sprintf("detector %s failed: %v", w.dets[i].Manifest().ID, err)
			return
		}
		w.t.Findings = append(w.t.Findings, check(w.dets[i].Manifest().ID, fs)...)
		if fs, ok := s.(FinishSkipper); ok {
			skips, err := finishSkipsSafely(fs)
			if err != nil {
				w.t.Error = fmt.Sprintf("detector %s failed: %v", w.ids[i], err)
				return
			}
			for _, sk := range skips {
				w.dropExclusion(i, sk.Path)
				w.t.Skipped = append(w.t.Skipped, source.Skip{Path: sk.Path, Reason: sk.Reason})
			}
		}
	}
}

// oneRecordPerPath merges the records of one path (two detectors that
// left it unchecked, or a source record and a detector's): a coverage gap
// if any record is one, a deliberate exclusion otherwise, with every
// distinct reason. Paths keep the order they were first recorded in.
func oneRecordPerPath(skips []source.Skip) []source.Skip {
	at := map[string]int{}
	var out []source.Skip
	for _, s := range skips {
		i, ok := at[s.Path]
		if !ok {
			at[s.Path] = len(out)
			out = append(out, s)
			continue
		}
		m := &out[i]
		switch {
		case m.Excluded && !s.Excluded:
			// The gap leads; the exclusion's reason follows.
			m.Reason, m.Excluded = s.Reason+"; "+strings.TrimPrefix(m.Reason, "excluded: "), false
		case !strings.Contains(m.Reason, strings.TrimPrefix(s.Reason, "excluded: ")):
			m.Reason += "; " + strings.TrimPrefix(s.Reason, "excluded: ")
		}
		m.DetectorFailed = m.DetectorFailed || s.DetectorFailed
	}
	return out
}

// dropExclusion removes the exclusion record made for scan i on p: the
// scan reports p as a gap instead.
func (w *walker) dropExclusion(i int, p string) {
	if w.exclusions == nil || w.exclusions[i][p] == "" {
		return
	}
	reason := w.exclusions[i][p]
	out := w.t.Skipped[:0]
	for _, s := range w.t.Skipped {
		if !(s.Excluded && s.Path == p && s.Reason == reason) {
			out = append(out, s)
		}
	}
	w.t.Skipped = out
}

func finishSkipsSafely(s FinishSkipper) (skips []Skip, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return s.FinishSkips(), nil
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
	var unresolved func() []string
	if p, ok := strings.CutPrefix(ref, "rootfs:"); ok && opts.Guarded {
		t.Error = fmt.Sprintf("%q: only registry references are opened for a source tree", "rootfs:"+p)
		return t
	} else if ok {
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
		open := image.Open
		if opts.Guarded {
			open = func(ref, platform string) (*image.Opened, error) {
				return image.OpenRegistry(ref, platform, netguard.Transport(opts.PublicOnly))
			}
		}
		o, err := open(ref, opts.Platform)
		if err != nil {
			t.Error = err.Error()
			return t
		}
		rc, t.Digest, t.Platform, w.ctx.env = o.FS, o.Digest, o.Platform, o.Env
		unresolved = o.Unresolved
		w.ctx.cmd = opts.Override.Apply(o.Entrypoint, o.Cmd)
	}
	defer rc.Close()
	so := w.sourceOptions(opts)
	so.Uncounted = source.DefaultExcludes
	// A registry or docker-archive image is flattened top layer first: the
	// first entry for a path is the file. A docker export (rootfs:) is
	// one filesystem, where the last entry is.
	so.FirstWins = !strings.HasPrefix(ref, "rootfs:")
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
	if unresolved != nil {
		// Paths the layers do not settle: whatever was read there is
		// forgotten, and each scan is told it was not read.
		for _, p := range unresolved() {
			w.forget(p)
			so.Unread(p, false)
			t.Skipped = append(t.Skipped, source.Skip{Path: p, Reason: "the image's layers do not settle what this file holds (two entries in one layer, a hard link to a file not in its layer, or a write through a symbolic link); not checked"})
		}
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
	ran, applied := false, false
	var notApplicable []string
	for _, d := range dets {
		p, ok := d.(Prober)
		if !ok || !d.Manifest().Supports(Host) {
			continue
		}
		ran = true
		name, checked, fs, err := p.Probe(context.Background(), addr, opts.Timeout)
		if errors.Is(err, ErrNotApplicable) {
			notApplicable = append(notApplicable, d.Manifest().ID+": "+err.Error())
			continue
		}
		applied = true
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
	switch {
	case !ran:
		t.Error = "none of the selected detectors check network hosts"
	case !applied:
		t.Error = strings.Join(notApplicable, "; ")
	}
	return t
}
