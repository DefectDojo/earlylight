package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// Change is a set of edits to one repository file.
type Change struct {
	File    string
	Edits   []Edit
	Summary string
	// NewFiles are files the change adds, by repository-relative path.
	// Apply refuses to replace a file that exists with other content.
	NewFiles map[string][]byte
}

// Declined is a plan that proposes no change, with the reason.
type Declined struct{ Reason string }

func (d *Declined) Error() string { return d.Reason }

// IsDeclined returns the Declined in err's chain, if any.
func IsDeclined(err error) (*Declined, bool) {
	var d *Declined
	if errors.As(err, &d) {
		return d, true
	}
	return nil, false
}

// Plan builds the edit for a finding the scan reported at file:line with
// rule and, for apk findings, props["package"]. It rescans the edited file
// in memory and accepts the edit only when that finding is gone and nothing
// new appeared. A line that is no longer there declines: the file changed
// since the scan, and the finding is not checked again here.
func Plan(ctx context.Context, root string, f Finding, opts Options) (*Change, error) {
	if !f.Fixable || f.edit == nil && len(f.newFiles) == 0 {
		return nil, &Declined{Reason: f.Fix}
	}
	for p, data := range f.newFiles {
		if err := checkNewPath(root, p, data); err != nil {
			return nil, &Declined{Reason: err.Error() + "; add the fix by hand"}
		}
	}
	if f.edit == nil {
		return planNewFiles(ctx, root, f, opts)
	}
	b, err := readFile(root, f.File)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	e := *f.edit
	if e.Line < 1 || e.Line > len(lines) {
		return nil, notChecked("line %d is past the end of %s, which changed since the scan", e.Line, f.File)
	}
	line := strings.TrimSuffix(lines[e.Line-1], "\r")
	if e.Col < 0 || e.Col+len(e.Old) > len(line) || line[e.Col:e.Col+len(e.Old)] != e.Old {
		// An earlier edit on the same line moves the word: rescan and take
		// the one finding that is still the same word, or decline.
		now, err := scanOne(ctx, root, f.File, opts, b)
		if err != nil {
			return nil, err
		}
		var match *Edit
		n := 0
		for _, g := range now {
			if g.Rule == f.Rule && g.Line == f.Line && g.edit != nil && g.edit.Old == e.Old && g.Props["spec"] == f.Props["spec"] {
				match = g.edit
				n++
			}
		}
		if n != 1 {
			return nil, &Declined{Reason: fmt.Sprintf("%s:%d no longer reads as scanned", f.File, e.Line)}
		}
		e = *match
	}
	newLine := line[:e.Col] + e.New + line[e.Col+len(e.Old):]
	ch := &Change{File: f.File, Edits: []Edit{{Line: e.Line, Col: e.Col, Old: line, New: newLine}}, Summary: summary(f), NewFiles: f.newFiles}

	// Rescan the edited file in memory.
	edited := append([]string{}, lines...)
	cr := ""
	if strings.HasSuffix(lines[e.Line-1], "\r") {
		cr = "\r"
	}
	edited[e.Line-1] = newLine + cr
	o := opts
	o.Overlay = map[string][]byte{f.File: []byte(strings.Join(edited, "\n"))}
	for p, data := range f.newFiles {
		o.Overlay[p] = data
	}
	before, err := scanOne(ctx, root, f.File, opts, nil)
	if err != nil {
		return nil, err
	}
	after, err := scanOne(ctx, root, f.File, o, o.Overlay[f.File])
	if err != nil {
		return nil, err
	}
	if count(after, f.Rule, f.Line) >= count(before, f.Rule, f.Line) {
		return nil, &Declined{Reason: "the edit did not clear the finding; change it by hand"}
	}
	if len(after) > len(before) {
		return nil, &Declined{Reason: "the edit raised a new finding; change it by hand"}
	}
	return ch, nil
}

// planNewFiles plans a fix that only adds files, checked by rescanning the
// finding's file with the files in place.
func planNewFiles(ctx context.Context, root string, f Finding, opts Options) (*Change, error) {
	o := opts
	o.Overlay = map[string][]byte{}
	for p, data := range f.newFiles {
		o.Overlay[p] = data
	}
	before, err := scanOne(ctx, root, f.File, opts, nil)
	if err != nil {
		return nil, err
	}
	after, err := scanOne(ctx, root, f.File, o, nil)
	if err != nil {
		return nil, err
	}
	if count(after, f.Rule, f.Line) >= count(before, f.Rule, f.Line) {
		return nil, &Declined{Reason: "the added files did not clear the finding; add the fix by hand"}
	}
	return &Change{File: f.File, Summary: summary(f), NewFiles: f.newFiles}, nil
}

func scanOne(ctx context.Context, root, file string, opts Options, data []byte) ([]Finding, error) {
	fs, _, err := scanFile(ctx, root, file, opts, data)
	return fs, err
}

// scanFile is scanOne that also returns what the rescan could not read
// when it walked the tree: a Yocto finding joins files across it. A Skip
// with no file is the walk's limit.
func scanFile(ctx context.Context, root, file string, opts Options, data []byte) ([]Finding, []Skip, error) {
	s := &scanner{ctx: ctx, root: root, opts: opts, bases: map[string]baseInfo{}}
	if data == nil {
		var err error
		if data, err = readFile(root, file); err != nil {
			return nil, nil, err
		}
	}
	switch kindOf(file) {
	case "dockerfile":
		return s.dockerfile(file, string(data)), nil, nil
	case "shell":
		return s.script(file, string(data)), nil, nil
	case "yaml":
		return s.yaml(file, string(data)), nil, nil
	case "sshd_config":
		return s.sshdConfig(file, string(data)), nil, nil
	case "build":
		// A Yocto finding needs the whole tree (TCLIBC and bbappends live
		// in other files): rescan it, keeping this file's findings.
		if s.yoctoNeedsTree(file) {
			res, err := Scan(ctx, root, opts)
			if err != nil {
				return nil, nil, err
			}
			var out []Finding
			for _, f := range res.Findings {
				if f.File == file {
					out = append(out, f)
				}
			}
			skips := res.Skips
			if res.Truncated {
				skips = append(skips, Skip{Reason: "the source tree has too many files to walk"})
			}
			return out, skips, nil
		}
		s.build(file, string(data))
		return s.finishBuild(), nil, nil
	}
	return nil, nil, nil
}

func count(fs []Finding, rule string, line int) int {
	n := 0
	for _, f := range fs {
		if f.Rule == rule && f.Line == line {
			n++
		}
	}
	return n
}

func summary(f Finding) string {
	switch f.Rule {
	case RulePin, RuleUnpinned:
		return fmt.Sprintf("Require %s at %s or later, the Alpine release with the *sshole fix", f.Props["package"], f.Props["fixed"])
	case RuleStar:
		return "Set the password field to \"*NP*\" instead of \"*\", which keeps key logins and matches no password"
	case RuleEOL:
		return fmt.Sprintf("Moves the base image to %s, on the nearest Alpine release with a fixed OpenSSH package. This is an Alpine release upgrade: review it and run your tests before you merge", f.Props["upgrade"])
	case RuleBuild:
		return f.Props["fix_summary"]
	case RuleAnsible:
		return "Sets the Ansible apk task to state: latest, so every run installs the fixed OpenSSH package from the host's Alpine repositories"
	}
	return f.Fix
}

// Apply writes a change after checking each edited line still reads as
// planned. It keeps line endings and the file mode, and writes atomically.
// New files are written first; one that exists already must hold the same
// content.
func Apply(root string, ch *Change) error {
	if err := WriteNewFiles(root, ch.NewFiles); err != nil {
		return err
	}
	if len(ch.Edits) == 0 {
		return nil
	}
	p, err := refs.SafePath(root, ch.File)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	b, err := readFile(root, ch.File)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	for _, e := range ch.Edits {
		if e.Line < 1 || e.Line > len(lines) || strings.TrimSuffix(lines[e.Line-1], "\r") != e.Old {
			return fmt.Errorf("%s changed since the plan: line %d no longer reads as planned", ch.File, e.Line)
		}
		cr := ""
		if strings.HasSuffix(lines[e.Line-1], "\r") {
			cr = "\r"
		}
		lines[e.Line-1] = e.New + cr
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".earlylight-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(strings.Join(lines, "\n")); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, fi.Mode().Perm()); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, p)
}

// Diff is the change as a short unified-style listing.
func Diff(ch *Change) string {
	var b strings.Builder
	for _, e := range ch.Edits {
		fmt.Fprintf(&b, "@@ %s line %d @@\n- %s\n+ %s\n", Printable(ch.File), e.Line, Printable(e.Old), Printable(e.New))
	}
	return b.String()
}

// Printable shows repository text safely on a terminal.
func Printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\t' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Find rescans one file and returns the finding with this rule at this
// line. message, when not empty, picks between several on the line: the apk
// spec or the text the finding's message quotes. gone is true only when
// this rescan checked what the scan reported and the finding is not there.
// Otherwise it declines with "rescan to confirm": a not-checked finding; a
// rule or file this package does not rescan; a file, TCLIBC setting or base
// image that cannot be read this time; another finding for the same package
// on the line; and a line past the end of a file that still has findings
// like it.
func Find(ctx context.Context, root, file string, line int, rule, message string, opts Options) (f *Finding, gone bool, err error) {
	if !findRules[rule] || kindOf(file) == "" {
		return nil, false, notChecked("%s findings in %s are not rescanned here, so it is not checked", rule, file)
	}
	data, err := readFile(root, file)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && rule != RuleNotChecked {
			return nil, true, nil // the file is deleted, and its findings with it
		}
		return nil, false, notChecked("%s could not be read (%v), so it is not checked", file, err)
	}
	fs, skips, err := scanFile(ctx, root, file, opts, data)
	if err != nil {
		return nil, false, err
	}
	msg := lineRefRE.ReplaceAllString(message, ")") // stored before messages lost their line numbers
	var at []Finding
	for _, g := range fs {
		if g.Rule == rule && g.Line == line {
			at = append(at, g)
		}
	}
	if len(at) > 1 && msg != "" {
		var picked []Finding
		for _, g := range at {
			if strings.Contains(msg, g.Message) || g.Props["spec"] != "" && strings.Contains(msg, g.Props["spec"]) {
				picked = append(picked, g)
			}
		}
		if len(picked) > 0 {
			at = picked
		}
	}
	if len(at) == 0 && msg != "" {
		// The line moved (an edit above it): the same finding elsewhere in
		// the file, when there is exactly one, is still this finding.
		var moved []Finding
		for _, g := range fs {
			if g.Rule == rule && strings.Contains(msg, g.Message) {
				moved = append(moved, g)
			}
		}
		if len(moved) == 1 {
			return &moved[0], false, nil
		}
		if len(moved) > 1 {
			return nil, false, &Declined{Reason: fmt.Sprintf("line %d of %s no longer has this finding and the file has %d like it; rescan and fix the new findings", line, file, len(moved))}
		}
	}
	if len(at) > 0 {
		// Several identical findings on one line: the first; the rest
		// come back on the next scan.
		return &at[0], false, nil
	}
	// Not there. That is "gone" only when the scan checked it and this
	// rescan checked the same again.
	if rule == RuleNotChecked {
		now := ""
		for _, g := range fs {
			if g.Line == line && g.Level != "note" {
				now = fmt.Sprintf(", and line %d now has %s (%s)", line, g.Rule, g.Message)
				break
			}
		}
		return nil, false, notChecked("%s:%d was not checked when it was scanned%s", file, line, now)
	}
	for _, sk := range skips {
		if blocksYocto(sk, msg) {
			what := sk.Reason
			if sk.File != "" {
				what = fmt.Sprintf("%s could not be read this time (%s)", sk.File, sk.Reason)
			}
			return nil, false, notChecked("%s, so %s is not checked", what, file)
		}
	}
	k := keyOf(msg)
	for _, g := range fs {
		switch {
		case g.Rule == RuleNotChecked && k.holds(g):
			// The same package, variable or build system, anywhere in
			// the file: this rescan could not judge it.
			return nil, false, notChecked("%s:%d is not checked this time (%s)", file, g.Line, g.Message)
		case g.Level != "note" && k.pkg != "" && g.Props["package"] == k.pkg && g.Line == line:
			// The same package under another rule (a pin loosened, an
			// end-of-life base no longer known as one).
			return nil, false, notChecked("line %d of %s now has %s (%s)", line, file, g.Rule, g.Message)
		case rule == RuleBuild && g.Rule == RuleBuild && k.system != "" && g.Props["system"] == k.system && g.Props["package"] == k.pkg:
			// One build finding per file and system: moved and reworded.
			return nil, false, notChecked("%s:%d still has %s (%s)", file, g.Line, g.Rule, g.Message)
		}
	}
	if line > len(strings.Split(string(data), "\n")) {
		for _, g := range fs {
			if g.Rule == rule {
				return nil, false, notChecked("line %d is past the end of %s, which changed since the scan and still has %s findings", line, file, rule)
			}
		}
	}
	return nil, true, nil
}

// findRules are the rules a rescan of one file produces.
var findRules = map[string]bool{RulePin: true, RuleUnpinned: true, RuleEOL: true, RuleStar: true, RulePassword: true,
	RuleNotChecked: true, RuleAnsible: true, RuleBuild: true}

var (
	lineRefRE = regexp.MustCompile(`, set on line \d+\)`)
	viaRE     = regexp.MustCompile(`\(through \$([A-Za-z_][A-Za-z0-9_]*)`)
	tclibcRE  = regexp.MustCompile(` and (\S+):\d+ sets TCLIBC`)
)

// findKey is what a finding's message names: the OpenSSH package, the
// variable it came through, the build system.
type findKey struct{ pkg, via, system string }

func keyOf(msg string) findKey {
	var k findKey
	w := strings.Fields(msg)
	if len(w) >= 2 && (w[0] == "installs" || w[0] == "pins") {
		if m := specRE.FindStringSubmatch(strings.Trim(w[1], `'"`)); m != nil && sshPackages[m[1]] {
			k.pkg = m[1]
		}
	}
	if m := viaRE.FindStringSubmatch(msg); m != nil {
		k.via = m[1]
	}
	switch {
	case strings.HasPrefix(msg, "Buildroot "):
		k.system = "buildroot"
	case strings.HasPrefix(msg, "Yocto "):
		k.system = "yocto"
	case strings.HasPrefix(msg, "OpenWrt configuration builds ") && len(w) >= 4:
		k.system, k.pkg = "openwrt", w[3]
	}
	return k
}

// holds reports whether a not-checked finding is about what k names.
func (k findKey) holds(g Finding) bool {
	if k.pkg != "" && g.Props["package"] == k.pkg || k.system != "" && g.Props["system"] == k.system {
		return true
	}
	if k.via == "" {
		return false
	}
	m := varRE.FindStringSubmatch(g.Props["spec"])
	return m != nil && (m[1] == k.via || m[3] == k.via)
}

// blocksYocto reports whether a file the Yocto rescan could not read may
// hide the finding: the TCLIBC setting its message names, or a directory
// holding it. Without that reference, any build file or directory.
func blocksYocto(sk Skip, msg string) bool {
	if sk.File == "" {
		return true // the tree past the walk's limit
	}
	if m := tclibcRE.FindStringSubmatch(msg); m != nil {
		return sk.File == m[1] || strings.HasPrefix(m[1], sk.File+"/")
	}
	k := kindOf(sk.File)
	return k == "build" || k == ""
}

// notChecked declines a finding Find cannot confirm as gone.
func notChecked(format string, args ...any) error {
	return &Declined{Reason: fmt.Sprintf(format, args...) + "; rescan to confirm"}
}

// WriteNewFiles writes files a change adds, refusing symbolic links on
// the way and any file that exists with other content.
func WriteNewFiles(root string, files map[string][]byte) error {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	// Check every path before writing anything, so a refusal leaves no
	// partial change behind.
	for _, rel := range paths {
		if err := checkNewPath(root, rel, files[rel]); err != nil {
			return err
		}
	}
	for _, rel := range paths {
		data := files[rel]
		// Create the directories one by one, refusing any symbolic link on
		// the way, then check the whole path again. Another writer (a
		// parallel fix of a sibling file) may create the same directories
		// and files: identical content already there is success.
		if err := mkdirsNoLinks(root, path.Dir(path.Clean(rel))); err != nil {
			return err
		}
		p, err := refs.SafePath(root, rel)
		if err != nil {
			return err
		}
		if same, err := sameFile(p, data); err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		} else if same {
			continue
		}
		// Write a temporary file, then link it into place: the link fails
		// rather than replace a file, and a reader never sees half a file.
		tmp, err := os.CreateTemp(filepath.Dir(p), ".earlylight-new-*")
		if err != nil {
			return err
		}
		name := tmp.Name()
		_, werr := tmp.Write(data)
		cerr := tmp.Close()
		if werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Chmod(name, 0o644)
		}
		if werr != nil {
			os.Remove(name)
			return werr
		}
		lerr := os.Link(name, p)
		os.Remove(name)
		if errors.Is(lerr, os.ErrExist) {
			if same, serr := sameFile(p, data); serr == nil && same {
				continue
			}
			return fmt.Errorf("%s exists with other content", rel)
		}
		if lerr != nil {
			return lerr
		}
	}
	return nil
}

// sameFile reports whether a regular file with exactly data is at p; an
// error when something else is there.
func sameFile(p string, data []byte) (bool, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, errors.New("exists and is not a regular file")
	}
	cur, err := os.ReadFile(p)
	if err != nil {
		return false, err
	}
	if string(cur) != string(data) {
		return false, errors.New("exists with other content")
	}
	return true, nil
}

// checkNewPath refuses a path outside the repository, inside .git, or
// through a symbolic link that already exists, and an existing file with
// other content.
func checkNewPath(root, rel string, data []byte) error {
	clean := path.Clean(rel)
	if rel == "" || path.IsAbs(rel) || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(rel, "\\") {
		return fmt.Errorf("%q leaves the repository", rel)
	}
	for _, part := range strings.Split(clean, "/") {
		if strings.EqualFold(part, ".git") {
			return fmt.Errorf("%q is inside .git", rel)
		}
	}
	cur := root
	parts := strings.Split(clean, "/")
	for i, e := range parts {
		cur = filepath.Join(cur, e)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil // the rest is created
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%q passes through a symbolic link", rel)
		}
		if i == len(parts)-1 {
			if _, err := sameFile(cur, data); err != nil {
				return fmt.Errorf("%s %w", rel, err)
			}
		} else if !fi.IsDir() {
			return fmt.Errorf("%q: %s is not a directory", rel, path.Join(parts[:i+1]...))
		}
	}
	return nil
}

func mkdirsNoLinks(root, dir string) error {
	if dir == "." || dir == "" {
		return nil
	}
	if path.IsAbs(dir) || dir == ".." || strings.HasPrefix(dir, "../") {
		return fmt.Errorf("%q leaves the repository", dir)
	}
	cur := root
	for _, e := range strings.Split(dir, "/") {
		cur = filepath.Join(cur, e)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			if fi, err := os.Lstat(cur); err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%s could not be created as a directory", cur)
			}
		case err != nil:
			return err
		case fi.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s passes through a symbolic link", dir)
		case !fi.IsDir():
			return fmt.Errorf("%s is not a directory", cur)
		}
	}
	return nil
}
