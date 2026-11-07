package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
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
// new appeared. already is true when the finding is no longer there.
func Plan(ctx context.Context, root string, f Finding, opts Options) (*Change, bool, error) {
	if !f.Fixable || f.edit == nil && len(f.newFiles) == 0 {
		return nil, false, &Declined{Reason: f.Fix}
	}
	for p, data := range f.newFiles {
		if err := checkNewPath(root, p, data); err != nil {
			return nil, false, &Declined{Reason: err.Error() + "; add the fix by hand"}
		}
	}
	if f.edit == nil {
		return planNewFiles(ctx, root, f, opts)
	}
	b, err := readFile(root, f.File)
	if err != nil {
		return nil, false, err
	}
	lines := strings.Split(string(b), "\n")
	e := *f.edit
	if e.Line < 1 || e.Line > len(lines) {
		return nil, true, nil
	}
	line := strings.TrimSuffix(lines[e.Line-1], "\r")
	if e.Col < 0 || e.Col+len(e.Old) > len(line) || line[e.Col:e.Col+len(e.Old)] != e.Old {
		// An earlier edit on the same line moves the word: rescan and take
		// the one finding that is still the same word, or decline.
		now, err := scanOne(ctx, root, f.File, opts, b)
		if err != nil {
			return nil, false, err
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
			return nil, false, &Declined{Reason: fmt.Sprintf("%s:%d no longer reads as scanned", f.File, e.Line)}
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
		return nil, false, err
	}
	after, err := scanOne(ctx, root, f.File, o, o.Overlay[f.File])
	if err != nil {
		return nil, false, err
	}
	if count(after, f.Rule, f.Line) >= count(before, f.Rule, f.Line) {
		return nil, false, &Declined{Reason: "the edit did not clear the finding; change it by hand"}
	}
	if len(after) > len(before) {
		return nil, false, &Declined{Reason: "the edit raised a new finding; change it by hand"}
	}
	return ch, false, nil
}

// planNewFiles plans a fix that only adds files, checked by rescanning the
// finding's file with the files in place.
func planNewFiles(ctx context.Context, root string, f Finding, opts Options) (*Change, bool, error) {
	o := opts
	o.Overlay = map[string][]byte{}
	for p, data := range f.newFiles {
		o.Overlay[p] = data
	}
	before, err := scanOne(ctx, root, f.File, opts, nil)
	if err != nil {
		return nil, false, err
	}
	after, err := scanOne(ctx, root, f.File, o, nil)
	if err != nil {
		return nil, false, err
	}
	if count(after, f.Rule, f.Line) >= count(before, f.Rule, f.Line) {
		return nil, false, &Declined{Reason: "the added files did not clear the finding; add the fix by hand"}
	}
	return &Change{File: f.File, Summary: summary(f), NewFiles: f.newFiles}, false, nil
}

func scanOne(ctx context.Context, root, file string, opts Options, data []byte) ([]Finding, error) {
	s := &scanner{ctx: ctx, root: root, opts: opts, bases: map[string]baseInfo{}}
	if data == nil {
		var err error
		if data, err = readFile(root, file); err != nil {
			return nil, err
		}
	}
	switch kindOf(file) {
	case "dockerfile":
		return s.dockerfile(file, string(data)), nil
	case "shell":
		return s.script(file, string(data)), nil
	case "yaml":
		return s.yaml(file, string(data)), nil
	case "sshd_config":
		return s.sshdConfig(file, string(data)), nil
	case "build":
		// A Yocto finding needs the whole tree (TCLIBC and bbappends live
		// in other files): rescan it, keeping this file's findings.
		if s.yoctoNeedsTree(file) {
			res, err := Scan(ctx, root, opts)
			if err != nil {
				return nil, err
			}
			var out []Finding
			for _, f := range res.Findings {
				if f.File == file {
					out = append(out, f)
				}
			}
			return out, nil
		}
		s.build(file, string(data))
		return s.finishBuild(), nil
	}
	return nil, nil
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
// line. spec, when not empty, picks between several on the line: the apk
// spec or the text the finding's message quotes. gone is true when the file
// has no such finding any more.
func Find(ctx context.Context, root, file string, line int, rule, message string, opts Options) (f *Finding, gone bool, err error) {
	fs, err := scanOne(ctx, root, file, opts, nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, err
	}
	var at []Finding
	for _, g := range fs {
		if g.Rule == rule && g.Line == line {
			at = append(at, g)
		}
	}
	if len(at) > 1 && message != "" {
		var picked []Finding
		for _, g := range at {
			if strings.Contains(message, g.Message) || g.Props["spec"] != "" && strings.Contains(message, g.Props["spec"]) {
				picked = append(picked, g)
			}
		}
		if len(picked) > 0 {
			at = picked
		}
	}
	if len(at) == 0 && message != "" {
		// The line moved (an edit above it): the same finding elsewhere in
		// the file, when there is exactly one, is still this finding.
		var moved []Finding
		for _, g := range fs {
			if g.Rule == rule && strings.Contains(message, g.Message) {
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
	switch len(at) {
	case 0:
		return nil, true, nil
	case 1:
		return &at[0], false, nil
	}
	// Several identical findings on one line: the first; the rest come
	// back on the next scan.
	return &at[0], false, nil
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
