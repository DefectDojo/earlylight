package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// Change is a set of edits to one repository file.
type Change struct {
	File    string
	Edits   []Edit
	Summary string
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
	if !f.Fixable || f.edit == nil {
		return nil, false, &Declined{Reason: f.Fix}
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
	ch := &Change{File: f.File, Edits: []Edit{{Line: e.Line, Col: e.Col, Old: line, New: newLine}}, Summary: summary(f)}

	// Rescan the edited file in memory.
	edited := append([]string{}, lines...)
	cr := ""
	if strings.HasSuffix(lines[e.Line-1], "\r") {
		cr = "\r"
	}
	edited[e.Line-1] = newLine + cr
	o := opts
	o.Overlay = map[string][]byte{f.File: []byte(strings.Join(edited, "\n"))}
	before, err := scanOne(ctx, root, f.File, opts, nil)
	if err != nil {
		return nil, false, err
	}
	after, err := scanOne(ctx, root, f.File, o, o.Overlay[f.File])
	if err != nil {
		return nil, false, err
	}
	if count(after, f.Rule, e.Line) >= count(before, f.Rule, e.Line) {
		return nil, false, &Declined{Reason: "the edit did not clear the finding; change it by hand"}
	}
	if len(after) > len(before) {
		return nil, false, &Declined{Reason: "the edit raised a new finding; change it by hand"}
	}
	return ch, false, nil
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
	}
	return f.Fix
}

// Apply writes a change after checking each edited line still reads as
// planned. It keeps line endings and the file mode, and writes atomically.
func Apply(root string, ch *Change) error {
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
