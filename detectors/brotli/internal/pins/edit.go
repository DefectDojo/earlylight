package pins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// Edit replaces the len(Old) lines starting at Line (1-based) with New.
type Edit struct {
	Line int
	Old  []string // exact lines, without line endings
	New  []string
}

// Change is a set of edits to one repository file.
type Change struct {
	File    string // repository-relative, slash-separated
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

// maxEditSize bounds the files a change rewrites.
const maxEditSize = 64 << 20

// readFile returns a repository file's content for planning: never through a
// symbolic link, never outside root, only a regular file.
func readFile(root, file string) ([]byte, error) {
	p, err := refs.SafePath(root, file)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxEditSize {
		return nil, fmt.Errorf("%s is not a regular file this fix rewrites", file)
	}
	return os.ReadFile(p)
}

// Apply writes a change, after checking every edited line still reads as
// planned. It keeps the file's line endings and mode and writes atomically.
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
	// Each line keeps its own ending: a file with mixed endings changes only
	// on the edited lines.
	lines := strings.Split(string(b), "\n")
	ending := func(l string) string {
		if strings.HasSuffix(l, "\r") {
			return "\r"
		}
		return ""
	}
	for k := len(ch.Edits) - 1; k >= 0; k-- {
		e := ch.Edits[k]
		if e.Line < 1 || e.Line-1+len(e.Old) > len(lines) {
			return fmt.Errorf("%s changed since the plan: line %d is gone", ch.File, e.Line)
		}
		cr := ""
		if e.Line-1 < len(lines) {
			cr = ending(lines[e.Line-1])
		}
		for i, o := range e.Old {
			if strings.TrimSuffix(lines[e.Line-1+i], "\r") != o {
				return fmt.Errorf("%s changed since the plan: line %d no longer reads as planned", ch.File, e.Line+i)
			}
		}
		repl := make([]string, len(e.New))
		for i, n := range e.New {
			repl[i] = n + cr
		}
		lines = append(lines[:e.Line-1], append(repl, lines[e.Line-1+len(e.Old):]...)...)
	}
	out := strings.Join(lines, "\n")
	tmp, err := os.CreateTemp(filepath.Dir(p), ".earlylight-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(out); err != nil {
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
		fmt.Fprintf(&b, "@@ %s line %d @@\n", Printable(ch.File), e.Line)
		for _, o := range e.Old {
			b.WriteString("- " + Printable(o) + "\n")
		}
		for _, n := range e.New {
			b.WriteString("+ " + Printable(n) + "\n")
		}
	}
	return b.String()
}

// Printable shows repository text safely on a terminal: control and format
// characters (escape sequences, a bare carriage return) become \uXXXX, and
// spacing is kept.
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
