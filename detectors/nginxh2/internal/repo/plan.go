package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// The planning here follows java4shell's (internal/repo/plan.go on that
// branch): one edit to one line, checked by rescanning the edited file in
// memory, applied only when the line still reads as planned.

// Change is one line edit to a repository file.
type Change struct {
	File    string
	Line    int
	Old     string // the whole line, as it was
	New     string
	Summary string
}

// Declined is a plan that proposes no change, with the reason.
type Declined struct{ Reason string }

func (d *Declined) Error() string { return d.Reason }

func declined(format string, args ...any) error {
	return &Declined{Reason: refs.CleanText(fmt.Sprintf(format, args...), 1500)}
}

// Registry is what planning a tag move needs: the tags of a repository,
// and a check that the target holds only fixed nginx builds on every
// platform the current tag has, on the same base OS (returning its
// digest).
type Registry struct {
	Tags   func(ctx context.Context, repo string) ([]string, error)
	Verify func(ctx context.Context, current, target string) (string, error)
}

// Plan finds the edit that fixes a finding, checks it by rescanning the
// edited file in memory, and returns it without writing anything.
func Plan(ctx context.Context, root string, f Finding, reg Registry, opts Options) (*Change, error) {
	if f.Fixable && f.pin != nil {
		return planPin(ctx, root, f, opts)
	}
	if !f.Fixable || f.edit == nil {
		return nil, declined("%s", f.Fix)
	}
	e, r := f.edit, f.ref
	if r == nil {
		return nil, declined("the image reference was not located; rescan to confirm")
	}
	if reg.Tags == nil || reg.Verify == nil {
		return nil, declined("moving %s needs the registry, which this run does not use; change it by hand to %s", e.image, e.target)
	}
	if strings.Contains(e.image, "@") {
		return nil, declined("%s is pinned by digest; change the tag and digest by hand (to %s and its digest)", e.image, e.target)
	}
	repoName, tag, _ := splitImage(e.image)
	start := refs.TagStart(e.image)
	if start < 0 || e.image[start:] != tag {
		return nil, declined("the tag of %s cannot be retagged automatically; change it to %s by hand", e.image, e.target)
	}
	tags, err := reg.Tags(ctx, repoName)
	if err != nil {
		return nil, declined("the tags of %s could not be listed (%v): not checked; try again later, or change it to %s by hand", repoName, err, e.target)
	}
	if !contains(tags, e.target) {
		return nil, declined("%s has not published %s yet (the registry was checked); move to it when it does", repoName, e.target)
	}
	newImage := e.image[:start] + e.target
	// The part of the reference that holds the whole tag, where it is
	// written.
	off := 0
	var part *refs.Part
	for i := range r.Parts {
		p := &r.Parts[i]
		if off <= start && off+len(p.Text) >= len(e.image) {
			part = p
			break
		}
		off += len(p.Text)
	}
	if part == nil || part.Column == 0 || part.Line == 0 {
		return nil, declined("the tag of %s is not written in one place this fix can edit; change it to %s by hand", e.image, e.target)
	}
	file := part.File
	if file == "" {
		file = r.File
	}
	col := part.Column - 1 + (start - off)
	if part.Var != "" {
		if n, err := varUses(root, r.File, part.Var, opts); err != nil || n > 1 {
			return nil, declined("%s gets its tag from %s, which %s uses in more than one place; change it by hand", e.image, part.Var, r.File)
		}
		if file != r.File {
			if other, err := varUsedBeside(root, file, r.File, part.Var, opts); err != nil || other != "" {
				return nil, declined("%s gets its tag from %s in %s, which %s uses too; change it by hand", e.image, part.Var, file, other)
			}
		}
	}
	digest, err := reg.Verify(ctx, e.image, newImage)
	if err != nil {
		var d *Declined
		if errors.As(err, &d) {
			return nil, err
		}
		return nil, declined("%s could not be verified (%v): not checked; try again later, or change it by hand", newImage, err)
	}
	where := ""
	if part.Var != "" {
		where = fmt.Sprintf(" (in the value of %s)", part.Var)
	}
	return planLine(ctx, root, f, file, part.Line, col, tag, e.target, opts,
		fmt.Sprintf("Changes the image %s to %s on line %d of %s%s: the first release of the same line and variant with the fix for CVE-2026-123007 and CVE-2026-123633, read and judged on the platforms it is built for (the FROM line's --platform, else the --platform list, else linux/amd64 and linux/arm64) and published for each of them, on the same base OS (index digest %s). Rebuild and redeploy.",
			e.image, newImage, part.Line, file, where, digest))
}

// planPin moves a package pin to the fixed package: the pin must be
// written once in the RUN instruction (its first line and the lines it
// continues onto).
func planPin(ctx context.Context, root string, f Finding, opts Options) (*Change, error) {
	b, ok := opts.Overlay[f.File]
	if !ok {
		var err error
		if b, err = readFile(root, f.File); err != nil {
			return nil, declined("%s could not be read: %v", f.File, err)
		}
	}
	ls := strings.Split(string(b), "\n")
	type hit struct{ line, col int }
	var hits []hit
	for i := f.Line - 1; i >= 0 && i < len(ls) && i < f.Line-1+200; i++ {
		l := strings.TrimSuffix(ls[i], "\r")
		for off := 0; ; {
			j := strings.Index(l[off:], f.pin.old)
			if j < 0 {
				break
			}
			c := off + j
			end := c + len(f.pin.old)
			if (c == 0 || strings.ContainsRune(" \t'\"", rune(l[c-1]))) && (end == len(l) || strings.ContainsRune(" \t'\";&|\\", rune(l[end]))) {
				hits = append(hits, hit{i + 1, c})
			}
			off = end
		}
		if !strings.HasSuffix(strings.TrimRight(l, " \t"), "\\") {
			break
		}
	}
	if len(hits) != 1 {
		return nil, declined("the pin %s is not written once in the instruction at line %d; change it to %s by hand", f.pin.old, f.Line, f.pin.repl)
	}
	return planLine(ctx, root, f, f.File, hits[0].line, hits[0].col, f.pin.old, f.pin.repl, opts,
		fmt.Sprintf("Changes the package pin %s to %s on line %d of %s: the fixed nginx package on Alpine %s (APKINDEX, %s). Rebuild.", f.pin.old, f.pin.repl, hits[0].line, f.File, f.pin.branch, knowledge.Checked))
}

// planLine replaces old with repl at col on a line and rescans in memory:
// the finding must be gone and nothing new may appear.
func planLine(ctx context.Context, root string, f Finding, file string, line, col int, old, repl string, opts Options, summary string) (*Change, error) {
	b, ok := opts.Overlay[file]
	if !ok {
		var err error
		if b, err = readFile(root, file); err != nil {
			return nil, declined("%s could not be read: %v", file, err)
		}
	}
	ls := strings.Split(string(b), "\n")
	if line < 1 || line > len(ls) {
		return nil, declined("line %d of %s is gone; rescan to confirm", line, file)
	}
	cur := strings.TrimSuffix(ls[line-1], "\r")
	if col < 0 || col+len(old) > len(cur) || cur[col:col+len(old)] != old {
		return nil, declined("line %d of %s no longer reads as the scan found it; rescan to confirm", line, file)
	}
	newLine := cur[:col] + repl + cur[col+len(old):]
	cr := ""
	if strings.HasSuffix(ls[line-1], "\r") {
		cr = "\r"
	}
	edited := append([]string(nil), ls...)
	edited[line-1] = newLine + cr
	over := map[string][]byte{}
	for k, v := range opts.Overlay {
		over[k] = v
	}
	over[file] = []byte(strings.Join(edited, "\n"))
	before, err := Scan(ctx, root, Options{Overlay: opts.Overlay})
	if err != nil {
		return nil, err
	}
	after, err := Scan(ctx, root, Options{Overlay: over})
	if err != nil {
		return nil, err
	}
	key := func(x Finding) string { return x.Rule + "|" + x.File + "|" + x.Props["image"] + "|" + string(x.Status) }
	had := map[string]int{}
	for _, x := range before.Findings {
		had[key(x)]++
	}
	for _, x := range after.Findings {
		if x.File == f.File && x.Line == f.Line && x.Rule == f.Rule && x.Props["image"] == f.Props["image"] {
			return nil, declined("after the edit, line %d of %s still names a release without the fix; change it by hand", f.Line, f.File)
		}
		if had[key(x)] == 0 && x.Level != "note" {
			return nil, declined("the edit would add a new finding (%s at %s:%d); change it by hand", x.Message, x.File, x.Line)
		}
		had[key(x)]--
	}
	if len(after.Skips) > len(before.Skips) {
		return nil, declined("after the edit, %s no longer reads cleanly; change it by hand", file)
	}
	return &Change{File: file, Line: line, Old: cur, New: newLine, Summary: refs.CleanText(summary, 800)}, nil
}

// Apply writes a change after checking the line still reads as planned. It
// keeps the file's mode and line ending and writes atomically.
func Apply(root string, ch *Change) error {
	p, err := refs.SafePath(root, ch.File)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", ch.File)
	}
	b, err := readFile(root, ch.File)
	if err != nil {
		return err
	}
	ls := strings.Split(string(b), "\n")
	if ch.Line < 1 || ch.Line > len(ls) || strings.TrimSuffix(ls[ch.Line-1], "\r") != ch.Old {
		return fmt.Errorf("%s changed since the plan: line %d no longer reads as planned", ch.File, ch.Line)
	}
	cr := ""
	if strings.HasSuffix(ls[ch.Line-1], "\r") {
		cr = "\r"
	}
	ls[ch.Line-1] = ch.New + cr
	tmp, err := os.CreateTemp(filepath.Dir(p), ".earlylight-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.WriteString(strings.Join(ls, "\n")); err != nil {
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

// Diff shows a change.
func Diff(ch *Change) string {
	return fmt.Sprintf("@@ %s line %d @@\n- %s\n+ %s\n", Printable(ch.File), ch.Line, Printable(ch.Old), Printable(ch.New))
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

// varUses counts the places a file uses a variable ($VAR, ${VAR}).
func varUses(root, file, name string, opts Options) (int, error) {
	b, ok := opts.Overlay[file]
	if !ok {
		var err error
		if b, err = readFile(root, file); err != nil {
			return 0, err
		}
	}
	re := regexp.MustCompile(`\$\{?` + regexp.QuoteMeta(name) + `\b`)
	return len(re.FindAllIndex(b, -1)), nil
}

// varUsedBeside names another file in the directory of def (the file that
// sets a variable, a .env) that uses the variable too.
func varUsedBeside(root, def, user, name string, opts Options) (string, error) {
	dir, p := path.Dir(def), root
	if dir != "." {
		var err error
		if p, err = refs.SafePath(root, dir); err != nil {
			return "", err
		}
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		rel := path.Join(dir, e.Name())
		if !e.Type().IsRegular() || rel == def || rel == user || kindOf(rel) != "yaml" && kindOf(rel) != "dockerfile" {
			continue
		}
		if n, err := varUses(root, rel, name, opts); err != nil {
			return rel, err
		} else if n > 0 {
			return rel, nil
		}
	}
	return "", nil
}

// SameBase compares the base OS of the current image and its replacement
// ("ID VERSION_ID" of os-release) on the distribution and its major
// version (Ubuntu on its full VERSION_ID): Debian 12 to 13 is not this
// fix's call, while Alpine 3.23 to 3.24 is what a rebuilt "-alpine" tag
// brings anyway.
func SameBase(current, target string) error {
	major := func(s string) string {
		id, ver, _ := strings.Cut(s, " ")
		if id != "ubuntu" {
			ver, _, _ = strings.Cut(ver, ".")
		}
		return id + " " + ver
	}
	switch {
	case current == "" || target == "":
		return declined("the base OS of the current or the new image could not be read; change it by hand")
	case major(current) != major(target):
		return declined("the new image is on %s, the current one on %s; change it by hand", refs.CleanText(target, 80), refs.CleanText(current, 80))
	}
	return nil
}

// NamesBaseOS reports whether a tag's variant names its base OS.
func NamesBaseOS(variant string) bool {
	v := strings.ToLower(variant)
	for _, w := range []string{"alpine", "trixie", "bookworm", "bullseye", "debian", "jammy", "noble", "ubuntu", "ubi", "alma", "rocky"} {
		if strings.Contains(v, w) {
			return true
		}
	}
	return false
}
