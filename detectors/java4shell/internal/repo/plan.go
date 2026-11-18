package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

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

// Registry is what planning an image move needs from a registry: the tags
// of a repository, and a check that a target image holds only fixed
// runtimes on every platform the current one has (returning its digest).
type Registry struct {
	Tags   func(ctx context.Context, repo string) ([]string, error)
	Verify func(ctx context.Context, current, target string) (string, error)
}

// Plan finds the edit that fixes a finding, checks it by rescanning the
// edited file in memory, and returns it without writing anything.
func Plan(ctx context.Context, root string, f Finding, reg Registry, opts Options) (*Change, error) {
	if !f.Fixable || f.edit == nil {
		return nil, declined("%s", f.Fix)
	}
	switch f.edit.kind {
	case "tag":
		return planTag(ctx, root, f, reg, opts)
	case "setup-java":
		return planLine(ctx, root, f, f.edit.file, f.edit.line, f.edit.col, f.edit.old, fmt.Sprint(f.edit.feature), opts,
			fmt.Sprintf("Sets setup-java's java-version from %s to %d on line %d of %s: the %s distribution's newest Java %d release has the Java4Shell fix (%s), and setup-java installs it when the job runs.",
				f.edit.old, f.edit.feature, f.edit.line, f.edit.file, f.Props["distribution"], f.edit.feature, knowledge.FixedVersion(f.edit.feature)))
	}
	return nil, declined("no automatic fix for this finding")
}

// target picks the first published tag of the same family, variant and
// style that has the fix.
func target(tags []string, e *pinEdit) (string, bool) {
	type cand struct {
		tag    string
		tv     TagVersion
		moving bool
	}
	fixed, _ := knowledge.LineOf(e.feature)
	var cs []cand
	for _, t := range tags {
		tv, ok := e.family.ParseTag(t)
		if !ok || tv.Variant != e.tv.Variant || tv.Exact != e.tv.Exact || tv.Nums[0] != e.feature || len(tv.Nums) < 3 {
			continue
		}
		switch st, _ := JudgeTag(tv); {
		case st == knowledge.Fixed:
			cs = append(cs, cand{t, tv, false})
		case !tv.Exact && fixed.Fixed != nil && len(tv.Nums) == 3 && knowledge.Compare(tv.Nums, fixed.Fixed[:3]) == 0:
			// A moving tag of the fixed update (Corretto republishes
			// "21.0.13" with 21.0.13.1.2): only reading the image shows
			// which release it holds, and Verify does.
			cs = append(cs, cand{t, tv, true})
		}
	}
	if len(cs) == 0 {
		return "", false
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].moving != cs[j].moving {
			return !cs[i].moving
		}
		if c := knowledge.Compare(cs[i].tv.Nums, cs[j].tv.Nums); c != 0 {
			return c < 0
		}
		return buildNum(cs[i].tv.Build) < buildNum(cs[j].tv.Build)
	})
	return cs[0].tag, true
}

// buildNum is the number in a tag's build part ("_10", "-9"), so _10 sorts
// after _2.
func buildNum(b string) int {
	n := 0
	fmt.Sscanf(strings.TrimLeft(b, "_-"), "%d", &n)
	return n
}

func planTag(ctx context.Context, root string, f Finding, reg Registry, opts Options) (*Change, error) {
	e, r := f.edit, f.ref
	if r == nil {
		return nil, declined("the image reference was not located")
	}
	if reg.Tags == nil || reg.Verify == nil {
		return nil, declined("moving %s needs the registry, which this run does not use; change it by hand", e.image)
	}
	if strings.Contains(e.image, "@") {
		return nil, declined("%s is pinned by digest; change the tag and digest by hand", e.image)
	}
	repo, tag := repoName(e.image)
	start := refs.TagStart(e.image)
	if start < 0 || e.image[start:] != tag {
		return nil, declined("the tag of %s cannot be retagged automatically", e.image)
	}
	tags, err := reg.Tags(ctx, strings.TrimSuffix(e.image[:start], ":"))
	if err != nil {
		return nil, declined("the tags of %s could not be listed (%v); try again later, or change it by hand", repo, err)
	}
	newTag, ok := target(tags, e)
	if !ok {
		return nil, declined("%s has no published tag of Java %s or later with the variant %q yet (the registry was checked); move to it when %s publishes it", repo, knowledge.FixedVersion(e.feature), strings.TrimPrefix(e.tv.Variant, "-"), e.family.Vendor)
	}
	newImage := e.image[:start] + newTag
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
		return nil, declined("the tag of %s is not written in one place this fix can edit; change it by hand", e.image)
	}
	file := part.File
	if file == "" {
		file = r.File
	}
	col := part.Column - 1 + (start - off)
	if _, err := reg.Verify(ctx, e.image, newImage); err != nil {
		var d *Declined
		if errors.As(err, &d) {
			return nil, err
		}
		return nil, declined("%s could not be verified (%v); try again later, or change it by hand", newImage, err)
	}
	where := ""
	if part.Var != "" {
		where = fmt.Sprintf(" (in the value of %s)", part.Var)
	}
	return planLine(ctx, root, f, file, part.Line, col, tag, newTag, opts,
		fmt.Sprintf("Changes the image %s to %s on line %d of %s%s: the %s release of the same variant with the Java4Shell fix, read and checked on every platform the current tag has. Rebuild and redeploy.",
			e.image, newImage, part.Line, file, where, e.family.Vendor))
}

// planLine replaces old with repl at col on a line and rescans the file in
// memory: the finding must be gone and nothing new may appear.
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
		return nil, declined("line %d of %s is gone; rescan", line, file)
	}
	cur := strings.TrimSuffix(ls[line-1], "\r")
	if col < 0 || col+len(old) > len(cur) || cur[col:col+len(old)] != old {
		return nil, declined("line %d of %s no longer reads as the scan found it; rescan", line, file)
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
	before, err := Scan(ctx, root, Options{Overlay: opts.Overlay, Platforms: opts.Platforms})
	if err != nil {
		return nil, err
	}
	after, err := Scan(ctx, root, Options{Overlay: over, Platforms: opts.Platforms})
	if err != nil {
		return nil, err
	}
	key := func(x Finding) string {
		return x.Rule + "|" + x.File + "|" + x.Props["image"] + "|" + x.Props["current"] + "|" + x.Status
	}
	had := map[string]int{}
	for _, x := range before.Findings {
		had[key(x)]++
	}
	for _, x := range after.Findings {
		if x.File == f.File && x.Line == f.Line && x.Rule == f.Rule && x.Status != StatusMitigated {
			return nil, declined("after the edit, line %d of %s still selects a release without the fix; change it by hand", f.Line, f.File)
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

// Mitigation is the optional interim edit for a Dockerfile whose image runs
// a vulnerable runtime that cannot be updated here (a product's bundled
// runtime): the line to add after the FROM line. fix prints it and does not
// apply it.
func Mitigation(file string, line int) string {
	return fmt.Sprintf("%s: after line %d add\n    ENV JAVA_TOOL_OPTIONS=\"-XX:-UseBASE64Intrinsics\"\n  (append to any JAVA_TOOL_OPTIONS the image already sets; this keeps the vulnerable decoder from being generated until the product ships a fixed runtime)", file, line)
}
