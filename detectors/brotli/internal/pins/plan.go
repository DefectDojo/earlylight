package pins

import (
	"context"
	"fmt"
	"strings"
)

// VerifyImage proves an image change before it is planned: target must hold
// no Brotli decoder without the fix on every platform current has (and be
// published for all of them). It returns target's digest. The detector sets
// it (pulling and scanning the image); nil declines every image change.
var VerifyImage func(ctx context.Context, current, target string) (digest string, err error)

func declined(format string, args ...any) error {
	return &Declined{Reason: clean(fmt.Sprintf(format, args...), 1500)}
}

// Plan re-scans file, finds the pin the finding at line names (narrowed by
// props source and current when given), and plans the one-line edit to the
// fixed release. The edit is verified by scanning the edited file again in
// memory: the pin must be fixed and nothing else may change. An image tag is
// changed only to a tag the registry shows is published for every platform
// the current one has, on the same base OS. It writes nothing.
func Plan(ctx context.Context, root, file string, line int, rule string, props map[string]string) (*Change, bool, error) {
	before, err := scanPins(ctx, root, []string{file}, Options{})
	if err != nil {
		return nil, false, err
	}
	p, found, err := choose(before, file, line, rule, props)
	if err != nil {
		return nil, false, err
	}
	if !found {
		for _, sk := range before.skips {
			if sk.File == file {
				// Not read this time (too large, not parseable): nothing is
				// known about the pin, so it is not "already fixed".
				return nil, false, declined("%s was not read: %s", file, sk.Reason)
			}
		}
		return nil, true, nil
	}
	f := p.finding()
	switch {
	case f.Level == "note":
		return nil, false, declined("%s", f.Fix)
	case !f.Fixable:
		return nil, false, declined("%s", f.Fix)
	}
	content, err := readFile(root, p.editFile)
	if err != nil {
		return nil, false, declined("%s could not be read: %v", p.editFile, err)
	}
	lines := splitLines(content)
	if p.editLine < 1 || p.editLine > len(lines) {
		return nil, false, declined("line %d of %s is gone; rescan", p.editLine, p.editFile)
	}
	old := strings.TrimSuffix(lines[p.editLine-1], "\r")
	if p.col < 0 || p.col+len(p.j.current) > len(old) || old[p.col:p.col+len(p.j.current)] != p.j.current {
		return nil, false, declined("the version on line %d of %s is not where the scan found it; rescan", p.editLine, p.editFile)
	}
	to := p.j.fixed
	if p.j.vd == noFixLine {
		to, _ = upgrade(p)
	}
	repl := old[:p.col] + to + old[p.col+len(p.j.current):]

	var newImage string
	if p.image != "" {
		var oldDigest, newDigest string
		if newImage, oldDigest, newDigest, err = verifyImage(ctx, p, to); err != nil {
			return nil, false, err
		}
		if oldDigest != "" {
			// A tag@digest pin: the new tag's digest replaces the old one.
			if strings.Count(repl, oldDigest) != 1 || newDigest == "" {
				return nil, false, declined("the digest of %s is not on the line its tag is; change both by hand", p.image)
			}
			repl = strings.Replace(repl, oldDigest, newDigest, 1)
			newImage += "@" + newDigest
		}
	}

	edited := append([]string(nil), lines...)
	edited[p.editLine-1] = repl
	overlay := map[string][]byte{p.editFile: []byte(strings.Join(edited, "\n"))}
	files := []string{file}
	if p.editFile != file {
		files = append(files, p.editFile)
	}
	after, err := scanPins(ctx, root, files, Options{Overlay: overlay})
	if err != nil {
		return nil, false, err
	}
	if err := verifyEdit(before, after, p); err != nil {
		return nil, false, err
	}
	what := p.prod.name()
	if p.dep != nil {
		what = p.dep.name
	}
	summary := fmt.Sprintf("Changes %s %s to %s on line %d of %s, the fixed release of the same line for %s (the bundled Brotli decoder).",
		what, p.j.current, to, p.editLine, p.editFile, CVE)
	if p.j.vd == noFixLine {
		_, kind := upgrade(p)
		summary = fmt.Sprintf("Moves %s %s to %s on line %d of %s: %s has no release with the %s fix. This is a %s upgrade: review it and run your tests before you merge.",
			p.prod.name(), p.j.current, to, p.editLine, p.editFile, p.j.current, CVE, kind)
	}
	if newImage != "" {
		summary = fmt.Sprintf("Changes the image %s to %s (published for every platform the current tag has, on the same base OS), the fixed %s release for %s. Rebuild and redeploy.",
			p.image, newImage, p.prod.name(), CVE)
		if p.j.vd == noFixLine {
			_, kind := upgrade(p)
			summary = fmt.Sprintf("Changes the image %s to %s (published for every platform the current tag has, on the same base OS): %s %s has no release with the %s fix. This is a %s upgrade: review it and run your tests before you merge, then rebuild and redeploy.",
				p.image, newImage, p.prod.name(), p.j.current, CVE, kind)
		}
	}
	ch := &Change{File: p.editFile, Edits: []Edit{{Line: p.editLine, Old: []string{old}, New: []string{repl}}}, Summary: clean(summary, 600)}
	return ch, false, nil
}

// scanPins runs the scan and keeps the judged pins.
func scanPins(ctx context.Context, root string, files []string, opts Options) (*scanner, error) {
	s := &scanner{ctx: ctx, root: root, opts: opts}
	for _, rel := range files {
		if k := kindOf(rel); k != kindNone || textCandidate(rel) || dependencyFile(rel) {
			s.parseFile(rel, k)
		}
	}
	if err := s.images(files); err != nil {
		return nil, err
	}
	return s, nil
}

// choose finds the pin a finding names. found is false when the file no
// longer has a vulnerable pin of that rule, source and release: it was fixed
// or removed.
func choose(s *scanner, file string, line int, rule string, props map[string]string) (pin, bool, error) {
	var same, moved []pin
	for _, p := range s.pins {
		if p.file != file || p.prod.rule() != rule {
			continue
		}
		if src := props["source"]; src != "" && p.source != src {
			continue
		}
		if cur := props["current"]; cur != "" && p.j.current != cur {
			continue
		}
		if p.line == line {
			same = append(same, p)
		} else {
			moved = append(moved, p)
		}
	}
	switch {
	case len(same) == 1:
		return same[0], true, nil
	case len(same) > 1:
		return pin{}, false, declined("line %d of %s has more than one pin of this runtime; fix them by hand", line, file)
	case len(moved) == 1 && line == 0:
		return moved[0], true, nil
	case len(moved) > 0:
		return pin{}, false, declined("the pin is no longer on line %d of %s (the file changed since the scan); rescan and fix the new finding", line, file)
	}
	return pin{}, false, nil
}

type pinKey struct {
	file, source, current, image string
	line                         int
}

func keyOf(p pin) pinKey { return pinKey{p.file, p.source, p.j.current, p.image, p.line} }

// verifyEdit checks that the edit fixed the pin and changed nothing else.
func verifyEdit(before, after *scanner, target pin) error {
	b := map[pinKey]bool{}
	for _, p := range before.pins {
		b[keyOf(p)] = true
	}
	for _, p := range after.pins {
		k := keyOf(p)
		if p.file == target.file && p.line == target.line && p.source == target.source {
			return declined("after the edit, line %d of %s still pins %s %s; fix it by hand", target.line, target.file, p.prod.name(), p.j.current)
		}
		if !b[k] {
			return declined("the edit would add a new vulnerable pin (%s %s at %s:%d); fix it by hand", p.prod.name(), p.j.current, p.file, p.line)
		}
	}
	if len(after.skips) > len(before.skips) {
		return declined("after the edit, %s no longer reads cleanly; fix it by hand", target.editFile)
	}
	return nil
}

// verifyImage resolves the current image and its replacement and requires
// the replacement to be published for every platform the current one has,
// on the same base OS. It returns the replacement reference.
func verifyImage(ctx context.Context, p pin, to string) (target, oldDigest, newDigest string, err error) {
	ref, err := parseReference(p.image)
	if err != nil || (ref.Tag == "" && p.imgOff <= 0) {
		return "", "", "", declined("the image %s cannot be retagged automatically", p.image)
	}
	base := p.image
	if i := strings.Index(base, "@"); i >= 0 {
		base, oldDigest = base[:i], base[i+1:]
	}
	if p.imgOff <= 0 && strings.Contains(ref.Tag, p.j.current) {
		newTag := strings.Replace(ref.Tag, p.j.current, to, 1)
		i := strings.LastIndex(base, ":"+ref.Tag)
		if i < 0 || newTag == ref.Tag {
			return "", "", "", declined("the tag of %s is not written as it is read", p.image)
		}
		target = base[:i] + ":" + newTag
	} else {
		// A line image names its line in the repository (nodejs20-debian12),
		// at the offset the scan found it.
		at := p.imgOff
		if at <= 0 || at+len(p.j.current) > len(base) || base[at:at+len(p.j.current)] != p.j.current {
			return "", "", "", declined("the release line of %s is not written as it is read", p.image)
		}
		target = base[:at] + to + base[at+len(p.j.current):]
	}
	t, d, err := verifyTarget(ctx, p, target)
	return t, oldDigest, d, err
}

func verifyTarget(ctx context.Context, p pin, target string) (string, string, error) {
	if VerifyImage == nil {
		return "", "", declined("moving %s needs the registry, which this run does not use; change it by hand", p.image)
	}
	d, err := VerifyImage(ctx, p.image, target)
	if err != nil {
		if _, ok := IsDeclined(err); ok {
			return "", "", err
		}
		return "", "", declined("%s could not be verified (%v); try again later, or change it by hand", target, err)
	}
	return target, d, nil
}

// Education is the background paragraph for a finding with this rule.
func Education(rule string) string {
	base := "CVE-2026-111497 (also called Node2Shell or Broccoli2Shell) is an out-of-bounds write in Google's Brotli decoder, releases 1.0.3 through 1.2.0: a crafted Brotli-compressed stream can crash the process, disclose its memory or run code. Anything that decompresses untrusted Brotli data is exposed, such as HTTP clients and servers that accept Content-Encoding: br. Brotli 1.0.10, 1.1.1 and 1.2.1 fix it."
	switch rule {
	case RuleNode:
		return base + " Node.js bundles its own copy of Brotli (zlib's Brotli functions and fetch), so updating the operating system's Brotli does not fix it: Node.js 22.23.4, 24.22.1 and 26.12.1 do. Node.js 20, 21, 23, 25 and older received no fix."
	case RuleDotnet:
		return base + " .NET bundles Brotli in System.IO.Compression.Native: .NET 8.0.33, 9.0.22 and 10.0.14 fix it. Self-contained apps and container images keep the runtime they were built with until they are rebuilt."
	case RuleBun:
		return base + " Bun bundles Brotli: Bun 1.4.4 fixes it, and executables made with bun build --compile must be rebuilt."
	}
	return base
}
