// Package fix proposes and applies deterministic one-line fixes for image
// references that carry a PHP release vulnerable to CVE-2026-109618 and
// CVE-2026-109619.
//
// A fix is proposed only when it is verified: the replacement reference
// exists in the registry, holds images (not an empty index), covers every
// platform the original covers, and every one of those platforms proves a PHP
// release with the fix. The edited file is then re-scanned in memory: the
// reference must resolve to exactly the replacement, every other reference
// the edit changes (an ARG shared by several FROMs) must verify the same way,
// and nothing else in the file may change. Anything short of that is a
// Decline with the reason.
//
// The rules are conservative:
//
//   - docker.io/library/php with an exact X.Y.Z tag on a branch with a fix:
//     the same tag with the fixed release (8.3.20-fpm-alpine3.21 becomes
//     8.3.36-fpm-alpine3.21), if the registry lists that tag. The OS release
//     suffix is never changed.
//   - A floating tag (8.3-fpm, 8-apache, latest, fpm-alpine) moves by itself
//     when Docker Hub publishes the fixed release; nothing to edit, unless the
//     reference is pinned by digest, in which case the digest is replaced with
//     the tag's current one once that is verified.
//   - An exact tag pinned by digest gets both the fixed tag and its digest.
//   - A bare digest (php@sha256:...) does not say which variant it is: decline.
//   - Branches before 8.2 have no upstream fix: moving to a supported branch
//     changes the PHP minor version and is left to the developer.
//   - Images built on PHP (wordpress, drupal, ...) and other repositories are
//     only bumped when pinned by digest under a tag that now verifies fixed.
//
// The edit lands where the changing characters were written: the FROM line,
// the ARG default that feeds it, the Compose default or .env value, the Helm
// values tag line. The rest of the line, and the rest of the file, are kept
// byte for byte.
package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/version"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// Resolver is what Plan needs from a registry; *registry.Resolver implements
// it.
type Resolver interface {
	Resolve(ctx context.Context, ref string) (*registry.Resolution, error)
	Tags(ctx context.Context, repository string) ([]string, error)
}

// Change is one verified line edit.
type Change struct {
	// File is the repository-relative path of the edited file.
	File string `json:"file"`
	// Line is the 1-based line edited.
	Line int `json:"line"`
	// Old is the line as it is now and New the line after the fix, both
	// without the line terminator (which Apply keeps).
	Old string `json:"old"`
	New string `json:"new"`
	// Reason explains the fix and its verification.
	Reason string `json:"reason"`
	// Before and After are the image reference before and after the fix.
	Before string `json:"before"`
	After  string `json:"after"`
	// Ref is the reference the fix is for (its File may differ from File when
	// the edit is to an ARG, a .env file, ...).
	Ref refs.Ref `json:"ref"`
	// Verified lists the platforms checked in the replacement:
	// "linux/amd64: PHP 8.3.36".
	Verified []string `json:"verified"`
	// Also lists other references the same edit changes, each verified.
	Also []string `json:"also,omitempty"`
}

// DeclineCode classifies why no fix is proposed.
type DeclineCode string

const (
	DeclineNotVulnerable      DeclineCode = "not-vulnerable"
	DeclineUnresolved         DeclineCode = "unresolved"
	DeclineOffline            DeclineCode = "offline"
	DeclineEndOfLife          DeclineCode = "end-of-life-branch"
	DeclineMixedBranches      DeclineCode = "mixed-branches"
	DeclineFloatingTag        DeclineCode = "floating-tag"
	DeclineBareDigest         DeclineCode = "bare-digest"
	DeclineDerivedImage       DeclineCode = "derived-image"
	DeclineUnsupportedTag     DeclineCode = "unsupported-tag"
	DeclineSuffixNotPublished DeclineCode = "suffix-not-published"
	DeclineNotPublished       DeclineCode = "not-published-yet"
	DeclinePlatformsMissing   DeclineCode = "platforms-missing"
	DeclineNotFixed           DeclineCode = "replacement-not-fixed"
	DeclineNotEditable        DeclineCode = "not-editable"
	DeclineMultipleLines      DeclineCode = "multiple-lines"
	DeclineSharedEdit         DeclineCode = "shared-edit"
	DeclineStale              DeclineCode = "file-changed"
	DeclineVerification       DeclineCode = "verification-failed"
	// DeclineBaseOSChanged: the replacement is built on another OS release
	// (php:8.3.20-fpm on Debian bookworm, php:8.3.36-fpm on trixie). The
	// Reason names the explicit tag that keeps the release.
	DeclineBaseOSChanged DeclineCode = "base-os-changed"
	// DeclineBaseOSUnknown: the OS release of the original or the replacement
	// cannot be determined and the tag does not name it.
	DeclineBaseOSUnknown DeclineCode = "base-os-unknown"
)

// Decline is returned by Plan when no fix is proposed.
type Decline struct {
	Code   DeclineCode `json:"code"`
	Reason string      `json:"reason"`
}

func (d *Decline) Error() string { return "no fix: " + d.Reason }

// decline builds a Decline. Reasons are single-line and bounded: they quote
// registry-provided text (tags, platforms, error messages).
func decline(code DeclineCode, format string, args ...any) *Decline {
	return &Decline{Code: code, Reason: registry.CleanText(fmt.Sprintf(format, args...), 2000)}
}

// IsDecline reports whether err is a Decline, and returns it.
func IsDecline(err error) (*Decline, bool) {
	var d *Decline
	ok := errors.As(err, &d)
	return d, ok
}

var (
	reExactTag    = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(-[a-z0-9][a-z0-9.-]*)?$`)
	reFloatingTag = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?(?:-[a-z0-9][a-z0-9.-]*)?|[a-z][a-z0-9.-]*)$`)
	reDigestHex   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

const maxFileSize = 4 << 20

// Plan proposes a verified fix for a vulnerable reference. res is the
// reference's resolution (registry.Resolver.Resolve(ref.Image)). The error is
// a *Decline when there is no fix to propose, or another error when the
// repository could not be read.
func Plan(ctx context.Context, root string, ref refs.Ref, res *registry.Resolution, resolver Resolver) (*Change, error) {
	if res == nil {
		return nil, decline(DeclineUnresolved, "%s was not resolved", ref.Image)
	}
	if res.Offline {
		return nil, decline(DeclineOffline, "fixes are verified against the registry, which offline mode does not contact")
	}
	pref, err := registry.ParseReference(ref.Image)
	if err != nil {
		return nil, decline(DeclineUnresolved, "%v", err)
	}
	if res.Reference.String() != pref.String() {
		return nil, decline(DeclineUnresolved, "the resolution is for %s, not %s", res.Reference.String(), pref.String())
	}
	if ref.Platform != "" {
		// FROM --platform=X builds X only: judge and verify X only.
		res = registry.FilterPlatforms(res, []string{ref.Platform})
	}
	a := registry.Assess(res)
	if a.Verdict != registry.Vulnerable {
		return nil, decline(DeclineNotVulnerable, "%s", a.Reason)
	}
	branch, err := oneBranch(a)
	if err != nil {
		return nil, err
	}
	fixed, ok := knowledge.FixedRelease(branch)
	if !ok {
		return nil, decline(DeclineEndOfLife, "PHP %s has no upstream fix (the branch is end of life); moving from %s to a supported branch changes the PHP minor version, so upgrade deliberately", branch, branch)
	}

	p := &planner{ctx: ctx, root: root, ref: ref, res: res, pref: pref, resolver: resolver, branch: branch, fixed: fixed, assess: a}
	return p.plan()
}

func oneBranch(a registry.Assessment) (version.Branch, error) {
	var b version.Branch
	seen := map[version.Branch]bool{}
	for _, p := range a.Platforms {
		v, err := version.ParsePHP(p.PHPVersion)
		if err != nil {
			return b, decline(DeclineUnresolved, "%v", err)
		}
		seen[v.Branch()] = true
		b = v.Branch()
	}
	if len(seen) != 1 {
		var bs []string
		for x := range seen {
			bs = append(bs, x.String())
		}
		sort.Strings(bs)
		return b, decline(DeclineMixedBranches, "the platforms carry different PHP branches (%s); no single fixed release applies", strings.Join(bs, ", "))
	}
	return b, nil
}

type planner struct {
	ctx      context.Context
	root     string
	ref      refs.Ref
	res      *registry.Resolution
	pref     registry.Reference
	resolver Resolver
	branch   version.Branch
	fixed    version.PHP
	assess   registry.Assessment
	tagList  []string
	tagErr   error
	tagsDone bool
}

func (p *planner) tags() ([]string, error) {
	if !p.tagsDone {
		p.tagList, p.tagErr = p.resolver.Tags(p.ctx, p.pref.Repository())
		p.tagsDone = true
	}
	return p.tagList, p.tagErr
}

func (p *planner) currentVersions() string {
	var vs []string
	for _, pl := range p.assess.Platforms {
		vs = append(vs, fmt.Sprintf("%s: PHP %s", platformName(pl.Platform), pl.PHPVersion))
	}
	return strings.Join(vs, ", ")
}

func platformName(p string) string {
	if p == "" {
		return "the image"
	}
	return p
}

func (p *planner) plan() (*Change, error) {
	tag, dig := p.pref.Tag, p.pref.Digest
	if dig != "" && !reDigestHex.MatchString(dig) {
		return nil, decline(DeclineUnsupportedTag, "digest %s is not a sha256 digest", dig)
	}
	if tag == "" && dig != "" {
		return nil, decline(DeclineBareDigest, "%s is pinned by digest without a tag, so the variant (cli, fpm, apache, zts) and OS are unknown; add the tag it was taken from to let the fix be verified", p.ref.Image)
	}
	official := p.pref.IsOfficialPHP()
	effTag := p.pref.EffectiveTag()
	newTag := tag
	reason := ""
	switch m := reExactTag.FindStringSubmatch(effTag); {
	case official && m != nil:
		tb := version.Branch{Major: atoi(m[1]), Minor: atoi(m[2])}
		if tb != p.branch {
			return nil, decline(DeclineUnsupportedTag, "the tag %s names PHP %s.%s but the image carries %s", tag, m[1], m[2], p.currentVersions())
		}
		suffix := m[4]
		newTag = p.fixed.String() + suffix
		tags, err := p.tags()
		if err != nil {
			return nil, decline(DeclineUnresolved, "cannot list the tags of %s: %v", p.pref.Repository(), err)
		}
		if !contains(tags, newTag) {
			return nil, decline(DeclineSuffixNotPublished, "%s:%s is not published; %s is published as: %s (the OS release is not switched automatically)",
				p.pref.Repository(), newTag, p.fixed, suffixList(tags, p.fixed.String()))
		}
		reason = fmt.Sprintf("%s carries %s; %s is the fixed %s release", p.ref.Image, p.currentVersions(), p.fixed, p.branch)
	case official && reFloatingTag.MatchString(effTag):
		if dig == "" {
			return nil, decline(DeclineFloatingTag, "%s is a floating tag that currently resolves to %s; the tag will move to the fixed release (%s) when Docker Hub finishes publishing; rebuild or redeploy then", p.ref.Image, p.currentVersions(), p.fixed)
		}
		reason = fmt.Sprintf("%s is pinned to a digest that carries %s; the digest is replaced with the one %s points at now", p.ref.Image, p.currentVersions(), p.pref.Repository()+":"+effTag)
	case official:
		return nil, decline(DeclineUnsupportedTag, "the tag %q does not follow the php image's <version>[-<variant>][-<os>] scheme", tag)
	default:
		if dig == "" {
			return nil, decline(DeclineDerivedImage, "%s is built on PHP (%s); upgrade when its publisher rebuilds it on PHP %s or later (a reference pinned by digest under its tag can be bumped automatically)", p.ref.Image, p.currentVersions(), p.fixed)
		}
		reason = fmt.Sprintf("%s is pinned to a digest that carries %s; the digest is replaced with the one %s points at now", p.ref.Image, p.currentVersions(), p.pref.Repository()+":"+effTag)
	}

	target := p.pref.Repository() + ":" + newTag
	if tag == "" {
		target = p.pref.Repository() + ":" + effTag
	}
	vo := verifyOpts{tagNamesOS: tagNamesOSRelease(effTag) && tagNamesOSRelease(newTagOr(newTag, effTag))}
	if official {
		vo.retired = p.retiredPlatforms(effTag)
		vo.keepBase = p.baseHint(newTagOr(newTag, effTag), dig != "")
	}
	tres, verified, err := verify(p.ctx, p.resolver, target, p.res, vo)
	if err != nil {
		return nil, err
	}
	newDig := ""
	if dig != "" {
		newDig, err = replacementDigest(p.res, tres)
		if err != nil {
			return nil, err
		}
	}

	// The new reference string, keeping the reference's own spelling.
	old := p.ref.Image
	type span struct {
		a, b int
		repl string
	}
	var spans []span
	if newTag != tag {
		ts := refs.TagStart(old)
		vlen := len(effTag)
		if i := strings.IndexByte(effTag, '-'); i >= 0 {
			vlen = i
		}
		oldV, newV := old[ts:ts+vlen], p.fixed.String()
		pre, suf := commonAffixes(oldV, newV)
		spans = append(spans, span{ts + pre, ts + len(oldV) - suf, newV[pre : len(newV)-suf]})
	}
	if newDig != "" && newDig != dig {
		at := strings.LastIndexByte(old, '@')
		ds := at + 1 + len("sha256:")
		spans = append(spans, span{ds, len(old), strings.TrimPrefix(newDig, "sha256:")})
	}
	if len(spans) == 0 {
		return nil, decline(DeclineVerification, "the replacement equals the original reference")
	}
	newImage := old
	for i := len(spans) - 1; i >= 0; i-- {
		s := spans[i]
		newImage = newImage[:s.a] + s.repl + newImage[s.b:]
	}

	// Map each span to the Part that holds it.
	type edit struct {
		part refs.Part
		off  int // byte offset of the span in the part
		n    int
		repl string
	}
	var edits []edit
	for _, s := range spans {
		off := 0
		found := false
		for _, pt := range p.ref.Parts {
			if s.a >= off && s.b <= off+len(pt.Text) {
				if pt.Line == 0 || pt.Column == 0 {
					return nil, decline(DeclineNotEditable, "the characters to change (%q) are not written verbatim on one line (quoted with escapes, folded, or assembled by a template)", old[s.a:s.b])
				}
				edits = append(edits, edit{pt, s.a - off, s.b - s.a, s.repl})
				found = true
				break
			}
			off += len(pt.Text)
		}
		if !found {
			return nil, decline(DeclineNotEditable, "the characters to change (%q) come from more than one place (a variable and the text around it)", old[s.a:s.b])
		}
	}
	file, line := edits[0].part.File, edits[0].part.Line
	for _, e := range edits[1:] {
		if e.part.File != file || e.part.Line != line {
			return nil, decline(DeclineMultipleLines, "the fix would edit %s:%d and %s:%d; only single-line fixes are proposed", file, line, e.part.File, e.part.Line)
		}
	}

	content, err := readFile(p.root, file)
	if err != nil {
		return nil, err
	}
	lines := splitKeep(content)
	if line < 1 || line > len(lines) {
		return nil, decline(DeclineStale, "%s has no line %d any more", file, line)
	}
	oldLine := lines[line-1].text
	newLine := oldLine
	sort.Slice(edits, func(i, j int) bool { return edits[i].part.Column+edits[i].off > edits[j].part.Column+edits[j].off })
	for _, e := range edits {
		c := e.part.Column - 1
		if c+len(e.part.Text) > len(oldLine) || oldLine[c:c+len(e.part.Text)] != e.part.Text {
			return nil, decline(DeclineStale, "%s:%d no longer reads %q at column %d", file, line, e.part.Text, e.part.Column)
		}
		at := c + e.off
		newLine = newLine[:at] + e.repl + newLine[at+e.n:]
	}
	lines[line-1].text = newLine
	newContent := joinKeep(lines)

	also, err := p.recheck(file, content, newContent, newImage)
	if err != nil {
		return nil, err
	}

	where := "the reference"
	if file != p.ref.File || line != p.ref.Line {
		where = fmt.Sprintf("%s:%d", file, line)
		if len(edits) == 1 && edits[0].part.Var != "" {
			where = fmt.Sprintf("the default of %s (%s:%d), which supplies that part of the reference", edits[0].part.Var, file, line)
		}
	}
	every := "every platform of the original"
	for _, v := range verified {
		if strings.Contains(v, "retired by Docker Hub") {
			every = "every platform of the original that Docker Hub still builds"
		}
	}
	reason += fmt.Sprintf(". %s is published for %s and verified: %s. The fix edits %s",
		target, every, strings.Join(verified, ", "), where)
	if len(also) > 0 {
		reason += "; the same edit also changes, verified: " + strings.Join(also, "; ")
	}
	return &Change{
		File: file, Line: line, Old: oldLine, New: newLine,
		Reason: registry.CleanText(reason+".", 4000),
		Before: old, After: newImage,
		Ref: p.ref, Verified: verified, Also: also,
	}, nil
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
		if n > 1<<20 {
			return -1
		}
	}
	return n
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// suffixList lists the published tags of release v as suffixes ("-fpm",
// "-fpm-alpine3.22", "" shown as "(plain)").
func suffixList(tags []string, v string) string {
	var out []string
	for _, t := range tags {
		if t == v {
			out = append(out, "(plain "+v+")")
		} else if strings.HasPrefix(t, v+"-") {
			out = append(out, registry.CleanText(t[len(v):], 64))
		}
	}
	if len(out) == 0 {
		return "no tags yet"
	}
	sort.Strings(out)
	if len(out) > 40 {
		out = append(out[:40], fmt.Sprintf("and %d more", len(out)-40))
	}
	return strings.Join(out, ", ")
}

// commonAffixes returns the lengths of the common prefix and suffix of a and b,
// leaving at least one byte of a to replace.
func commonAffixes(a, b string) (int, int) {
	pre := 0
	for pre < len(a)-1 && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre-1 && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	return pre, suf
}

// verifyOpts adjust verify.
type verifyOpts struct {
	// retired, given the original platforms missing from the replacement,
	// returns those that Docker Hub stopped building before the replacement
	// (platform -> explanation); they are not required.
	retired func(missing []string) map[string]string
	// tagNamesOS: the original and replacement tags name the OS release
	// (alpine3.21, bookworm), so an unknown base is not a reason to decline.
	tagNamesOS bool
	// keepBase, given the original's base OS, names the tag that keeps it.
	keepBase func(base string) string
}

// verify resolves a replacement and checks it against the original
// resolution: non-empty, every original platform present (unless retired),
// each of those proving a fixed PHP release on the same base OS release.
func verify(ctx context.Context, r Resolver, target string, orig *registry.Resolution, vo verifyOpts) (*registry.Resolution, []string, error) {
	tres, err := r.Resolve(ctx, target)
	if err != nil {
		return nil, nil, decline(DeclineUnresolved, "cannot resolve the replacement %s: %v", target, err)
	}
	if tres.Empty {
		return nil, nil, decline(DeclineNotPublished, "%s exists but has no images yet (Docker Hub publishes new tags as empty indexes until the builds finish); try again later", target)
	}
	byPlat := map[string]registry.Platform{}
	for _, tp := range tres.Platforms {
		byPlat[registry.NormalizePlatform(tp.Platform)] = tp
	}
	var missing, notFixed, verified, changed, unknown []string
	origBase := ""
	for _, op := range orig.Platforms {
		if op.Platform == "" {
			return nil, nil, decline(DeclineUnresolved, "the original's platforms are unknown")
		}
		tp, ok := byPlat[registry.NormalizePlatform(op.Platform)]
		if !ok {
			missing = append(missing, op.Platform)
			continue
		}
		if tp.PHPVersion == "" {
			notFixed = append(notFixed, fmt.Sprintf("%s: no PHP version proven", op.Platform))
			continue
		}
		v, err := version.ParsePHP(tp.PHPVersion)
		if err != nil {
			notFixed = append(notFixed, fmt.Sprintf("%s: %v", op.Platform, err))
			continue
		}
		st, why := knowledge.Upstream(v)
		if st != knowledge.UpstreamFixed {
			notFixed = append(notFixed, fmt.Sprintf("%s: %s", op.Platform, why))
			continue
		}
		switch {
		case op.BaseOS != "" && tp.BaseOS != "":
			if op.BaseOS != tp.BaseOS {
				changed = append(changed, fmt.Sprintf("%s: %s -> %s", op.Platform, op.BaseOS, tp.BaseOS))
				if origBase == "" {
					origBase = op.BaseOS
				}
				continue
			}
		case vo.tagNamesOS:
		default:
			unknown = append(unknown, op.Platform)
			continue
		}
		base := ""
		if tp.BaseOS != "" {
			base = " on " + tp.BaseOS
		}
		verified = append(verified, fmt.Sprintf("%s: PHP %s%s", op.Platform, tp.PHPVersion, base))
	}
	if len(missing) > 0 {
		var retired map[string]string
		if vo.retired != nil {
			retired = vo.retired(missing)
		}
		var pending []string
		for _, m := range missing {
			if why, ok := retired[m]; ok {
				verified = append(verified, why)
			} else {
				pending = append(pending, m)
			}
		}
		if len(pending) > 0 {
			var have []string
			for _, tp := range tres.Platforms {
				have = append(have, tp.Platform)
			}
			return nil, nil, decline(DeclinePlatformsMissing, "%s is not yet published for %s (it has %s); try again when Docker Hub finishes publishing",
				target, strings.Join(pending, ", "), strings.Join(have, ", "))
		}
	}
	if len(notFixed) > 0 {
		return nil, nil, decline(DeclineNotFixed, "%s does not verify as fixed: %s", target, strings.Join(notFixed, "; "))
	}
	if len(changed) > 0 {
		hint := ""
		if vo.keepBase != nil {
			hint = vo.keepBase(origBase)
		}
		return nil, nil, decline(DeclineBaseOSChanged, "%s is built on another OS release than the original (%s); a fix never changes the base OS release%s", target, strings.Join(changed, ", "), hint)
	}
	if len(unknown) > 0 {
		return nil, nil, decline(DeclineBaseOSUnknown, "cannot tell which OS release %s or the original is built on for %s (no org.opencontainers.image.base.name annotation or recognisable base layer), and the tag does not name one; pin a tag that names the OS release (for the php image: -bookworm, -trixie, -alpine3.21 ...)", target, strings.Join(unknown, ", "))
	}
	if len(verified) == 0 {
		return nil, nil, decline(DeclineVerification, "%s: nothing to verify", target)
	}
	return tres, verified, nil
}

func newTagOr(tag, eff string) string {
	if tag == "" {
		return eff
	}
	return tag
}

var (
	reAlpineRelease = regexp.MustCompile(`^alpine[0-9]+\.[0-9]+$`)
	debianCodenames = map[string]bool{"jessie": true, "stretch": true, "buster": true, "bullseye": true, "bookworm": true, "trixie": true, "forky": true, "duke": true}
)

// tagNamesOSRelease reports whether a tag names its OS release
// ("8.3.36-fpm-alpine3.21", "8.3-fpm-bookworm"); "-alpine" alone does not.
func tagNamesOSRelease(tag string) bool {
	for _, tok := range strings.Split(tag, "-") {
		if reAlpineRelease.MatchString(tok) || debianCodenames[tok] || strings.HasPrefix(tok, "ltsc") {
			return true
		}
	}
	return false
}

// osTagFor turns a base OS ("alpine:3.21", "debian:bookworm") into the php
// image's tag token ("alpine3.21", "bookworm").
func osTagFor(base string) string {
	fam, rel, ok := strings.Cut(base, ":")
	if !ok {
		return ""
	}
	switch fam {
	case "alpine":
		return "alpine" + rel
	case "debian":
		return rel
	}
	return ""
}

// baseHint names the tag that keeps the original's OS release: tag with its
// OS tokens replaced by the release ("8.3.36-fpm-alpine" on alpine:3.21
// becomes "8.3.36-fpm-alpine3.21"), saying whether it is published.
func (p *planner) baseHint(tag string, pinned bool) func(string) string {
	return func(base string) string {
		ot := osTagFor(base)
		if ot == "" {
			return ""
		}
		var keep []string
		for _, tok := range strings.Split(tag, "-") {
			if tok == "alpine" || reAlpineRelease.MatchString(tok) || debianCodenames[tok] {
				continue
			}
			keep = append(keep, tok)
		}
		cand := strings.Join(append(keep, ot), "-")
		if strings.HasPrefix(cand, "latest-") {
			cand = strings.TrimPrefix(cand, "latest-")
		}
		ref := p.pref.Repository() + ":" + cand
		tags, err := p.tags()
		switch {
		case err != nil:
			return fmt.Sprintf("; to stay on %s, use %s if it is published", base, ref)
		case contains(tags, cand):
			if pinned {
				return fmt.Sprintf("; to stay on %s, use %s (published; pin its digest)", base, ref)
			}
			return fmt.Sprintf("; to stay on %s, use %s (published)", base, ref)
		default:
			return fmt.Sprintf("; %s is not published, so no release of this tag stays on %s", ref, base)
		}
	}
}

var reVersionPrefix = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}`)

// retiredPlatforms explains which missing platforms Docker Hub retired: a
// platform is retired when the newest earlier patch release of the branch
// published with the same tag suffix, and holding images, lacks it too.
// Platforms that release still has are pending, not retired.
func (p *planner) retiredPlatforms(tag string) func([]string) map[string]string {
	return func(missing []string) map[string]string {
		suffix := ""
		switch {
		case reVersionPrefix.MatchString(tag):
			suffix = tag[len(reVersionPrefix.FindString(tag)):]
		case tag == "latest":
		default:
			suffix = "-" + tag
		}
		low := 1 << 30
		for _, pl := range p.assess.Platforms {
			if v, err := version.ParsePHP(pl.PHPVersion); err == nil && v.Patch < low {
				low = v.Patch
			}
		}
		tags, err := p.tags()
		if err != nil {
			return nil
		}
		var cands []version.PHP
		for _, t := range tags {
			if !strings.HasSuffix(t, suffix) {
				continue
			}
			v, err := version.ParsePHP(strings.TrimSuffix(t, suffix))
			if err != nil || v.Extra != "" || !v.IsRelease() || v.Branch() != p.branch || v.Patch <= low || v.Patch >= p.fixed.Patch {
				continue
			}
			cands = append(cands, v)
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].Patch > cands[j].Patch })
		for i, v := range cands {
			if i == 3 {
				break
			}
			prev := p.pref.Repository() + ":" + v.String() + suffix
			res, err := p.resolver.Resolve(p.ctx, prev)
			if err != nil || res.Empty || len(res.Platforms) == 0 {
				continue
			}
			out := map[string]string{}
			for _, m := range missing {
				has := false
				for _, pl := range res.Platforms {
					if registry.NormalizePlatform(pl.Platform) == registry.NormalizePlatform(m) {
						has = true
					}
				}
				if !has {
					out[m] = fmt.Sprintf("%s: retired by Docker Hub before %s (%s has no %s image), not required", m, p.fixed, prev, m)
				}
			}
			return out
		}
		return nil
	}
}

// replacementDigest picks the digest to pin: the replacement's index digest
// when the original was pinned to an index, or the matching platform's
// manifest digest when it was pinned to a single-platform manifest.
func replacementDigest(orig, tres *registry.Resolution) (string, error) {
	if orig.Index {
		if !tres.Index {
			return "", decline(DeclineVerification, "the original is pinned to a multi-platform index but the replacement is a single manifest")
		}
		return tres.Digest, nil
	}
	if !tres.Index {
		return tres.Digest, nil
	}
	if len(orig.Platforms) != 1 {
		return "", decline(DeclineVerification, "unexpected platforms in a single manifest")
	}
	want := registry.NormalizePlatform(orig.Platforms[0].Platform)
	for _, tp := range tres.Platforms {
		if registry.NormalizePlatform(tp.Platform) == want {
			return tp.Digest, nil
		}
	}
	return "", decline(DeclinePlatformsMissing, "the replacement has no %s image", want)
}

// recheck re-scans the edited file in memory: the reference must now resolve
// to newImage, any other reference the edit changes must verify as fixed, and
// nothing else may change.
func (p *planner) recheck(file string, oldContent, newContent []byte, newImage string) ([]string, error) {
	files := []string{p.ref.File}
	if file != p.ref.File {
		files = append(files, file)
	}
	if path.Base(file) == ".env" {
		// Every Compose file in the directory reads this .env.
		dir := path.Dir(file)
		abs, err := refs.SafePath(p.root, path.Join(dir, ".env"))
		if err == nil {
			ents, _ := os.ReadDir(filepath.Dir(abs))
			for _, e := range ents {
				rel := path.Join(dir, e.Name())
				if e.Type().IsRegular() && rel != p.ref.File && isComposeName(e.Name()) {
					files = append(files, rel)
				}
			}
		}
	}
	before, bskips, err := refs.ScanFiles(p.root, files, refs.Options{Overlay: map[string][]byte{file: oldContent}})
	if err != nil {
		return nil, err
	}
	after, askips, err := refs.ScanFiles(p.root, files, refs.Options{Overlay: map[string][]byte{file: newContent}})
	if err != nil {
		return nil, err
	}
	target := -1
	for i, r := range before {
		if sameRef(r, p.ref) && r.Image == p.ref.Image {
			target = i
		}
	}
	if target < 0 {
		return nil, decline(DeclineStale, "%s:%d no longer holds %s", p.ref.File, p.ref.Line, p.ref.Image)
	}
	if len(before) != len(after) || len(bskips) != len(askips) {
		return nil, decline(DeclineVerification, "the edit changes what else the scanner finds in %s", strings.Join(files, ", "))
	}
	for i := range bskips {
		if bskips[i] != askips[i] {
			return nil, decline(DeclineVerification, "the edit changes a skipped reference at %s:%d", askips[i].File, askips[i].Line)
		}
	}
	var also []string
	for i := range before {
		b, a := before[i], after[i]
		if !sameRef(a, b) {
			return nil, decline(DeclineVerification, "the edit moves references in %s", b.File)
		}
		if i == target {
			if a.Image != newImage {
				return nil, decline(DeclineVerification, "after the edit %s:%d resolves to %s, not %s", a.File, a.Line, a.Image, newImage)
			}
			continue
		}
		if a.Image == b.Image {
			continue
		}
		// Another reference changes with the same edit (a shared ARG or .env
		// value). It must verify as fixed on its own platforms too.
		ores, err := p.resolver.Resolve(p.ctx, b.Image)
		if err != nil {
			return nil, decline(DeclineSharedEdit, "the edit also changes %s:%d from %s to %s, which cannot be verified: %v", b.File, b.Line, b.Image, a.Image, err)
		}
		if ref := b.Platform; ref != "" {
			ores = registry.FilterPlatforms(ores, []string{ref})
		}
		otag := ""
		if r, err := registry.ParseReference(a.Image); err == nil {
			otag = r.EffectiveTag()
		}
		if _, _, err := verify(p.ctx, p.resolver, a.Image, ores, verifyOpts{tagNamesOS: tagNamesOSRelease(otag)}); err != nil {
			d, _ := IsDecline(err)
			return nil, decline(DeclineSharedEdit, "the edit also changes %s:%d from %s to %s, whose fix would differ: %s", b.File, b.Line, b.Image, a.Image, d.Reason)
		}
		also = append(also, fmt.Sprintf("%s:%d %s -> %s", b.File, b.Line, b.Image, a.Image))
	}
	return also, nil
}

func sameRef(a, b refs.Ref) bool {
	return a.File == b.File && a.Line == b.Line && a.Kind == b.Kind && a.Context == b.Context && a.Stage == b.Stage
}

func isComposeName(base string) bool {
	l := strings.ToLower(base)
	return (strings.HasPrefix(l, "docker-compose") || strings.HasPrefix(l, "compose")) && !strings.HasPrefix(l, "composer") &&
		(strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".yaml"))
}

// ---- files ----

type fileLine struct {
	text string // without terminator
	term string // "\n", "\r\n", or for the last line "" or "\r"
}

func splitKeep(b []byte) []fileLine {
	s := string(b)
	var out []fileLine
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			// A final line without "\n": a trailing "\r" is a terminator
			// too (the scanner drops it, as bufio.ScanLines does).
			l := fileLine{text: s}
			if strings.HasSuffix(s, "\r") {
				l.text, l.term = s[:len(s)-1], "\r"
			}
			out = append(out, l)
			break
		}
		l := fileLine{text: s[:i], term: "\n"}
		if strings.HasSuffix(l.text, "\r") {
			l.text, l.term = l.text[:len(l.text)-1], "\r\n"
		}
		out = append(out, l)
		s = s[i+1:]
	}
	return out
}

func joinKeep(lines []fileLine) []byte {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.text)
		b.WriteString(l.term)
	}
	return []byte(b.String())
}

func readFile(root, rel string) ([]byte, error) {
	p, err := refs.SafePath(root, rel)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", rel, maxFileSize)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxFileSize+1))
}

// Apply writes changes. Every change is checked first: its file must be a
// regular file inside root (no symbolic links on the way), and its line must
// still read exactly Old. If any check fails nothing is written. Each file is
// then replaced atomically (a temporary file in the same directory, synced
// and renamed over it), keeping its permissions and every other byte.
func Apply(root string, changes []Change) error {
	unlock, err := lockFiles(root, changes)
	if err != nil {
		return err
	}
	defer unlock()
	type pending struct {
		abs   string
		mode  os.FileMode
		lines []fileLine
	}
	files := map[string]*pending{}
	var order []string
	done := map[string]Change{}
	for _, c := range changes {
		key := fmt.Sprintf("%s:%d", c.File, c.Line)
		if prev, ok := done[key]; ok {
			if prev.Old == c.Old && prev.New == c.New {
				continue
			}
			return fmt.Errorf("%s: two different changes to the same line", key)
		}
		done[key] = c
		if strings.Contains(c.New, "\n") || strings.HasSuffix(c.New, "\r") || strings.Contains(c.Old, "\n") || strings.HasSuffix(c.Old, "\r") {
			return fmt.Errorf("%s: a change must stay on one line", key)
		}
		pf, ok := files[c.File]
		if !ok {
			abs, err := refs.SafePath(root, c.File)
			if err != nil {
				return err
			}
			fi, err := os.Lstat(abs)
			if err != nil {
				return err
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", c.File)
			}
			b, err := readFile(root, c.File)
			if err != nil {
				return err
			}
			pf = &pending{abs: abs, mode: fi.Mode().Perm(), lines: splitKeep(b)}
			files[c.File] = pf
			order = append(order, c.File)
		}
		if c.Line < 1 || c.Line > len(pf.lines) {
			return fmt.Errorf("%s has no line %d", c.File, c.Line)
		}
		if pf.lines[c.Line-1].text != c.Old {
			return fmt.Errorf("%s:%d has changed since the fix was planned; refusing to write", c.File, c.Line)
		}
	}
	for _, c := range done {
		files[c.File].lines[c.Line-1].text = c.New
	}
	for _, f := range order {
		pf := files[f]
		if err := writeAtomic(pf.abs, joinKeep(pf.lines), pf.mode); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	return nil
}

// fileLocks serializes Apply's read-check-write per file within the process,
// so concurrent Apply calls on different lines of one file both land.
var (
	fileLocksMu sync.Mutex
	fileLocks   = map[string]*sync.Mutex{}
)

// lockFiles locks every file the changes touch, in a fixed order, keyed by
// the file's real path.
func lockFiles(root string, changes []Change) (func(), error) {
	keys := map[string]bool{}
	for _, c := range changes {
		abs, err := refs.SafePath(root, c.File)
		if err != nil {
			return nil, err
		}
		k := abs
		if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
			k = filepath.Join(dir, filepath.Base(abs))
		}
		if a, err := filepath.Abs(k); err == nil {
			k = a
		}
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var held []*sync.Mutex
	for _, k := range sorted {
		fileLocksMu.Lock()
		m, ok := fileLocks[k]
		if !ok {
			m = &sync.Mutex{}
			fileLocks[k] = m
		}
		fileLocksMu.Unlock()
		m.Lock()
		held = append(held, m)
	}
	return func() {
		for i := len(held) - 1; i >= 0; i-- {
			held[i].Unlock()
		}
	}, nil
}

func writeAtomic(abs string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(abs), "."+filepath.Base(abs)+".php2shell-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, abs); err != nil {
		return err
	}
	ok = true
	return nil
}
