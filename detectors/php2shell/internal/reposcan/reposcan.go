// Package reposcan checks the image references in a source tree and plans the
// fix for each vulnerable one. It is the library entry point for repository
// scans: the CLI's repo and fix modes and DefectDojo Sensei both call Run.
package reposcan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/fix"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/refs"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/repocheck"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/report"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/source"
)

// Options configure a repository scan.
type Options struct {
	Registry registry.Options
	Refs     refs.Options
	// Parallel is how many references are resolved at once (default 4).
	Parallel int
	// Files limits the scan to these repository-relative files (a PR's changed
	// files); empty scans the whole tree.
	Files []string
	// NoPlan skips fix planning (no tag listing).
	NoPlan bool
	// MaxImages caps the distinct image references resolved (default 200), so a
	// repository cannot make one scan spend a registry's rate limit for everyone.
	// References past the cap are listed as not checked.
	MaxImages int
}

// TransientError reports image references that could not be checked because a
// registry failed (network, timeout, rate limit). A scan with any of these is
// incomplete in a way the next run can fix, so callers must not treat its
// (shorter) findings list as the truth: a reimport would close open findings.
type TransientError struct{ Refs []string }

func (e *TransientError) Error() string {
	return fmt.Sprintf("%d image reference(s) could not be checked because a registry failed: %s", len(e.Refs), strings.Join(e.Refs, "; "))
}

// Item is one reference that proves a PHP version, with its fix plan.
type Item struct {
	Result repocheck.Result `json:"result"`
	// Change is the verified edit that fixes it, when one exists.
	Change *fix.Change `json:"change,omitempty"`
	// Decline says why there is no edit, for a vulnerable reference without one.
	Decline *fix.Decline `json:"decline,omitempty"`
}

// Run scans root and returns the report target and an item per PHP reference.
// When a registry failed for some references, Run still returns the target and
// items it has, with a *TransientError.
func Run(ctx context.Context, root string, opts Options) (*report.Target, []Item, error) {
	t := &report.Target{Name: root, Type: "repository"}
	var rs []refs.Ref
	var skips []refs.Skip
	var err error
	if len(opts.Files) > 0 {
		rs, skips, err = refs.ScanFiles(root, opts.Files, opts.Refs)
	} else {
		rs, skips, err = refs.Scan(root, opts.Refs)
	}
	if err != nil {
		return nil, nil, err
	}
	for _, s := range skips {
		where := s.File
		if s.Line > 0 {
			where = fmt.Sprintf("%s:%d", s.File, s.Line)
		}
		t.Skipped = append(t.Skipped, source.Skip{Path: where, Reason: s.Reason})
	}
	parallel := opts.Parallel
	if parallel <= 0 {
		parallel = 4
	}
	maxImages := opts.MaxImages
	if maxImages <= 0 {
		maxImages = 200
	}
	var kept []refs.Ref
	distinct := map[string]bool{}
	for _, r := range rs {
		if !distinct[r.Image] && len(distinct) >= maxImages {
			t.Skipped = append(t.Skipped, source.Skip{Path: fmt.Sprintf("%s:%d %s", r.File, r.Line, r.Image), Reason: fmt.Sprintf("image not checked: more than %d distinct images in one scan", maxImages)})
			continue
		}
		distinct[r.Image] = true
		kept = append(kept, r)
	}
	rs = kept
	res := registry.NewResolver(opts.Registry)
	results, stats := repocheck.Check(ctx, rs, res, parallel)
	var transient []string
	t.RefsChecked = stats.Refs
	t.Files = len(distinctFiles(rs))
	var items []Item
	for _, r := range results {
		a := r.Assessment
		switch a.Verdict {
		case registry.NoPHP:
			continue
		case registry.NoImages, registry.Unresolved:
			reason := a.Reason
			if r.Error != "" {
				reason = r.Error
			}
			where := fmt.Sprintf("%s:%d %s", r.Ref.File, r.Ref.Line, r.Ref.Image)
			t.Skipped = append(t.Skipped, source.Skip{Path: where, Reason: "image not checked: " + oneLine(reason)})
			if r.ErrorKind != "" && registry.Transient(r.ErrorKind) {
				transient = append(transient, where+" ("+r.ErrorKind+")")
			}
			continue
		}
		it := Item{Result: r}
		rf := report.RefFinding{File: r.Ref.File, Line: r.Ref.Line, Kind: fmt.Sprint(r.Ref.Kind), Image: r.Ref.Image, Reason: a.Reason, Platforms: a.VulnerablePlatforms}
		switch a.Verdict {
		case registry.Vulnerable:
			rf.Status, rf.Severity = assess.Vulnerable, "critical"
			if !opts.NoPlan {
				ch, err := fix.Plan(ctx, root, r.Ref, r.Resolution, res)
				if d, ok := fix.IsDecline(err); ok {
					it.Decline = d
					rf.Fix = "No automatic change: " + oneLine(d.Reason)
				} else if err != nil {
					rf.Fix = "No automatic change: " + oneLine(err.Error())
				} else {
					it.Change = ch
					rf.Fix = describe(ch)
				}
			}
		case registry.Fixed:
			rf.Status, rf.Severity = assess.Fixed, "none"
		default:
			rf.Status, rf.Severity = assess.Unknown, "review"
		}
		t.Refs = append(t.Refs, rf)
		items = append(items, it)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i].Result.Ref, items[j].Result.Ref
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	if len(transient) > 0 {
		return t, items, &TransientError{Refs: transient}
	}
	return t, items, nil
}

// oneLine flattens text that may come from a registry or the repository: one
// line, no control characters, bounded length.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)), " ")
	if r := []rune(s); len(r) > 400 {
		s = string(r[:400]) + "…"
	}
	return s
}

func describe(ch *fix.Change) string {
	s := fmt.Sprintf("Change %s to %s (%s line %d)", ch.Before, ch.After, ch.File, ch.Line)
	if len(ch.Verified) > 0 {
		s += ". Verified in the registry: " + strings.Join(ch.Verified, ", ")
	}
	return s + "."
}

func distinctFiles(rs []refs.Ref) map[string]bool {
	m := map[string]bool{}
	for _, r := range rs {
		m[r.File] = true
	}
	return m
}
