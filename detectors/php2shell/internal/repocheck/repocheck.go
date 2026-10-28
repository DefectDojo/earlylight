// Package repocheck judges the image references found in a repository: it
// resolves each one (once per distinct reference) and assesses it with
// registry.Assess. A reference whose images prove no PHP version is not a
// finding, but it is counted.
package repocheck

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// Resolver is what Check needs; *registry.Resolver implements it.
type Resolver interface {
	Resolve(ctx context.Context, ref string) (*registry.Resolution, error)
}

// Result is the judgement for one reference.
type Result struct {
	Ref        refs.Ref             `json:"ref"`
	Resolution *registry.Resolution `json:"resolution,omitempty"`
	Assessment registry.Assessment  `json:"assessment"`
	// Error is set when the reference could not be resolved (Assessment is
	// then Unresolved).
	Error string `json:"error,omitempty"`
	// ErrorKind classifies Error: "network", "timeout" and "rate-limited" are
	// transient (registry.Transient); "not-found", "denied", "invalid",
	// "unsupported" and "offline" are definitive.
	ErrorKind string `json:"error_kind,omitempty"`
	// Transient is registry.Transient(ErrorKind): the reference may resolve on
	// a later attempt, so its absence from the findings proves nothing.
	Transient bool `json:"transient,omitempty"`
}

// Finding reports whether the result is a finding (vulnerable).
func (r Result) Finding() bool { return r.Assessment.Verdict == registry.Vulnerable }

// Stats counts results by verdict.
type Stats struct {
	Refs       int `json:"refs"`
	Images     int `json:"images"` // distinct references resolved
	Vulnerable int `json:"vulnerable"`
	Fixed      int `json:"fixed"`
	Unknown    int `json:"unknown"`
	NoPHP      int `json:"no_php_evidence"`
	NoImages   int `json:"no_images"`
	Unresolved int `json:"unresolved"`
	// Transient counts the unresolved references that failed transiently.
	Transient int `json:"transient"`
}

// Check resolves and assesses every reference, with at most parallel
// references in flight (default 4). Results are in the order of rs. A
// reference with a literal FROM --platform (Ref.Platform) is judged on that
// platform only; Result.Resolution is then filtered to it. A global platform
// restriction is registry.Options.Platforms.
func Check(ctx context.Context, rs []refs.Ref, r Resolver, parallel int) ([]Result, Stats) {
	if parallel <= 0 {
		parallel = 4
	}
	type out struct {
		res *registry.Resolution
		err error
	}
	images := map[string]*out{}
	var keys []string
	for _, ref := range rs {
		if _, ok := images[ref.Image]; !ok {
			images[ref.Image] = &out{}
			keys = append(keys, ref.Image)
		}
	}
	sort.Strings(keys)
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, k := range keys {
		o := images[k]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o.res, o.err = r.Resolve(ctx, k)
		}()
	}
	wg.Wait()

	st := Stats{Refs: len(rs), Images: len(keys)}
	results := make([]Result, len(rs))
	for i, ref := range rs {
		o := images[ref.Image]
		res := Result{Ref: ref, Resolution: o.res}
		if o.res != nil && ref.Platform != "" {
			res.Resolution = registry.FilterPlatforms(o.res, []string{ref.Platform})
		}
		if o.err != nil {
			res.Error = registry.CleanText(o.err.Error(), 600)
			res.ErrorKind = ErrorKind(o.err)
			res.Transient = registry.Transient(res.ErrorKind)
			if res.Transient {
				st.Transient++
			}
			res.Assessment = registry.Assessment{Verdict: registry.Unresolved, Reason: res.Error}
		} else {
			res.Assessment = registry.Assess(res.Resolution)
		}
		switch res.Assessment.Verdict {
		case registry.Vulnerable:
			st.Vulnerable++
		case registry.Fixed:
			st.Fixed++
		case registry.Unknown:
			st.Unknown++
		case registry.NoPHP:
			st.NoPHP++
		case registry.NoImages:
			st.NoImages++
		default:
			st.Unresolved++
		}
		results[i] = res
	}
	return results, st
}

// ErrorKind classifies a resolution error: the registry.ErrorKind name, or
// "timeout" for an expired deadline or cancellation, or "network".
func ErrorKind(err error) string {
	var e *registry.Error
	switch {
	case errors.As(err, &e):
		return e.Kind.String()
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	}
	return "network"
}
