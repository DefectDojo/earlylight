package brotli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/image"
	"github.com/DefectDojo/earlylight/internal/source"
)

// Kind IDs for a source tree: what pins a vulnerable runtime or package.
const (
	KindNodePin    = "node-pin"
	KindDotnetPin  = "dotnet-pin"
	KindBunPin     = "bun-pin"
	KindDependency = "dependency"
	KindNotChecked = "not-checked"
)

var ruleKinds = map[string]string{
	pins.RuleNode: KindNodePin, pins.RuleDotnet: KindDotnetPin, pins.RuleBun: KindBunPin,
	pins.RuleDependency: KindDependency, pins.RuleNotChecked: KindNotChecked,
}

func repoKinds() []engine.Kind {
	cwe := []string{"CWE-252", "CWE-787"}
	return []engine.Kind{
		{ID: KindNodePin, Title: "Source tree pins Node.js to a release with the vulnerable Brotli decoder", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "A Dockerfile, Compose or Kubernetes image, version file, package.json, CI step or serverless runtime that selects a Node.js release before 22.23.4, 24.22.1 or 26.12.1, or a line with no fixed release."},
		{ID: KindDotnetPin, Title: "Source tree pins .NET to a release with the vulnerable Brotli decoder", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "An image, SDK, global.json, project file, runtime pack or CI step that selects a .NET runtime before 8.0.33, 9.0.22 or 10.0.14, or an SDK without the fixed runtime."},
		{ID: KindBunPin, Title: "Source tree pins Bun to a release with the vulnerable Brotli decoder", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "An image, version file, packageManager field or CI step that selects Bun before 1.4.4."},
		{ID: KindDependency, Title: "Dependency bundles a Brotli decoder without the fix", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "A package that ships Google's C Brotli decoder in its own build at a release without the fix: brotli4j, the Ruby brotli gem, pycurl, curl_cffi, PyMuPDF, pyarrow, duckdb, Pillow, iltorb and others. OSV has no advisory for these."},
		{ID: KindNotChecked, Title: "Runtime pin not checked for the Brotli fix", Level: "note",
			Description: "A file or value that could not be read (too large, not valid JSON or YAML, or an image pinned by digest only). It is not known to be safe."},
	}
}

// ScanRepo finds what a source tree pins: runtime versions and packages that
// bundle the decoder.
func (d *Detector) ScanRepo(ctx context.Context, dir string, o engine.Options) *engine.Target {
	t := &engine.Target{Name: dir, Type: engine.Repository}
	res, err := pins.Scan(ctx, dir, nil, pins.Options{}) // the pin finder's own file limit (4 MiB), not --max-file-size
	if err != nil {
		t.Error = err.Error()
		return t
	}
	t.Files = res.Files
	if res.Truncated {
		t.Incomplete = "the source tree has too many files to walk; what lies past the limit is not checked"
	}
	for _, f := range res.Findings {
		t.Findings = append(t.Findings, repoFinding(f))
	}
	for _, s := range res.Skips {
		t.Skipped = append(t.Skipped, source.Skip{Path: s.File, Reason: s.Reason})
	}
	return t
}

func repoFinding(f pins.Finding) engine.Finding {
	v := engine.Vulnerable
	reason := ""
	if f.Level == "note" {
		v, reason = engine.Inactive, "a test fixture, not built or deployed"
	}
	facts := map[string]string{}
	for k, val := range f.Props {
		facts[k] = val
	}
	out := engine.Finding{Kind: ruleKinds[f.Rule], Path: f.File, Line: f.Line, Verdict: v, Reason: reason, Message: f.Message,
		Method: "source", Facts: facts, Fix: f.Fix}
	if f.Level == "warning" {
		out.Severity = "medium"
	} else {
		out.CVEs = []engine.CVEResult{{ID: assess.CVE, Verdict: v, Reason: reason}}
	}
	return out
}

// Fix moves a source tree's vulnerable pins to fixed releases: one verified
// edit each, an image only after the replacement is pulled and scanned clean
// on every platform the current one has. With opts.DryRun it prints the
// changes without writing them.
func (d *Detector) Fix(ctx context.Context, dirs []string, o engine.Options, stdout, stderr io.Writer) int {
	if !o.Offline {
		pins.VerifyImage = d.verifier(o)
		defer func() { pins.VerifyImage = nil }()
	}
	code := 0
	for _, dir := range dirs {
		res, err := pins.Scan(ctx, dir, nil, pins.Options{})
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", pins.Printable(dir), err)
			return 2
		}
		// What was not read cannot be called fixed.
		if res.Truncated {
			fmt.Fprintf(stdout, "incomplete %s: the source tree has too many files to walk; what lies past the limit is not checked\n", pins.Printable(dir))
			code = max(code, 1)
		}
		for _, sk := range res.Skips {
			fmt.Fprintf(stdout, "not checked %s:%d  %s\n", pins.Printable(sk.File), sk.Line, pins.Printable(sk.Reason))
			code = max(code, 1)
		}
		for _, f := range res.Findings {
			if f.Level == "note" {
				continue
			}
			where := fmt.Sprintf("%s:%d", pins.Printable(f.File), f.Line)
			if !f.Fixable {
				fmt.Fprintf(stdout, "not fixed  %s  %s\n           %s\n", where, pins.Printable(f.Message), pins.Printable(f.Fix))
				code = max(code, 1)
				continue
			}
			ch, already, err := pins.Plan(ctx, dir, f.File, f.Line, f.Rule, f.Props)
			switch {
			case already:
				continue
			case err != nil:
				fmt.Fprintf(stdout, "not fixed  %s  %s\n", where, pins.Printable(err.Error()))
				code = max(code, 1)
				continue
			}
			verb := "fixed"
			if o.DryRun {
				verb = "would fix"
			} else if err := pins.Apply(dir, ch); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", pins.Printable(ch.File), err)
				return 2
			}
			fmt.Fprintf(stdout, "%-10s %s  %s\n%s", verb, where, pins.Printable(ch.Summary), indent(pins.Diff(ch)))
		}
	}
	return code
}

func indent(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("           " + l + "\n")
	}
	return b.String()
}

// verifier pulls the replacement image on every platform the current one
// has and requires the brotli detector to find no decoder without the fix.
func (d *Detector) verifier(o engine.Options) func(ctx context.Context, current, target string) (string, error) {
	return func(ctx context.Context, current, target string) (string, error) {
		cur, err := image.Platforms(current)
		if err != nil {
			cur = nil // the current tag may be gone: judge the target on its own platforms
		}
		tp, err := image.Platforms(target)
		if err != nil {
			return "", err
		}
		have := map[string]bool{}
		for _, p := range tp {
			have[p] = true
		}
		want := cur
		if len(want) == 0 {
			want = tp
		}
		for _, p := range want {
			if len(tp) > 0 && !have[p] {
				return "", &pins.Declined{Reason: fmt.Sprintf("%s is not published for %s, which %s has; change it by hand", target, p, current)}
			}
		}
		if len(want) == 0 {
			want = []string{""}
		}
		for _, p := range want {
			t := engine.ScanImage([]engine.Detector{d}, target, engine.Options{Platform: p, MaxFileSize: o.MaxFileSize})
			if t.Error != "" {
				return "", fmt.Errorf("scanning %s (%s): %s", target, p, t.Error)
			}
			// Clean means read in full, with the runtime's own decoder
			// proven fixed: a scan with gaps, or one that never saw a
			// decoder, proves nothing.
			if t.Incomplete != "" || t.Gaps() > 0 || len(t.Problems) > 0 {
				return "", &pins.Declined{Reason: fmt.Sprintf("%s on %s could not be read in full; change it by hand", target, p)}
			}
			fixed := 0
			for _, f := range t.Findings {
				switch f.Verdict {
				case engine.Vulnerable, engine.Unknown:
					return "", &pins.Declined{Reason: fmt.Sprintf("%s on %s still holds %s (%s); change it by hand", target, p, f.Path, f.Verdict)}
				case engine.Fixed:
					fixed++
				}
			}
			if fixed == 0 {
				return "", &pins.Declined{Reason: fmt.Sprintf("no Brotli decoder was found in %s on %s, so the runtime's fix is not proven; change it by hand", target, p)}
			}
		}
		ref, err := name.ParseReference(target)
		if err != nil {
			return "", err
		}
		desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
		if err != nil {
			return "", err
		}
		return desc.Digest.String(), nil
	}
}
