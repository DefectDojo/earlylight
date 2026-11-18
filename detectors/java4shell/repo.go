package java4shell

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/repo"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/image"
	"github.com/DefectDojo/earlylight/internal/netguard"
	"github.com/DefectDojo/earlylight/internal/refs"
	"github.com/DefectDojo/earlylight/internal/source"
)

// Kind IDs for a source tree.
const (
	KindImagePin   = repo.RuleImagePin
	KindJavaPin    = repo.RuleJavaPin
	KindLine       = repo.RuleLine
	KindPackage    = repo.RulePackage
	KindImage      = "image"
	KindNotChecked = repo.RuleNotChecked
)

func repoKinds() []engine.Kind {
	cwe := []string{"CWE-787"}
	return []engine.Kind{
		{ID: KindImagePin, Title: "Source tree uses a Java image without the Java4Shell fix", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "A Dockerfile, Compose, Kubernetes, Helm values, CI or Jib file names a Java runtime image (eclipse-temurin, amazoncorretto, azul/zulu-openjdk, bellsoft/liberica, sapmachine and others) whose tag is a Java release without the fix."},
		{ID: KindImage, Title: "Image the source tree uses holds a Java runtime vulnerable to Java4Shell", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "An image the tree builds on or deploys, read from its registry for linux/amd64 and judged as scan image does: a moving tag, or a product image (Jira, Elasticsearch, Jenkins...) that carries its own runtime."},
		{ID: KindJavaPin, Title: "Source tree pins a Java release without the Java4Shell fix", Level: "warning", SecuritySeverity: "6.5", CWEs: cwe,
			Description: "A version file (.java-version, .sdkmanrc, .tool-versions, mise), a GitHub Actions setup-java step, a buildpack setting or a Maven Enforcer floor that selects or allows a Java release without the fix."},
		{ID: KindLine, Title: "Source tree selects a Java line that received no Java4Shell fix", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "A toolchain, version file, CI step, buildpack, image or package of Java 18, 19, 20, 22, 23, 24 or 26: those lines are end of life and received no fix."},
		{ID: KindPackage, Title: "Dockerfile installs a distribution OpenJDK package without the Java4Shell fix", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
			Description: "An apt, apk, dnf, yum or microdnf install of an OpenJDK 17 or later package pinned to a release without the fix, or without a version while the distribution had no fixed package."},
		{ID: KindNotChecked, Title: "Java runtime not checked for the Java4Shell fix", Level: "note",
			Description: "An image whose tag does not name one Java release (a moving tag, a product image) that was not read, a workflow expression, or a file that could not be read. It is not known to be safe."},
	}
}

// ScanRepo checks a source tree.
func (d *Detector) ScanRepo(ctx context.Context, dir string, o engine.Options) *engine.Target {
	t := &engine.Target{Name: dir, Type: engine.Repository}
	res, err := repo.Scan(ctx, dir, repo.Options{Platforms: o.Platforms})
	if err != nil {
		t.Error = err.Error()
		return t
	}
	t.Files = res.Files
	if res.Truncated {
		t.Incomplete = "the source tree has too many files to walk; what lies past the limit is not checked"
	}
	pulls := map[string]*engine.Target{}
	for _, f := range res.Findings {
		if f.Pull != "" && !o.Offline {
			t.Findings = append(t.Findings, d.pulled(dir, f, o, pulls, t)...)
			continue
		}
		t.Findings = append(t.Findings, repoFinding(f))
	}
	for _, s := range res.Skips {
		p := s.File
		if s.Line > 0 {
			p = fmt.Sprintf("%s:%d", s.File, s.Line)
		}
		t.Skipped = append(t.Skipped, source.Skip{Path: p, Reason: s.Reason})
	}
	return t
}

func repoFinding(f repo.Finding) engine.Finding {
	v, reason := engine.Vulnerable, f.Reason
	switch f.Status {
	case repo.StatusUnknown:
		v = engine.Unknown
	case repo.StatusMitigated:
		v = engine.Inactive
	}
	if reason == "" && v != engine.Vulnerable {
		reason = "not decided"
	}
	facts := map[string]string{}
	for k, val := range f.Props {
		facts[k] = val
	}
	out := engine.Finding{Kind: f.Rule, Path: f.File, Line: f.Line, Verdict: v, Reason: reason, Message: f.Message, Method: "source",
		Facts: facts, Fix: f.Fix, CVEs: []engine.CVEResult{{ID: knowledge.CVE, Verdict: v, Reason: reason}}}
	if f.Level == "warning" {
		out.Severity = "medium"
	}
	return out
}

// maxRepoImages bounds the images one source-tree scan pulls.
const maxRepoImages = 20

// pulled reads an image the tree references (linux/amd64, the only
// affected platform) through the guarded transport and reports its
// runtimes at the reference.
func (d *Detector) pulled(dir string, f repo.Finding, o engine.Options, cache map[string]*engine.Target, t *engine.Target) []engine.Finding {
	img := f.Pull
	it, ok := cache[img]
	if !ok {
		if len(cache) >= maxRepoImages {
			t.Skipped = append(t.Skipped, source.Skip{Path: fmt.Sprintf("%s:%d", f.File, f.Line), Reason: fmt.Sprintf("image %s not pulled: this scan already pulled %d images", img, maxRepoImages)})
			return []engine.Finding{repoFinding(f)}
		}
		it = engine.ScanImage([]engine.Detector{d}, img, engine.Options{Platform: "linux/amd64", MaxFileSize: o.MaxFileSize, Guarded: true, PublicOnly: o.PublicOnly})
		cache[img] = it
	}
	if it.Error != "" {
		g := repoFinding(f)
		g.Message = fmt.Sprintf("image %s could not be read for Java4Shell: %s", img, refs.CleanText(it.Error, 300))
		g.Reason = "the image could not be pulled"
		g.CVEs[0].Reason = g.Reason
		return []engine.Finding{g}
	}
	var out []engine.Finding
	for _, x := range it.Findings {
		if x.Verdict.Cleared() {
			continue
		}
		g := x
		g.Kind, g.Path, g.Line, g.Method = KindImage, f.File, f.Line, "registry"
		g.Facts = map[string]string{}
		for k, v := range x.Facts {
			g.Facts[k] = v
		}
		g.Facts["image"], g.Facts["runtime"] = img, x.Path
		g.Message = fmt.Sprintf("image %s: %s: %s", img, x.Path, x.Message)
		if mit := f.Props["mitigation"]; mit != "" && x.Verdict == engine.Vulnerable {
			g.Verdict = engine.Inactive
			g.Reason = x.Reason + "; " + mit
			g.Message += ", mitigated by its JVM options until it is updated"
			g.CVEs = []engine.CVEResult{{ID: knowledge.CVE, Verdict: g.Verdict, Reason: g.Reason}}
		}
		g.Fix = x.Fix + " Use a release of " + img + " built with the fix (or rebuild it), then redeploy."
		out = append(out, g)
	}
	return out
}

// Fix moves what can be moved to fixed releases: image tags to the first
// published fixed tag of the same variant (read and checked first) and
// setup-java versions to the moving major version for distributions whose
// newest release is fixed. Each edit is rescanned in memory first.
func (d *Detector) Fix(ctx context.Context, dirs []string, o engine.Options, stdout, stderr io.Writer) int {
	reg := repo.Registry{}
	if !o.Offline {
		reg.Tags = tagLister(o)
		reg.Verify = d.verifier(o)
	}
	code := 0
	for _, dir := range dirs {
		ro := repo.Options{Platforms: o.Platforms}
		res, err := repo.Scan(ctx, dir, ro)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", repo.Printable(dir), err)
			return 2
		}
		if res.Truncated {
			fmt.Fprintf(stdout, "incomplete %s: the source tree has too many files to walk; what lies past the limit is not checked\n", repo.Printable(dir))
			code = max(code, 1)
		}
		for _, sk := range res.Skips {
			fmt.Fprintf(stdout, "not checked %s  %s\n", repo.Printable(sk.File), repo.Printable(sk.Reason))
			code = max(code, 1)
		}
		pulls := map[string]*engine.Target{}
		for _, f := range res.Findings {
			where := fmt.Sprintf("%s:%d", repo.Printable(f.File), f.Line)
			if f.Pull != "" {
				if o.Offline {
					fmt.Fprintf(stdout, "not checked %s  %s\n", where, repo.Printable(f.Message))
					code = max(code, 1)
					continue
				}
				dummy := &engine.Target{}
				for _, g := range d.pulled(dir, f, o, pulls, dummy) {
					if g.Verdict == engine.Inactive {
						continue
					}
					fmt.Fprintf(stdout, "not fixed  %s  %s\n           %s\n", where, repo.Printable(g.Message), repo.Printable(g.Fix))
					if g.Facts["product"] != "" && f.Props["mitigation"] == "" && strings.HasSuffix(strings.ToLower(f.File), "dockerfile") {
						fmt.Fprintf(stdout, "           optional interim mitigation (not applied):\n           %s\n", repo.Printable(repo.Mitigation(f.File, f.Line)))
					}
					code = max(code, 1)
				}
				continue
			}
			if f.Status == repo.StatusMitigated || f.Level == "note" && f.Rule != repo.RuleNotChecked {
				continue
			}
			if f.Rule == repo.RuleNotChecked {
				fmt.Fprintf(stdout, "not checked %s  %s\n", where, repo.Printable(f.Message))
				code = max(code, 1)
				continue
			}
			if !f.Fixable {
				fmt.Fprintf(stdout, "not fixed  %s  %s\n           %s\n", where, repo.Printable(f.Message), repo.Printable(f.Fix))
				code = max(code, 1)
				continue
			}
			ch, err := repo.Plan(ctx, dir, f, reg, ro)
			if err != nil {
				fmt.Fprintf(stdout, "not fixed  %s  %s\n           %s\n", where, repo.Printable(f.Message), repo.Printable(err.Error()))
				code = max(code, 1)
				continue
			}
			verb := "fixed"
			if o.DryRun {
				verb = "would fix"
			} else if err := repo.Apply(dir, ch); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", repo.Printable(ch.File), err)
				return 2
			}
			fmt.Fprintf(stdout, "%-10s %s  %s\n%s", verb, where, repo.Printable(ch.Summary), indent(repo.Diff(ch)))
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

// tagLister lists an image repository's tags through the guarded
// transport, a page at a time, at most 20,000, within the timeout.
func tagLister(o engine.Options) func(context.Context, string) ([]string, error) {
	return func(ctx context.Context, img string) ([]string, error) {
		if err := registryRef(img); err != nil {
			return nil, err
		}
		repoName, err := name.NewRepository(img)
		if err != nil {
			return nil, err
		}
		timeout := o.Timeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		lctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		p, err := remote.NewPuller(remote.WithContext(lctx), remote.WithTransport(netguard.Transport(o.PublicOnly)), remote.WithAuthFromKeychain(authn.DefaultKeychain))
		if err != nil {
			return nil, err
		}
		l, err := p.Lister(lctx, repoName)
		if err != nil {
			return nil, err
		}
		var tags []string
		for l.HasNext() && len(tags) < 20000 {
			page, err := l.Next(lctx)
			if err != nil {
				return nil, err
			}
			tags = append(tags, page.Tags...)
		}
		return tags, nil
	}
}

// registryRef accepts only a registry reference: never a local archive or
// any other transport a source file could name.
func registryRef(ref string) error {
	if strings.Contains(ref, "://") || strings.HasPrefix(ref, "docker-archive:") || strings.HasPrefix(ref, "rootfs:") || strings.HasPrefix(ref, "/") {
		return fmt.Errorf("%q is not a registry reference", ref)
	}
	if _, err := name.ParseReference(ref); err != nil {
		return fmt.Errorf("%q is not a valid image reference", ref)
	}
	return nil
}

// verifier reads the replacement image on linux/amd64 (and checks it is
// published for every platform the current one has) and requires the
// detector to find at least one runtime with the fix and none without it.
func (d *Detector) verifier(o engine.Options) func(ctx context.Context, current, target string) (string, error) {
	return func(ctx context.Context, current, target string) (string, error) {
		if err := registryRef(target); err != nil {
			return "", err
		}
		var cur []string
		if registryRef(current) == nil {
			cur, _ = image.Platforms(current) // the current tag may be gone: judge the target on its own
		}
		tp, err := image.Platforms(target)
		if err != nil {
			return "", err
		}
		have := map[string]bool{}
		for _, p := range tp {
			have[p] = true
		}
		for _, p := range cur {
			if len(tp) > 0 && !have[p] {
				return "", &repo.Declined{Reason: fmt.Sprintf("%s is not published for %s, which %s has; change it by hand", target, p, current)}
			}
		}
		t := engine.ScanImage([]engine.Detector{d}, target, engine.Options{Platform: "linux/amd64", MaxFileSize: o.MaxFileSize, Guarded: true, PublicOnly: o.PublicOnly})
		if t.Error != "" {
			return "", fmt.Errorf("reading %s: %s", target, t.Error)
		}
		if t.Incomplete != "" || t.Gaps() > 0 || len(t.Problems) > 0 {
			return "", &repo.Declined{Reason: fmt.Sprintf("%s could not be read in full; change it by hand", target)}
		}
		fixed := 0
		for _, f := range t.Findings {
			switch {
			case f.Verdict == engine.Vulnerable || f.Verdict == engine.Unknown || f.Verdict == engine.Inactive:
				return "", &repo.Declined{Reason: fmt.Sprintf("%s still holds %s (%s); change it by hand", target, f.Path, f.Verdict)}
			case f.Facts["status"] == "fixed":
				fixed++
			}
		}
		if fixed == 0 {
			return "", &repo.Declined{Reason: fmt.Sprintf("no Java runtime with the fix was found in %s, so the fix is not proven; change it by hand", target)}
		}
		ref, err := name.ParseReference(target)
		if err != nil {
			return "", err
		}
		desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx), remote.WithTransport(netguard.Transport(o.PublicOnly)))
		if err != nil {
			return "", err
		}
		return desc.Digest.String(), nil
	}
}
