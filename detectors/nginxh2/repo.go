package nginxh2

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/repo"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/netguard"
	"github.com/DefectDojo/earlylight/internal/refs"
	"github.com/DefectDojo/earlylight/internal/source"
)

// Kind IDs for a source tree.
const (
	KindImagePin   = repo.RuleImage
	KindPackage    = repo.RulePackage
	KindHTTP2      = repo.RuleHTTP2
	KindNotChecked = repo.RuleNotChecked
	KindImage      = "image"
)

func repoKinds() []engine.Kind {
	cwe := []string{"CWE-787", "CWE-416"}
	return []engine.Kind{
		{ID: KindImagePin, Title: "Source tree uses an nginx image without the fix for the HTTP/2 pair", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: cwe,
			Description: "A Dockerfile, Compose, Kubernetes, Helm values or CI file names an nginx image (the official nginx image, nginx-unprivileged, OpenResty, Bitnami, the ingress-nginx controller, the F5 NGINX Ingress Controller, Angie) whose tag is a release without the fix for CVE-2026-123007 and CVE-2026-123633, or a Helm chart deploys ingress-nginx, which will publish no fix."},
		{ID: KindImage, Title: "Image the source tree uses holds an nginx vulnerable to the HTTP/2 pair", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: cwe,
			Description: "An image the tree builds on or deploys under a moving tag or a digest, read from its registry for linux/amd64 and linux/arm64 and judged as scan image does."},
		{ID: KindPackage, Title: "Dockerfile installs nginx without the fix for the HTTP/2 pair", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: cwe,
			Description: "An apt, apk, dnf, yum, microdnf or zypper install of nginx, OpenResty or Angie pinned to a release without the fix, or without a version from a distribution that had published no fixed package."},
		{ID: KindHTTP2, Title: "nginx configuration turns HTTP/2 on", Level: "note",
			Description: "An nginx configuration in the tree (a file, a template or a ConfigMap) turns HTTP/2 on, which makes an nginx without the fix reachable. A setting, not a vulnerable build; fix prints the interim HTTP/2-off edit and never applies it."},
		{ID: KindNotChecked, Title: "nginx not checked for the fix for the HTTP/2 pair", Level: "note",
			Description: "An nginx image whose tag does not name one release (a moving tag, a digest) that was not read, a package whose release the file does not show, or a file or reference that could not be read. It is not known to be safe."},
	}
}

// ScanRepo checks a source tree.
func (d *Detector) ScanRepo(ctx context.Context, dir string, o engine.Options) *engine.Target {
	t := &engine.Target{Name: dir, Type: engine.Repository}
	res, err := repo.Scan(ctx, dir, repo.Options{})
	if err != nil {
		t.Error = err.Error()
		return t
	}
	t.Files = res.Files
	if res.Truncated {
		t.Incomplete = "the source tree has too many files to walk; what lies past the limit is not checked"
	}
	pulls := map[string][]*engine.Target{}
	for _, f := range res.Findings {
		if f.Pull != "" && !o.Offline {
			t.Findings = append(t.Findings, d.pulled(ctx, f, o, pulls, t)...)
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

var repoVerdicts = map[knowledge.Status]engine.Verdict{
	knowledge.Vulnerable:  engine.Vulnerable,
	knowledge.Unknown:     engine.Unknown,
	knowledge.NotAffected: engine.Inactive,
	knowledge.Fixed:       engine.Fixed,
}

func repoFinding(f repo.Finding) engine.Finding {
	v, ok := repoVerdicts[f.Status]
	if !ok {
		v = engine.Unknown
	}
	reason := f.Reason
	if reason == "" && v != engine.Vulnerable {
		reason = "not decided"
	}
	facts := map[string]string{"status": string(f.Status)}
	for k, val := range f.Props {
		facts[k] = val
	}
	out := engine.Finding{Kind: f.Rule, Path: f.File, Line: f.Line, Verdict: v, Reason: reason, Message: f.Message, Method: "source", Facts: facts, Fix: f.Fix}
	for _, c := range f.CVEs {
		cv, ok := repoVerdicts[c.Status]
		if !ok {
			cv = engine.Unknown
		}
		out.CVEs = append(out.CVEs, engine.CVEResult{ID: c.ID, Verdict: cv, Reason: c.Reason})
	}
	if out.CVEs == nil && f.Rule != repo.RuleHTTP2 {
		for _, c := range knowledge.CVEs {
			out.CVEs = append(out.CVEs, engine.CVEResult{ID: c.ID, Verdict: v, Reason: reason})
		}
	}
	if f.Level == "warning" {
		out.Severity = "medium"
	}
	return out
}

// Limits on what one source-tree scan reads from registries.
const (
	maxRepoImages = 20
	pullTimeout   = 5 * time.Minute
)

// repoPlatforms are the platforms a pulled image is judged on: the ones
// the tree builds (--platform), else linux/amd64 and linux/arm64, where
// nginx is affected alike.
func repoPlatforms(o engine.Options, fromLine string) []string {
	if fromLine != "" && !strings.Contains(fromLine, "$") {
		return []string{fromLine}
	}
	if len(o.Platforms) > 0 {
		return o.Platforms
	}
	return []string{"linux/amd64", "linux/arm64"}
}

// pulled reads an image the tree references through the guarded
// transport on each platform, and reports what it holds at the
// reference.
func (d *Detector) pulled(ctx context.Context, f repo.Finding, o engine.Options, cache map[string][]*engine.Target, t *engine.Target) []engine.Finding {
	img := f.Pull
	key := img + "|" + f.Platform
	its, ok := cache[key]
	if !ok {
		if len(cache) >= maxRepoImages {
			t.Skipped = append(t.Skipped, source.Skip{Path: fmt.Sprintf("%s:%d", f.File, f.Line), Reason: fmt.Sprintf("image %s not pulled: this scan already pulled %d images", img, maxRepoImages)})
			return []engine.Finding{repoFinding(f)}
		}
		have, err := platforms(ctx, img, o)
		want := repoPlatforms(o, f.Platform)
		switch {
		case err != nil:
			its = []*engine.Target{{Name: img, Error: err.Error()}}
		case have == nil:
			// One image, not an index: its own platform.
			its = []*engine.Target{d.scanImage(img, "", o)}
		default:
			for _, p := range want {
				if !containsPlatform(have, p) {
					continue
				}
				its = append(its, d.scanImage(img, p, o))
			}
			if len(its) == 0 {
				its = []*engine.Target{{Name: img, Error: fmt.Sprintf("the image has none of the platforms %s", strings.Join(want, ", "))}}
			}
		}
		cache[key] = its
	}
	var out []engine.Finding
	for _, it := range its {
		out = append(out, fromPulled(f, it)...)
	}
	return out
}

func containsPlatform(have []string, p string) bool {
	for _, h := range have {
		if h == p || strings.HasPrefix(h, p+"/") {
			return true
		}
	}
	return false
}

func (d *Detector) scanImage(ref, platform string, o engine.Options) *engine.Target {
	return engine.ScanImage([]engine.Detector{d}, ref, engine.Options{Platform: platform, MaxFileSize: o.MaxFileSize, Guarded: true, PublicOnly: o.PublicOnly})
}

// fromPulled turns what an image scan found into findings at the
// reference. An image read only in part, where nothing was found, is not
// checked: no finding is not proof of no nginx.
func fromPulled(f repo.Finding, it *engine.Target) (out []engine.Finding) {
	img := f.Pull
	at := img
	if it.Platform != "" {
		at += " (" + it.Platform + ")"
	}
	if it.Error != "" {
		g := repoFinding(f)
		g.Message = fmt.Sprintf("image %s could not be read for the nginx HTTP/2 pair: %s", at, refs.CleanText(it.Error, 300))
		g.Reason = "the image could not be read"
		for i := range g.CVEs {
			g.CVEs[i].Reason = g.Reason
		}
		return []engine.Finding{g}
	}
	partial := it.Incomplete != "" || it.Gaps() > 0 || len(it.Problems) > 0
	found := false
	for _, x := range it.Findings {
		found = true
		if x.Verdict.Cleared() {
			continue
		}
		g := x
		g.Kind, g.Path, g.Line, g.Method = KindImage, f.File, f.Line, "registry"
		g.Facts = map[string]string{}
		for k, v := range x.Facts {
			g.Facts[k] = v
		}
		g.Facts["image"], g.Facts["server"] = img, x.Path
		if it.Digest != "" {
			g.Facts["digest"] = it.Digest
		}
		if it.Platform != "" {
			g.Facts["platform"] = it.Platform
		}
		g.Message = fmt.Sprintf("image %s (%s): %s: %s", at, it.Digest, x.Path, x.Message)
		g.Fix = x.Fix + " Use a release of " + img + " built with the fix (nginx 1.31.9 or 1.30.7), then redeploy."
		out = append(out, g)
	}
	switch {
	case len(out) > 0:
	case partial:
		// Read in part: what was read clearing (or nothing found) does
		// not clear the image.
		g := repoFinding(f)
		g.Verdict, g.Reason = engine.Unknown, "the image could not be read in full, so an nginx in it may have been missed"
		g.Message = fmt.Sprintf("image %s (%s) was read only in part (%d files not scanned, %d problems): not checked", at, it.Digest, it.Gaps(), len(it.Problems))
		for i := range g.CVEs {
			g.CVEs[i].Verdict, g.CVEs[i].Reason = g.Verdict, g.Reason
		}
		out = append(out, g)
	case !found:
		// An nginx image in which no nginx binary was recognised (a packed
		// or renamed build): not checked, never clean.
		g := repoFinding(f)
		g.Verdict, g.Reason = engine.Unknown, "no nginx binary was recognised in an image of an nginx family"
		g.Message = fmt.Sprintf("image %s (%s): no nginx binary was recognised in it: not checked", at, it.Digest)
		for i := range g.CVEs {
			g.CVEs[i].Verdict, g.CVEs[i].Reason = g.Verdict, g.Reason
		}
		out = append(out, g)
	}
	return out
}

// platforms lists the platforms of an image through the guarded
// transport, within the timeout; nil for a single image.
func platforms(ctx context.Context, ref string, o engine.Options) ([]string, error) {
	if err := registryRef(ref); err != nil {
		return nil, err
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithTransport(netguard.Transport(o.PublicOnly)), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	if !desc.MediaType.IsIndex() {
		return nil, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range m.Manifests {
		if d.Platform == nil || d.Platform.OS == "unknown" || d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		out = append(out, d.Platform.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is an image index with no images (it may still be being published)", ref)
	}
	sort.Strings(out)
	return out, nil
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

// verifier reads the replacement image and requires: every platform the
// tree builds (--platform), or else every platform the current tag has, is
// published for it; on each platform judged
// (linux/amd64 and linux/arm64, or --platform) it is read in full and
// every nginx in it has the fix for both CVEs (at least one nginx found);
// and it is on the same base OS as the current image.
func (d *Detector) verifier(o engine.Options) func(ctx context.Context, current, target string) (string, error) {
	return func(ctx context.Context, current, target string) (string, error) {
		if err := registryRef(target); err != nil {
			return "", err
		}
		cur, curErr := platforms(ctx, current, o)
		tp, err := platforms(ctx, target, o)
		if err != nil {
			return "", err
		}
		// The platforms that must be there: those the tree builds
		// (--platform), else every one the current tag has.
		need, from := cur, current+" has"
		switch {
		case len(o.Platforms) > 0:
			need, from = o.Platforms, "the tree builds (--platform)"
		case curErr != nil:
			return "", &repo.Declined{Reason: fmt.Sprintf("the platforms of %s could not be listed (%v), so whether %s covers them is not checked; rescan to confirm, or name the platforms you build with --platform", current, curErr, target)}
		}
		if tp == nil && len(need) > 1 {
			return "", &repo.Declined{Reason: fmt.Sprintf("%s is a single image, and %s needs %s; change it by hand", target, from, strings.Join(need, ", "))}
		}
		for _, p := range need {
			if tp != nil && !containsPlatform(tp, p) {
				return "", &repo.Declined{Reason: fmt.Sprintf("%s is not published for %s, which %s (it may still be being published); try again later or change it by hand", target, p, from)}
			}
		}
		judge := repoPlatforms(o, "")
		if tp == nil {
			judge = []string{""}
		}
		curOS := ""
		if curErr == nil {
			c := d.scanImage(current, firstOf(judge, tp), o)
			if c.Error == "" {
				curOS = annotation(c, "nginxh2_os")
			}
		}
		judged := 0
		for _, p := range judge {
			if p != "" && !containsPlatform(tp, p) {
				continue
			}
			t := d.scanImage(target, p, o)
			where := target
			if p != "" {
				where += " (" + p + ")"
			}
			if t.Error != "" {
				return "", fmt.Errorf("reading %s: %s", where, t.Error)
			}
			if t.Incomplete != "" || t.Gaps() > 0 || len(t.Problems) > 0 {
				return "", &repo.Declined{Reason: fmt.Sprintf("%s could not be read in full; change it by hand", where)}
			}
			fixed := 0
			for _, f := range t.Findings {
				if f.Verdict != engine.Fixed {
					return "", &repo.Declined{Reason: fmt.Sprintf("%s still holds %s (%s for %s); change it by hand", where, f.Path, f.Verdict, f.Kind)}
				}
				fixed++
			}
			if fixed == 0 {
				return "", &repo.Declined{Reason: fmt.Sprintf("no nginx was found in %s, so the fix could not be shown; change it by hand", where)}
			}
			_, tag, _ := strings.Cut(target[strings.LastIndex(target, "/")+1:], ":")
			if curOS != "" || !repo.NamesBaseOS(tag) {
				if err := repo.SameBase(curOS, annotation(t, "nginxh2_os")); err != nil {
					return "", err
				}
			}
			judged++
		}
		if judged == 0 {
			return "", &repo.Declined{Reason: fmt.Sprintf("%s has none of the platforms %s; change it by hand", target, strings.Join(judge, ", "))}
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

func firstOf(judge, have []string) string {
	for _, p := range judge {
		if p == "" || containsPlatform(have, p) {
			return p
		}
	}
	return ""
}

func annotation(t *engine.Target, key string) string {
	if t == nil || t.Error != "" {
		return ""
	}
	v, _ := t.Annotations[key].(string)
	return v
}

// Fix moves image tags to the first fixed release of the same line and
// variant, after reading the new image. Everything else is explained: a
// package without a published fix, a moving tag, an image with no fixed
// tag, and the optional HTTP/2-off edit, which is never applied.
func (d *Detector) Fix(ctx context.Context, dirs []string, o engine.Options, stdout, stderr io.Writer) int {
	reg := repo.Registry{}
	if !o.Offline {
		reg.Tags = tagLister(o)
		reg.Verify = d.verifier(o)
	}
	code := 0
	for _, dir := range dirs {
		res, err := repo.Scan(ctx, dir, repo.Options{})
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", repo.Printable(dir), err)
			return 2
		}
		if res.Truncated {
			fmt.Fprintf(stdout, "incomplete %s: the source tree has too many files to walk; what lies past the limit is not checked\n", repo.Printable(dir))
			code = max(code, 1)
		}
		for _, sk := range res.Skips {
			where := sk.File
			if sk.Line > 0 {
				where = fmt.Sprintf("%s:%d", sk.File, sk.Line)
			}
			fmt.Fprintf(stdout, "not checked %s  %s; rescan to confirm once it can be read\n", repo.Printable(where), repo.Printable(sk.Reason))
			code = max(code, 1)
		}
		pulls := map[string][]*engine.Target{}
		for _, f := range res.Findings {
			where := fmt.Sprintf("%s:%d", repo.Printable(f.File), f.Line)
			switch {
			case f.Rule == repo.RuleHTTP2:
				fmt.Fprintf(stdout, "note       %s  %s\n           optional interim edit (not applied, not a fix):\n           %s\n", where, repo.Printable(f.Message), repo.Printable(f.Interim))
				continue
			case f.Pull != "":
				if o.Offline {
					fmt.Fprintf(stdout, "not checked %s  %s (offline: the image was not read); rescan online to confirm\n", where, repo.Printable(f.Message))
					code = max(code, 1)
					continue
				}
				for _, g := range d.pulled(ctx, f, o, pulls, &engine.Target{}) {
					verb := "not fixed "
					if g.Verdict == engine.Unknown {
						verb = "not checked"
					}
					fmt.Fprintf(stdout, "%s %s  %s\n           %s\n", verb, where, repo.Printable(g.Message), repo.Printable(g.Fix))
					code = max(code, 1)
				}
				continue
			case f.Status == knowledge.Unknown || f.Rule == repo.RuleNotChecked:
				fmt.Fprintf(stdout, "not checked %s  %s\n           %s\n", where, repo.Printable(f.Message), repo.Printable(f.Fix))
				code = max(code, 1)
				continue
			case !f.Fixable:
				fmt.Fprintf(stdout, "not fixed  %s  %s\n           %s\n", where, repo.Printable(f.Message), repo.Printable(f.Fix))
				if f.Interim != "" {
					fmt.Fprintf(stdout, "           optional interim step (not applied, not a fix): %s\n", repo.Printable(f.Interim))
				}
				code = max(code, 1)
				continue
			}
			ch, err := repo.Plan(ctx, dir, f, reg, repo.Options{})
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
