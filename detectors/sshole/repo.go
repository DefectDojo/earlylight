package sshole

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/DefectDojo/earlylight/detectors/sshole/internal/repo"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/image"
	"github.com/DefectDojo/earlylight/internal/netguard"
	"github.com/DefectDojo/earlylight/internal/refs"
	"github.com/DefectDojo/earlylight/internal/source"
)

// Kind IDs for a source tree.
const (
	KindAPKPin     = repo.RulePin
	KindAPKFloor   = repo.RuleUnpinned
	KindEOL        = repo.RuleEOL
	KindStar       = repo.RuleStar
	KindPassword   = repo.RulePassword
	KindNotChecked = repo.RuleNotChecked
)

func repoKinds() []engine.Kind {
	cwe := []string{"CWE-287", "CWE-253"}
	return []engine.Kind{
		{ID: KindAPKPin, Title: "Dockerfile pins an Alpine OpenSSH server package without the *sshole fix", Level: "error", SecuritySeverity: "9.8", CWEs: cwe,
			Description: "An apk add of openssh, openssh-server, openssh-server-pam or openssh-server-krb5 pinned to a release older than the fixed package for the image's Alpine branch."},
		{ID: KindAPKFloor, Title: "Dockerfile installs an Alpine OpenSSH server with no floor at the *sshole fix", Level: "warning", SecuritySeverity: "6.5", CWEs: cwe,
			Description: "An apk add of an OpenSSH server package with no version floor. Images built before 2026-11-05, or rebuilt from a cached layer, keep the vulnerable package; a floor at the fixed release rebuilds the layer and fails the build if the fix is missing."},
		{ID: KindEOL, Title: "OpenSSH server built on an Alpine release with no *sshole fix", Level: "warning", SecuritySeverity: "6.5", CWEs: cwe,
			Description: "A Dockerfile stage that installs an OpenSSH server on an Alpine release before 3.16, for which Alpine published no fixed package."},
		{ID: KindStar, Title: "Account password field set to \"*\"", Level: "error", SecuritySeverity: "8.1", CWEs: cwe,
			Description: "A Dockerfile, script or Ansible or cloud-init task that sets an account's password field to \"*\" (usermod -p, chpasswd -e, sed on /etc/shadow). On an OpenSSH server on musl without the fix, a crafted password logs in to that account. \"*NP*\" keeps key logins and matches no password on any build."},
		{ID: KindPassword, Title: "PasswordAuthentication turned on", Level: "note",
			Description: "Something turns PasswordAuthentication on. With an OpenSSH server on musl that lacks the fix, every account with the password field \"*\" is exposed."},
		{ID: KindImage, Title: "Image the source tree uses runs an OpenSSH server exposed to *sshole", Level: "error", SecuritySeverity: "9.8", CWEs: cwe,
			Description: "An image a Dockerfile, Compose file, Kubernetes manifest, Helm values or CI file names holds an OpenSSH server on musl without the fix, judged as scan image does, with the command the file sets for it."},
		{ID: KindNotChecked, Title: "OpenSSH install not checked for the *sshole fix", Level: "note",
			Description: "An apk add of an OpenSSH server whose base image could not be identified, or a file that could not be read. It is not known to be safe."},
	}
}

// ScanRepo checks a source tree.
func (d *Detector) ScanRepo(ctx context.Context, dir string, o engine.Options) *engine.Target {
	t := &engine.Target{Name: dir, Type: engine.Repository}
	res, err := repo.Scan(ctx, dir, repoOptions(o))
	if err != nil {
		t.Error = err.Error()
		return t
	}
	if !o.Offline {
		d.scanImages(dir, o, t)
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

func repoFinding(f repo.Finding) engine.Finding {
	v, reason := engine.Vulnerable, ""
	switch f.Rule {
	case repo.RuleNotChecked:
		v, reason = engine.Unknown, "the base image could not be identified"
	case repo.RulePassword:
		v, reason = engine.Inactive, "a setting, not a vulnerable build: it matters only with an affected OpenSSH server"
	}
	facts := map[string]string{}
	for k, val := range f.Props {
		facts[k] = val
	}
	out := engine.Finding{Kind: f.Rule, Path: f.File, Line: f.Line, Verdict: v, Reason: reason, Message: f.Message, Method: "source", Facts: facts, Fix: f.Fix}
	if f.Level == "warning" {
		out.Severity = "medium"
	}
	return out
}

func repoOptions(o engine.Options) repo.Options {
	ro := repo.Options{Base: baseResolver(o)}
	if !o.Offline {
		ro.Tags = tagLister(o)
	}
	return ro
}

// KindImage: an image the source tree builds on or deploys holds an
// OpenSSH server exposed to *sshole.
const KindImage = "image"

// maxRepoImages bounds the images one source-tree scan pulls.
const maxRepoImages = 20

// scanImages pulls the images the tree references (Dockerfile FROM,
// Compose, Kubernetes, Helm values, CI) through the guarded transport and
// judges them like scan image does, with the command a Compose service or
// Kubernetes container sets in place of the image's own.
func (d *Detector) scanImages(dir string, o engine.Options, t *engine.Target) {
	rs, _, err := refs.Scan(dir, refs.Options{})
	if err != nil {
		t.Problems = append(t.Problems, "image references: "+err.Error())
		return
	}
	type key struct{ image, cmd string }
	seen := map[key]bool{}
	pulled := 0
	for _, r := range rs {
		if r.Image == "" || r.Image == "scratch" || strings.Contains(r.Image, "$") {
			continue
		}
		ov := repo.OverrideFor(dir, r, nil)
		k := key{r.Image, fmt.Sprint(ov)}
		if ov != nil && ov.Entrypoint != nil {
			k.cmd = strings.Join(*ov.Entrypoint, " ")
		}
		if ov != nil && ov.Cmd != nil {
			k.cmd += "|" + strings.Join(*ov.Cmd, " ")
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		if pulled >= maxRepoImages {
			t.Skipped = append(t.Skipped, source.Skip{Path: fmt.Sprintf("%s:%d", r.File, r.Line), Reason: fmt.Sprintf("image %s not pulled: this scan already pulled %d images", r.Image, maxRepoImages)})
			continue
		}
		pulled++
		eo := engine.Options{Platform: o.Platform, MaxFileSize: o.MaxFileSize, Guarded: true, PublicOnly: o.PublicOnly}
		if ov != nil {
			eo.Override = &engine.CommandOverride{Entrypoint: ov.Entrypoint, Cmd: ov.Cmd, ClearCmd: ov.ClearCmd}
		}
		it := engine.ScanImage([]engine.Detector{d}, r.Image, eo)
		if it.Error != "" {
			t.Findings = append(t.Findings, engine.Finding{Kind: KindNotChecked, Path: r.File, Line: r.Line, Verdict: engine.Unknown,
				Reason: "the image could not be pulled", Message: fmt.Sprintf("image %s could not be checked for *sshole: %s", r.Image, it.Error), Method: "registry",
				Facts: map[string]string{"image": r.Image}})
			continue
		}
		for _, f := range it.Findings {
			if f.Verdict.Cleared() {
				continue
			}
			g := f
			g.Kind, g.Path, g.Line, g.Method = KindImage, r.File, r.Line, "registry"
			if g.Facts == nil {
				g.Facts = map[string]string{}
			}
			g.Facts["image"], g.Facts["server"] = r.Image, f.Path
			via := ""
			if ov != nil {
				via = " (with the command this file sets)"
				g.Facts["command_override"] = "yes"
			}
			g.Message = fmt.Sprintf("image %s%s: %s: %s", r.Image, via, f.Path, f.Message)
			g.Fix = f.Fix + " Use a release of " + r.Image + " built with the fix, or rebuild it; then redeploy."
			if f.Kind == KindExposed && g.Severity == "" {
				g.Severity = "critical"
			}
			t.Findings = append(t.Findings, g)
		}
	}
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

// baseResolver reads /etc/alpine-release from the images a tree builds on,
// once each, unless the run is offline.
func baseResolver(o engine.Options) func(context.Context, string) (bool, string, error) {
	if o.Offline {
		return nil
	}
	type res struct {
		alpine bool
		branch string
		err    error
	}
	var mu sync.Mutex
	cache := map[string]res{}
	return func(_ context.Context, ref string) (bool, string, error) {
		mu.Lock()
		defer mu.Unlock()
		if r, ok := cache[ref]; ok {
			return r.alpine, r.branch, r.err
		}
		if err := registryRef(ref); err != nil {
			cache[ref] = res{err: err}
			return false, "", err
		}
		if len(cache) >= maxBases {
			err := fmt.Errorf("not resolved: this scan already read %d base images, its limit", maxBases)
			return false, "", err
		}
		platform := o.Platform
		if platform == "" && len(o.Platforms) > 0 {
			platform = o.Platforms[0]
		}
		a, b, err := repo.AlpineOf(func() (io.ReadCloser, error) {
			// The guarded transport refuses link-local addresses (cloud
			// metadata) always, and with --public-registries-only every
			// loopback, private and internal one, on each connection and
			// redirect.
			op, err := image.OpenRegistry(ref, platform, netguard.Transport(o.PublicOnly))
			if err != nil {
				return nil, err
			}
			return limitedReadCloser{io.LimitReader(op.FS, maxBaseBytes), op.FS}, nil
		})
		cache[ref] = res{a, b, err}
		return a, b, err
	}
}

// Limits on base-image lookups: a source tree may not be yours, so what it
// names cannot make a scan read without bound.
const (
	maxBases     = 32
	maxBaseBytes = 2 << 30
)

type limitedReadCloser struct {
	io.Reader
	io.Closer
}

// registryRef accepts only a registry reference: never a local archive
// (docker-archive:, rootfs:) or any other transport a Dockerfile could
// name. Addresses are checked by the guarded transport when it connects.
func registryRef(ref string) error {
	if strings.Contains(ref, "://") || strings.HasPrefix(ref, "docker-archive:") || strings.HasPrefix(ref, "rootfs:") || strings.HasPrefix(ref, "/") {
		return fmt.Errorf("%q is not a registry reference", ref)
	}
	if _, err := name.ParseReference(ref); err != nil {
		return fmt.Errorf("%q is not a valid image reference", ref)
	}
	return nil
}

// Fix rewrites what can be fixed: apk constraints to the fixed release and
// "*" password fields to "*NP*". Each edit is rescanned in memory first.
func (d *Detector) Fix(ctx context.Context, dirs []string, o engine.Options, stdout, stderr io.Writer) int {
	code := 0
	opts := repoOptions(o)
	for _, dir := range dirs {
		res, err := repo.Scan(ctx, dir, opts)
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
		for _, f := range res.Findings {
			if f.Level == "note" && f.Rule != repo.RuleNotChecked {
				continue
			}
			where := fmt.Sprintf("%s:%d", repo.Printable(f.File), f.Line)
			if !f.Fixable {
				fmt.Fprintf(stdout, "not fixed  %s  %s\n           %s\n", where, repo.Printable(f.Message), repo.Printable(f.Fix))
				code = max(code, 1)
				continue
			}
			ch, already, err := repo.Plan(ctx, dir, f, opts)
			switch {
			case already:
				continue
			case err != nil:
				fmt.Fprintf(stdout, "not fixed  %s  %s\n", where, repo.Printable(err.Error()))
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
	out := ""
	for _, l := range splitLines(s) {
		out += "           " + l + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
