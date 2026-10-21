// Package registry resolves image references against their registries and
// decides, from image configuration alone, which PHP release each platform of
// an image carries.
//
// Only manifests and image configs are read; layers are never downloaded. A
// PHP version is claimed only when an image config carries the build
// environment of the official php image (github.com/docker-library/php), which
// images built FROM php inherit:
//
//	PHP_VERSION=X.Y.Z
//	PHP_URL=https://www.php.net/distributions/php-X.Y.Z.tar.xz   (or .gz, .bz2;
//	        older images: https://secure.php.net/get/php-X.Y.Z.tar.xz/from/this/mirror)
//	PHP_SHA256=<64 hex digits>   (very old images: PHP_MD5=<32 hex digits>)
//
// Anything else makes no claim: an image that installs PHP some other way may
// well contain PHP, but its config does not prove which release.
package registry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Options configure a Resolver.
type Options struct {
	// Offline makes no network requests. Only a docker.io/library/php
	// reference with an exact X.Y.Z tag and no digest resolves (the official
	// tags are the PHP version); everything else returns an Error of kind
	// KindOffline.
	Offline bool
	// Keychain supplies registry credentials (default authn.DefaultKeychain,
	// which reads the Docker config and credential helpers).
	Keychain authn.Keychain
	// Transport is the base HTTP transport (default: go-containerregistry's
	// remote.DefaultTransport with a 30 s response header timeout).
	Transport http.RoundTripper
	// Timeout bounds each Resolve and Tags call (default 2 minutes).
	Timeout time.Duration
	// Retries is how many times a request is retried after HTTP 429, 500, 502,
	// 503, 504 or a transient network error (default 4; negative for none).
	Retries int
	// MinBackoff and MaxBackoff bound the exponential backoff between retries
	// (defaults 1 s and 30 s). A Retry-After header longer than MaxRetryAfter
	// (default 60 s) is not waited for: the request fails as rate limited.
	MinBackoff, MaxBackoff, MaxRetryAfter time.Duration
	// Concurrency is the most registry requests in flight (default 4).
	Concurrency int
	// Mirrors sends requests for a registry to another host
	// ({"index.docker.io": "mirror.example.com"}). The reference keeps its
	// name; only the host contacted changes. Tests point Docker Hub at an
	// in-memory registry this way.
	Mirrors map[string]string
	// UserAgent is sent with every request (default "php2shell-scan").
	UserAgent string
	// Platforms, when set, restricts every Resolution to these platforms
	// ("linux/amd64", "linux/arm64"; see PlatformMatches): images for other
	// platforms are left out and listed in Resolution.OmittedPlatforms.
	Platforms []string
	// RequestTimeout bounds the wait for each response's headers (default
	// 30 s) and, at twice that, for its body, whatever Transport is given. A
	// registry host that times out is not contacted again by this Resolver:
	// later requests to it fail at once (as KindTimeout).
	RequestTimeout time.Duration
}

// Resolution is what a reference points at.
type Resolution struct {
	// Ref is the reference as given; Reference is its parsed form.
	Ref       string    `json:"ref"`
	Reference Reference `json:"-"`
	// Digest is the digest of the manifest or index the reference points at.
	Digest    string `json:"digest,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	// Index is true when the reference points at an image index (manifest
	// list).
	Index bool `json:"index,omitempty"`
	// Empty is true when the reference exists but holds no images: an index
	// whose only manifests are attestations, or none at all. Docker Hub
	// publishes new tags this way before their builds finish.
	Empty bool `json:"empty,omitempty"`
	// Platforms lists every image the reference holds, in index order.
	Platforms []Platform `json:"platforms,omitempty"`
	// Offline is true when the result comes from offline rules.
	Offline bool `json:"offline,omitempty"`
	// OmittedPlatforms lists the platforms left out by a platform filter
	// (Options.Platforms, FilterPlatforms).
	OmittedPlatforms []string `json:"omitted_platforms,omitempty"`
}

// Platform is one image of a Resolution.
type Platform struct {
	// Platform is os/arch[/variant]; "" when unknown (offline resolution).
	Platform string    `json:"platform"`
	Digest   string    `json:"digest,omitempty"`
	Created  time.Time `json:"created,omitempty"`
	// PHPVersion is set only when the image config proves it (see the package
	// documentation); Evidence says how.
	PHPVersion string   `json:"php_version,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	// BaseOS is the base operating system release the image is built on,
	// normalized ("alpine:3.21", "debian:bookworm"), from the
	// org.opencontainers.image.base.name annotation (BaseSource
	// "annotation") or, failing that, from the first history entry the
	// docker-library build leaves (BaseSource "history"); "" when unknown.
	BaseOS     string `json:"base_os,omitempty"`
	BaseSource string `json:"base_source,omitempty"`
	// ImageVersion is the org.opencontainers.image.version annotation; for
	// the official php image it is the explicit tag ("8.3.20-fpm-alpine3.21").
	ImageVersion string `json:"image_version,omitempty"`
}

// ErrorKind classifies resolution failures.
type ErrorKind int

const (
	KindNetwork     ErrorKind = iota // the registry could not be reached or failed
	KindNotFound                     // the tag, digest or repository does not exist
	KindDenied                       // authentication required or refused (Docker Hub also answers this for repositories that do not exist)
	KindRateLimited                  // HTTP 429 after retries
	KindInvalid                      // not a valid reference
	KindUnsupported                  // a manifest the scanner does not read (schema 1, artifacts)
	KindOffline                      // offline mode cannot resolve the reference
	KindTimeout                      // a timeout or deadline expired (or the call was cancelled)
)

func (k ErrorKind) String() string {
	if k < 0 || int(k) >= len(kindNames) {
		return "network"
	}
	return kindNames[k]
}

var kindNames = [...]string{"network", "not-found", "denied", "rate-limited", "invalid", "unsupported", "offline", "timeout"}

// Transient reports whether an error kind (ErrorKind.String(), as in
// repocheck.Result.ErrorKind) may succeed on a later attempt: network,
// timeout and rate-limited failures. not-found, denied, invalid, unsupported
// and offline are definitive for this scan.
func Transient(kind string) bool {
	switch kind {
	case "network", "timeout", "rate-limited":
		return true
	}
	return false
}

// Error is a resolution failure.
type Error struct {
	Kind ErrorKind
	Ref  string
	Err  error
}

// Error is a single line. The underlying error's text, which can come from the
// registry's response body, is stripped of control characters and cut to
// about 200 characters.
func (e *Error) Error() string {
	msg := ""
	if e.Err != nil {
		msg = e.Err.Error()
	}
	return CleanText(e.Ref, 300) + ": " + e.Kind.String() + ": " + CleanText(msg, 200)
}
func (e *Error) Unwrap() error { return e.Err }

// permanent errors are cached; others (network, rate limit, cancellation) are
// retried by the next call.
func (e *Error) permanent() bool {
	switch e.Kind {
	case KindNotFound, KindDenied, KindInvalid, KindUnsupported, KindOffline:
		return true
	}
	return false
}

func classify(ref string, err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, errHostTimedOut) {
		return &Error{KindTimeout, ref, err}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &Error{KindTimeout, ref, err}
	}
	var te *transport.Error
	if errors.As(err, &te) {
		for _, d := range te.Errors {
			switch d.Code {
			case transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode, transport.BlobUnknownErrorCode:
				return &Error{KindNotFound, ref, err}
			case transport.UnauthorizedErrorCode, transport.DeniedErrorCode:
				return &Error{KindDenied, ref, err}
			case transport.TooManyRequestsErrorCode:
				return &Error{KindRateLimited, ref, err}
			}
		}
		switch te.StatusCode {
		case http.StatusNotFound:
			return &Error{KindNotFound, ref, err}
		case http.StatusUnauthorized, http.StatusForbidden:
			return &Error{KindDenied, ref, err}
		case http.StatusTooManyRequests:
			return &Error{KindRateLimited, ref, err}
		}
	}
	return &Error{KindNetwork, ref, err}
}

type call[T any] struct {
	done chan struct{}
	val  T
	err  error
}

// cache is a single-flight cache: concurrent and later calls for the same key
// share one result. Results that fail transiently are dropped once delivered.
type cache[T any] struct {
	mu sync.Mutex
	m  map[string]*call[T]
}

func (c *cache[T]) do(ctx context.Context, key string, fn func() (T, error)) (T, error) {
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]*call[T]{}
	}
	if cl, ok := c.m[key]; ok {
		c.mu.Unlock()
		select {
		case <-cl.done:
			return cl.val, cl.err
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}
	cl := &call[T]{done: make(chan struct{})}
	c.m[key] = cl
	c.mu.Unlock()
	cl.val, cl.err = fn()
	close(cl.done)
	if cl.err != nil {
		var e *Error
		if !errors.As(cl.err, &e) || !e.permanent() {
			c.mu.Lock()
			delete(c.m, key)
			c.mu.Unlock()
		}
	}
	return cl.val, cl.err
}

// Resolver resolves references, caching every result for its lifetime (one
// scan): the same reference, and the same manifest digest, are fetched once.
// It is safe for concurrent use.
type Resolver struct {
	opts      Options
	transport *retryTransport
	sem       chan struct{}
	puller    *remote.Puller
	pullerErr error
	refs      cache[*Resolution]
	digests   cache[*Resolution]
	images    cache[Platform]
	tags      cache[[]string]
	heads     cache[string]
}

// NewResolver returns a Resolver.
func NewResolver(opts Options) *Resolver {
	if opts.Keychain == nil {
		opts.Keychain = authn.DefaultKeychain
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 2 * time.Minute
	}
	if opts.Retries == 0 {
		opts.Retries = 4
	} else if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 30 * time.Second
	}
	if opts.MaxRetryAfter <= 0 {
		opts.MaxRetryAfter = 60 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "php2shell-scan"
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = 30 * time.Second
	}
	base := opts.Transport
	if base == nil {
		t := remote.DefaultTransport.(*http.Transport).Clone()
		t.ResponseHeaderTimeout = 30 * time.Second
		base = t
	}
	r := &Resolver{
		opts:      opts,
		transport: newRetryTransport(base, opts),
		sem:       make(chan struct{}, opts.Concurrency),
	}
	// One Puller per Resolver reuses each repository's authenticated
	// transport instead of pinging and fetching a token for every request.
	r.puller, r.pullerErr = remote.NewPuller(r.remoteOpts()...)
	return r
}

// Resolve resolves a reference with a new Resolver. Use a shared Resolver to
// benefit from caching across references.
func Resolve(ctx context.Context, ref string, opts Options) (*Resolution, error) {
	return NewResolver(opts).Resolve(ctx, ref)
}

// Stats reports the requests made so far.
func (r *Resolver) Stats() Stats { return r.transport.stats.snapshot() }

func (r *Resolver) acquire(ctx context.Context) error {
	select {
	case r.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Resolver) release() { <-r.sem }

func (r *Resolver) remoteOpts() []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(r.opts.Keychain),
		remote.WithTransport(r.transport),
		remote.WithUserAgent(r.opts.UserAgent),
		// Retries happen in retryTransport, which honours Retry-After; turn
		// go-containerregistry's own off so they do not multiply.
		remote.WithRetryBackoff(remote.Backoff{Steps: 1}),
		remote.WithRetryPredicate(func(error) bool { return false }),
		remote.WithRetryStatusCodes(),
	}
}

// repo returns the repository to contact for a reference (after mirrors).
func (r *Resolver) repo(ref Reference) (name.Repository, error) {
	host := ref.Registry
	if m, ok := r.opts.Mirrors[host]; ok {
		host = m
	}
	return name.NewRepository(host + "/" + ref.Path)
}

// Resolve resolves a reference: by digest when it has one (a digest wins over
// a tag, as in docker pull), otherwise by tag.
func (r *Resolver) Resolve(ctx context.Context, s string) (*Resolution, error) {
	ref, err := ParseReference(s)
	if err != nil {
		return nil, &Error{KindInvalid, s, err}
	}
	res, err := r.refs.do(ctx, ref.String(), func() (*Resolution, error) {
		ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		return r.resolve(ctx, ref)
	})
	if err != nil {
		return nil, err
	}
	// Each caller gets its own copy with its own spelling of the reference.
	cp := *res
	cp.Ref = s
	cp.Reference = ref
	cp.Platforms = append([]Platform(nil), res.Platforms...)
	if len(r.opts.Platforms) > 0 {
		return FilterPlatforms(&cp, r.opts.Platforms), nil
	}
	return &cp, nil
}

// PlatformMatches reports whether an image platform satisfies a requested
// one. Both are os/arch[/variant]; linux/arm64 and linux/arm64/v8 are the
// same; a request without a variant matches every variant of its os/arch
// ("linux/arm" matches linux/arm/v6 and linux/arm/v7), so all of them are
// judged.
func PlatformMatches(want, have string) bool {
	w, h := NormalizePlatform(want), NormalizePlatform(have)
	if w == h {
		return true
	}
	wp := strings.Split(w, "/")
	hp := strings.Split(h, "/")
	return len(wp) == 2 && len(hp) == 3 && wp[0] == hp[0] && wp[1] == hp[1]
}

// FilterPlatforms returns a copy of res holding only the images whose
// platform matches one of platforms (all of them when platforms is empty).
// The others are listed in OmittedPlatforms. An offline resolution (platform
// unknown) is returned unchanged.
func FilterPlatforms(res *Resolution, platforms []string) *Resolution {
	cp := *res
	cp.Platforms = nil
	cp.OmittedPlatforms = append([]string(nil), res.OmittedPlatforms...)
	for _, p := range res.Platforms {
		keep := len(platforms) == 0 || p.Platform == ""
		for _, w := range platforms {
			if PlatformMatches(w, p.Platform) {
				keep = true
			}
		}
		if keep {
			cp.Platforms = append(cp.Platforms, p)
		} else {
			cp.OmittedPlatforms = append(cp.OmittedPlatforms, p.Platform)
		}
	}
	return &cp
}

var exactOfficialTag = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)(?:-[a-z0-9.-]+)?$`)

func (r *Resolver) resolve(ctx context.Context, ref Reference) (*Resolution, error) {
	s := ref.String()
	if r.opts.Offline {
		if ref.IsOfficialPHP() && ref.Digest == "" {
			if m := exactOfficialTag.FindStringSubmatch(ref.Tag); m != nil {
				return &Resolution{
					Ref: s, Reference: ref, Offline: true,
					Platforms: []Platform{{
						PHPVersion: m[1],
						Evidence:   []string{fmt.Sprintf("from the tag: Docker Hub's official php image tags %q with PHP %s (offline, not checked against the registry)", ref.Tag, m[1])},
					}},
				}, nil
			}
		}
		return nil, &Error{KindOffline, s, errors.New("offline: only docker.io/library/php references with an exact X.Y.Z tag and no digest can be resolved without the registry")}
	}
	if r.pullerErr != nil {
		return nil, &Error{KindNetwork, s, r.pullerErr}
	}
	repo, err := r.repo(ref)
	if err != nil {
		return nil, &Error{KindInvalid, s, err}
	}
	dig := ref.Digest
	if dig == "" {
		dig, err = r.headTag(ctx, repo, ref.EffectiveTag())
		if err != nil {
			return nil, withRef(s, classify(s, err))
		}
	}
	res, err := r.digests.do(ctx, repo.String()+"@"+dig, func() (*Resolution, error) {
		return r.fetch(ctx, repo, dig)
	})
	if err != nil {
		return nil, withRef(s, classify(s, err))
	}
	return res, nil
}

func withRef(ref string, e *Error) *Error {
	cp := *e
	cp.Ref = ref
	return &cp
}

// fetch reads the manifest or index at a digest and every image it holds.
func (r *Resolver) fetch(ctx context.Context, repo name.Repository, dig string) (*Resolution, error) {
	s := repo.String() + "@" + dig
	desc, err := r.getManifest(ctx, repo, dig)
	if err != nil {
		return nil, classify(s, err)
	}
	res := &Resolution{Digest: desc.Digest.String(), MediaType: string(desc.MediaType)}
	switch {
	case desc.MediaType.IsIndex():
		res.Index = true
		im, err := v1.ParseIndexManifest(strings.NewReader(string(desc.Manifest)))
		if err != nil {
			return nil, &Error{KindUnsupported, s, fmt.Errorf("index does not parse: %w", err)}
		}
		type job struct {
			i    int
			desc v1.Descriptor
		}
		var jobs []job
		for _, m := range im.Manifests {
			if m.MediaType.IsIndex() {
				// A nested index would hide platforms; rather than report an
				// incomplete set, make no claim.
				return nil, &Error{KindUnsupported, s, errors.New("nested image index (not read)")}
			}
			if isAttestation(m) || !m.MediaType.IsImage() {
				continue
			}
			jobs = append(jobs, job{len(jobs), m})
		}
		if len(jobs) == 0 {
			res.Empty = true
			return res, nil
		}
		res.Platforms = make([]Platform, len(jobs))
		errs := make([]error, len(jobs))
		var wg sync.WaitGroup
		for _, j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res.Platforms[j.i], errs[j.i] = r.image(ctx, repo, j.desc.Digest.String(), &j.desc)
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, classify(s, err)
			}
		}
	case desc.MediaType.IsImage():
		p, err := r.image(ctx, repo, desc.Digest.String(), nil)
		if err != nil {
			return nil, classify(s, err)
		}
		res.Platforms = []Platform{p}
	case desc.MediaType.IsSchema1():
		return nil, &Error{KindUnsupported, s, errors.New("schema 1 manifest (deprecated, not read)")}
	default:
		return nil, &Error{KindUnsupported, s, fmt.Errorf("media type %q is not an image or index", desc.MediaType)}
	}
	return res, nil
}

// isAttestation reports whether an index entry is a BuildKit attestation
// manifest rather than a runnable image.
func isAttestation(d v1.Descriptor) bool {
	if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
		return true
	}
	return d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown"
}

// headTag finds a tag's digest with a HEAD request (Docker Hub does not count
// HEAD requests against pull limits), falling back to GET when the registry
// does not answer HEAD usefully.
func (r *Resolver) headTag(ctx context.Context, repo name.Repository, tag string) (string, error) {
	return r.heads.do(ctx, repo.String()+":"+tag, func() (string, error) {
		if err := r.acquire(ctx); err != nil {
			return "", err
		}
		defer r.release()
		t := repo.Tag(tag)
		d, err := r.puller.Head(ctx, t)
		if err == nil {
			return d.Digest.String(), nil
		}
		var te *transport.Error
		if !errors.As(err, &te) || ctx.Err() != nil {
			// Not an HTTP answer (unreachable, timed out): a GET would fail
			// the same way.
			return "", err
		}
		switch te.StatusCode {
		case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
			return "", classify(t.String(), err)
		}
		desc, err := r.puller.Get(ctx, t)
		if err != nil {
			return "", err
		}
		return desc.Digest.String(), nil
	})
}

func (r *Resolver) getManifest(ctx context.Context, repo name.Repository, dig string) (*remote.Descriptor, error) {
	if err := r.acquire(ctx); err != nil {
		return nil, err
	}
	defer r.release()
	return r.puller.Get(ctx, repo.Digest(dig))
}

const maxConfigSize = 8 << 20

// image reads one image manifest and its config (never its layers).
func (r *Resolver) image(ctx context.Context, repo name.Repository, dig string, desc *v1.Descriptor) (Platform, error) {
	p, err := r.images.do(ctx, repo.String()+"@"+dig, func() (Platform, error) {
		desc, err := r.getManifest(ctx, repo, dig)
		if err != nil {
			return Platform{}, err
		}
		if !desc.MediaType.IsImage() {
			return Platform{}, &Error{KindUnsupported, repo.String() + "@" + dig, fmt.Errorf("media type %q is not an image", desc.MediaType)}
		}
		m, err := v1.ParseManifest(strings.NewReader(string(desc.Manifest)))
		if err != nil {
			return Platform{}, &Error{KindUnsupported, repo.String() + "@" + dig, fmt.Errorf("manifest does not parse: %w", err)}
		}
		if m.Config.Size > maxConfigSize {
			return Platform{}, &Error{KindUnsupported, repo.String() + "@" + dig, fmt.Errorf("config is %d bytes, larger than %d", m.Config.Size, maxConfigSize)}
		}
		if !isImageConfig(m.Config.MediaType) {
			return Platform{}, &Error{KindUnsupported, repo.String() + "@" + dig, fmt.Errorf("config media type %q is not an image config", m.Config.MediaType)}
		}
		img, err := desc.Image()
		if err != nil {
			return Platform{}, err
		}
		if err := r.acquire(ctx); err != nil {
			return Platform{}, err
		}
		raw, err := img.RawConfigFile()
		r.release()
		if err != nil {
			return Platform{}, err
		}
		cfg, err := v1.ParseConfigFile(strings.NewReader(string(raw)))
		if err != nil {
			return Platform{}, &Error{KindUnsupported, repo.String() + "@" + dig, fmt.Errorf("config does not parse: %w", err)}
		}
		out := Platform{Digest: dig, Created: cfg.Created.Time}
		out.Platform = platformString(cfg.OS, cfg.Architecture, cfg.Variant)
		out.PHPVersion, out.Evidence = PHPFromEnv(cfg.Config.Env)
		out.ImageVersion = CleanText(m.Annotations[annVersion], 128)
		if b := BaseOSFromName(m.Annotations[annBaseName]); b != "" {
			out.BaseOS, out.BaseSource = b, "annotation"
		} else if b := baseOSFromHistory(cfg.History); b != "" {
			out.BaseOS, out.BaseSource = b, "history"
		}
		return out, nil
	})
	if err != nil {
		return Platform{}, err
	}
	if desc != nil {
		if desc.Platform != nil {
			p.Platform = platformString(desc.Platform.OS, desc.Platform.Architecture, desc.Platform.Variant)
		}
		// The index entry's annotations are as good as the manifest's.
		if p.BaseSource != "annotation" {
			if b := BaseOSFromName(desc.Annotations[annBaseName]); b != "" {
				p.BaseOS, p.BaseSource = b, "annotation"
			}
		}
		if p.ImageVersion == "" {
			p.ImageVersion = CleanText(desc.Annotations[annVersion], 128)
		}
	}
	return p, nil
}

const (
	annBaseName = "org.opencontainers.image.base.name"
	annVersion  = "org.opencontainers.image.version"
)

var (
	reAlpineRootfs = regexp.MustCompile(`^ADD alpine-minirootfs-([0-9]+\.[0-9]+)\.[0-9]+-[a-z0-9_]+\.tar\.gz / `)
	reDebianRootfs = regexp.MustCompile(`^# debian\.sh --arch '[a-z0-9]+' out/ '([a-z]+)' '@[0-9]+'`)
	reBaseName     = regexp.MustCompile(`^(?:(?:docker\.io|index\.docker\.io)/)?(?:library/)?([a-z0-9]+(?:[._-][a-z0-9]+)*):([a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})$`)
)

// BaseOSFromName normalizes an org.opencontainers.image.base.name value to
// family:release ("debian:bookworm-slim" becomes "debian:bookworm",
// "alpine:3.21" stays). It returns "" for anything that is not a plain
// repository:tag of an operating system image.
func BaseOSFromName(n string) string {
	m := reBaseName.FindStringSubmatch(n)
	if m == nil || !osFamilies[m[1]] {
		// Not an operating system image (wordpress's base is php:8.3-apache,
		// which itself moves between Debian releases): fall back to history.
		return ""
	}
	return m[1] + ":" + strings.TrimSuffix(m[2], "-slim")
}

// osFamilies are base images that are operating system releases.
var osFamilies = map[string]bool{
	"alpine": true, "debian": true, "ubuntu": true, "centos": true, "fedora": true, "rockylinux": true,
	"almalinux": true, "amazonlinux": true, "oraclelinux": true, "photon": true, "busybox": true,
}

// baseOSFromHistory reads the base release from the first history entry of a
// docker-library image: Alpine's "ADD alpine-minirootfs-3.21.3-x86_64.tar.gz /"
// or Debian's "# debian.sh --arch 'amd64' out/ 'bookworm' '@...'".
func baseOSFromHistory(h []v1.History) string {
	if len(h) == 0 {
		return ""
	}
	c := h[0].CreatedBy
	if m := reAlpineRootfs.FindStringSubmatch(c); m != nil {
		return "alpine:" + m[1]
	}
	if m := reDebianRootfs.FindStringSubmatch(c); m != nil {
		return "debian:" + m[1]
	}
	return ""
}

func isImageConfig(mt types.MediaType) bool {
	return mt == types.DockerConfigJSON || mt == types.OCIConfigJSON || mt == ""
}

// platformString builds os/arch[/variant]; the parts come from the
// registry, so they are cleaned.
func platformString(os, arch, variant string) string {
	s := CleanText(os, 32) + "/" + CleanText(arch, 32)
	if variant != "" {
		s += "/" + CleanText(variant, 32)
	}
	return s
}

// CleanText makes registry- or file-provided text safe to put in a one-line
// message: control characters (including newlines) become spaces, runs of
// spaces collapse, and the result is cut to max bytes (on a rune boundary)
// with "..." appended when cut.
func CleanText(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u2028' || r == '\u2029' || r == utf8.RuneError {
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		if b.Len()+utf8.RuneLen(r) > max {
			return strings.TrimSpace(b.String()) + "..."
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// Tags lists a repository's tags (all pages), cached per Resolver.
func (r *Resolver) Tags(ctx context.Context, repository string) ([]string, error) {
	if r.opts.Offline {
		return nil, &Error{KindOffline, repository, errors.New("offline: cannot list tags")}
	}
	ref, err := ParseReference(repository)
	if err != nil || ref.Tag != "" || ref.Digest != "" {
		return nil, &Error{KindInvalid, repository, fmt.Errorf("not a repository name")}
	}
	repo, err := r.repo(ref)
	if err != nil {
		return nil, &Error{KindInvalid, repository, err}
	}
	tags, err := r.tags.do(ctx, repo.String(), func() ([]string, error) {
		ctx, cancel := context.WithTimeout(ctx, r.opts.Timeout)
		defer cancel()
		if err := r.acquire(ctx); err != nil {
			return nil, err
		}
		defer r.release()
		if r.pullerErr != nil {
			return nil, r.pullerErr
		}
		tags, err := r.puller.List(ctx, repo)
		if err != nil {
			return nil, classify(repository, err)
		}
		return tags, nil
	})
	if err != nil {
		return nil, err
	}
	return append([]string(nil), tags...), nil
}

var (
	reVersion  = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	reDistURL  = regexp.MustCompile(`^https://(?:www|secure)\.php\.net/distributions/php-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.(?:xz|gz|bz2)$`)
	reMirror   = regexp.MustCompile(`^https://secure\.php\.net/get/php-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.(?:xz|gz|bz2)/from/this/mirror$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reMD5      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	phpEnvKeys = []string{"PHP_VERSION", "PHP_URL", "PHP_SHA256", "PHP_MD5"}
)

// PHPFromEnv decides the PHP version from an image config's environment. It
// returns "" unless the environment is the official php image's build
// environment (see the package documentation).
func PHPFromEnv(env []string) (string, []string) {
	vals := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		for _, want := range phpEnvKeys {
			if k == want {
				vals[k] = v // later entries win, as in the container
			}
		}
	}
	ver := vals["PHP_VERSION"]
	if !reVersion.MatchString(ver) {
		return "", nil
	}
	u := vals["PHP_URL"]
	m := reDistURL.FindStringSubmatch(u)
	if m == nil {
		m = reMirror.FindStringSubmatch(u)
	}
	if m == nil || m[1] != ver {
		return "", nil
	}
	var sum string
	switch {
	case reSHA256.MatchString(vals["PHP_SHA256"]):
		sum = "PHP_SHA256"
	case reMD5.MatchString(vals["PHP_MD5"]):
		sum = "PHP_MD5"
	default:
		return "", nil
	}
	return ver, []string{
		"image config sets PHP_VERSION=" + ver,
		"PHP_URL=" + u + " (the php.net release tarball of the same version)",
		sum + " is set: the build environment of the official php image (github.com/docker-library/php), inherited by images built FROM php",
	}
}
