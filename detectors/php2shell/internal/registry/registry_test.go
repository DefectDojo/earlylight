package registry_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry/registrytest"
)

func newResolver(s *registrytest.Server) *registry.Resolver {
	return registry.NewResolver(registry.Options{
		Keychain:   authn.NewMultiKeychain(),
		Mirrors:    s.Mirrors(),
		MinBackoff: time.Millisecond,
		MaxBackoff: 5 * time.Millisecond,
		Timeout:    20 * time.Second,
	})
}

func setup(t *testing.T) *registrytest.Server {
	s := registrytest.New(t)
	s.PHPIndex("8.3.35", "8.3.35-fpm", "8.3-fpm")
	s.EmptyIndex("library/php", "8.3.36-fpm")
	// 8.4-fpm while Docker Hub is half way through publishing: amd64 rebuilt,
	// arm64 still on the old release.
	s.PushIndex("library/php", "8.4-fpm", s.Index(
		registrytest.Spec{OS: "linux", Arch: "amd64", Env: registrytest.PHPEnv("8.4.27")},
		registrytest.Spec{OS: "linux", Arch: "arm64", Variant: "v8", Env: registrytest.PHPEnv("8.4.26")},
		registrytest.Spec{OS: registrytest.Attestation},
	))
	s.PHPIndex("8.5.12", "8.5.12-fpm-alpine")
	wpEnv := append(registrytest.PHPEnv("8.3.35"), "WORDPRESS_VERSION=6.8.3", "WORDPRESS_SHA1=abc")
	s.PushIndex("library/wordpress", "latest", s.Index(registrytest.Spec{OS: "linux", Arch: "amd64", Env: wpEnv}))
	s.PushIndex("library/nginx", "latest", s.Index(registrytest.Spec{OS: "linux", Arch: "amd64", Env: []string{"NGINX_VERSION=1.29.2", "PATH=/usr/bin"}}))
	s.Push("acme/single", "1", s.Image(registrytest.Spec{OS: "linux", Arch: "amd64", Env: registrytest.PHPEnv("8.2.30")}))
	s.Requests()
	return s
}

func TestResolve(t *testing.T) {
	s := setup(t)
	r := newResolver(s)
	ctx := context.Background()
	tests := []struct {
		ref       string
		verdict   registry.Verdict
		platforms []string // "platform=version"
		empty     bool
	}{
		{"php:8.3.35-fpm", registry.Vulnerable, []string{"linux/amd64=8.3.35", "linux/arm64/v8=8.3.35"}, false},
		{"docker.io/library/php:8.3-fpm", registry.Vulnerable, []string{"linux/amd64=8.3.35", "linux/arm64/v8=8.3.35"}, false},
		{"php:8.3.36-fpm", registry.NoImages, nil, true},
		{"php:8.4-fpm", registry.Vulnerable, []string{"linux/amd64=8.4.27", "linux/arm64/v8=8.4.26"}, false},
		{"php:8.5.12-fpm-alpine", registry.Fixed, []string{"linux/amd64=8.5.12", "linux/arm64/v8=8.5.12"}, false},
		{"wordpress", registry.Vulnerable, []string{"linux/amd64=8.3.35"}, false},
		{"nginx:latest", registry.NoPHP, []string{"linux/amd64="}, false},
		{"acme/single:1", registry.Vulnerable, []string{"linux/amd64=8.2.30"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			res, err := r.Resolve(ctx, tc.ref)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, p := range res.Platforms {
				got = append(got, p.Platform+"="+p.PHPVersion)
				if p.PHPVersion != "" && len(p.Evidence) != 3 {
					t.Errorf("evidence %v", p.Evidence)
				}
			}
			if !slices.Equal(got, tc.platforms) || res.Empty != tc.empty {
				t.Errorf("platforms %v empty %v, want %v %v", got, res.Empty, tc.platforms, tc.empty)
			}
			a := registry.Assess(res)
			if a.Verdict != tc.verdict {
				t.Errorf("verdict %s (%s), want %s", a.Verdict, a.Reason, tc.verdict)
			}
			if res.Ref != tc.ref {
				t.Errorf("Ref %q", res.Ref)
			}
		})
	}
	a := registry.Assess(mustResolve(t, r, "php:8.4-fpm"))
	if len(a.VulnerablePlatforms) != 1 || a.VulnerablePlatforms[0] != "linux/arm64/v8 (PHP 8.4.26)" {
		t.Errorf("vulnerable platforms %v", a.VulnerablePlatforms)
	}
	if s.LayerFetched(s.Requests()) {
		t.Error("a layer was downloaded")
	}
}

func mustResolve(t *testing.T, r *registry.Resolver, ref string) *registry.Resolution {
	t.Helper()
	res, err := r.Resolve(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCaching(t *testing.T) {
	s := setup(t)
	r := newResolver(s)
	mustResolve(t, r, "php:8.3.35-fpm")
	st := r.Stats()
	// One index and two image manifests; the attestation is never fetched.
	if st.ManifestGets != 3 || st.BlobGets != 2 {
		t.Errorf("first resolve: %+v", st)
	}
	// Same reference again: nothing. Another tag of the same index: one HEAD.
	mustResolve(t, r, "php:8.3.35-fpm")
	mustResolve(t, r, "php:8.3-fpm")
	st2 := r.Stats()
	if st2.ManifestGets != 3 || st2.BlobGets != 2 || st2.ManifestHeads != st.ManifestHeads+1 {
		t.Errorf("cached resolves: %+v then %+v", st, st2)
	}
}

func TestDigestWinsOverTag(t *testing.T) {
	s := setup(t)
	d := s.PHPIndex("8.2.20", "8.2.20-cli")
	r := newResolver(s)
	res := mustResolve(t, r, "php:8.3-fpm@"+d.String())
	if res.Digest != d.String() || res.Platforms[0].PHPVersion != "8.2.20" || res.Reference.Tag != "8.3-fpm" {
		t.Errorf("resolved %+v", res)
	}
}

func TestErrors(t *testing.T) {
	s := setup(t)
	r := newResolver(s)
	ctx := context.Background()
	_, err := r.Resolve(ctx, "php:9.9-nope")
	var e *registry.Error
	if !errors.As(err, &e) || e.Kind != registry.KindNotFound {
		t.Errorf("missing tag: %v", err)
	}
	_, err = r.Resolve(ctx, "Not A Ref")
	if !errors.As(err, &e) || e.Kind != registry.KindInvalid {
		t.Errorf("invalid: %v", err)
	}
}

func TestRetries(t *testing.T) {
	s := setup(t)
	var nm, nb atomic.Int32
	s.Fail = func(req *http.Request) (int, int) {
		if strings.Contains(req.URL.Path, "/manifests/") && nm.Add(1) <= 2 {
			return http.StatusTooManyRequests, 0
		}
		if strings.Contains(req.URL.Path, "/blobs/") && nb.Add(1) <= 2 {
			return http.StatusServiceUnavailable, -1
		}
		return 0, 0
	}
	r := newResolver(s)
	res := mustResolve(t, r, "php:8.3.35-fpm")
	if res.Platforms[0].PHPVersion != "8.3.35" {
		t.Fatal(res)
	}
	if st := r.Stats(); st.Retries < 3 {
		t.Errorf("stats %+v", st)
	}

	// Persistent rate limiting: the error says so and is not cached.
	s.Fail = func(req *http.Request) (int, int) {
		if strings.Contains(req.URL.Path, "/manifests/") {
			return http.StatusTooManyRequests, 0
		}
		return 0, 0
	}
	r = newResolver(s)
	_, err := r.Resolve(context.Background(), "php:8.4-fpm")
	var e *registry.Error
	if !errors.As(err, &e) || e.Kind != registry.KindRateLimited {
		t.Fatalf("got %v", err)
	}
	s.Fail = nil
	if _, err := r.Resolve(context.Background(), "php:8.4-fpm"); err != nil {
		t.Errorf("after the limit lifted: %v", err)
	}

	// A Retry-After beyond the limit is not waited for.
	s.Fail = func(req *http.Request) (int, int) { return http.StatusTooManyRequests, 3600 }
	r = newResolver(s)
	start := time.Now()
	_, err = r.Resolve(context.Background(), "php:8.5.12-fpm-alpine")
	if !errors.As(err, &e) || e.Kind != registry.KindRateLimited || time.Since(start) > 5*time.Second {
		t.Errorf("got %v after %v", err, time.Since(start))
	}
}

func TestTags(t *testing.T) {
	s := setup(t)
	r := newResolver(s)
	tags, err := r.Tags(context.Background(), "php")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"8.3.35-fpm", "8.3-fpm", "8.3.36-fpm", "8.4-fpm", "8.5.12-fpm-alpine"} {
		if !slices.Contains(tags, want) {
			t.Errorf("tags %v lack %s", tags, want)
		}
	}
	for _, tg := range tags {
		if strings.HasPrefix(tg, "sha256:") {
			t.Errorf("digest in tag list: %s", tg)
		}
	}
}

func TestOffline(t *testing.T) {
	r := registry.NewResolver(registry.Options{Offline: true})
	ctx := context.Background()
	res, err := r.Resolve(ctx, "php:8.3.20-fpm-alpine3.21")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || len(res.Platforms) != 1 || res.Platforms[0].PHPVersion != "8.3.20" || !strings.Contains(res.Platforms[0].Evidence[0], "from the tag") {
		t.Errorf("%+v", res)
	}
	if a := registry.Assess(res); a.Verdict != registry.Vulnerable {
		t.Errorf("verdict %s", a.Verdict)
	}
	for _, ref := range []string{
		"php:8.3-fpm", "php", "php:8.3.20@sha256:" + strings.Repeat("a", 64), "ghcr.io/acme/php:8.3.20",
		"wordpress:6.8.3-php8.3", "php:8.5.0RC1-cli",
	} {
		_, err := r.Resolve(ctx, ref)
		var e *registry.Error
		if !errors.As(err, &e) || e.Kind != registry.KindOffline {
			t.Errorf("%s: %v", ref, err)
		}
	}
	if _, err := r.Tags(ctx, "php"); err == nil {
		t.Error("tags offline")
	}
}

func TestPHPFromEnv(t *testing.T) {
	sha := "PHP_SHA256=" + strings.Repeat("0", 64)
	tests := []struct {
		env  []string
		want string
	}{
		{registrytest.PHPEnv("8.3.35"), "8.3.35"},
		{[]string{"PHP_VERSION=7.2.0", "PHP_URL=https://secure.php.net/get/php-7.2.0.tar.xz/from/this/mirror", sha}, "7.2.0"},
		{[]string{"PHP_VERSION=5.6.40", "PHP_URL=https://secure.php.net/get/php-5.6.40.tar.gz/from/this/mirror", "PHP_MD5=" + strings.Repeat("f", 32)}, "5.6.40"},
		{[]string{"PHP_VERSION=8.3.35", "PHP_URL=https://www.php.net/distributions/php-8.3.36.tar.xz", sha}, ""},
		{[]string{"PHP_VERSION=8.3.35", "PHP_URL=https://www.php.net/distributions/php-8.3.35.tar.xz"}, ""},
		{[]string{"PHP_VERSION=8.3.35", sha}, ""},
		{[]string{"PHP_VERSION=8.3", "PHP_URL=https://www.php.net/distributions/php-8.3.tar.xz", sha}, ""},
		{[]string{"PHP_VERSION=8.5.0RC1", "PHP_URL=https://downloads.php.net/~daniels/php-8.5.0RC1.tar.xz", sha}, ""},
		{[]string{"PHP_VERSION=8.3.35", "PHP_URL=http://www.php.net/distributions/php-8.3.35.tar.xz", sha}, ""},
		{[]string{"PHP_VERSION=8.3.35", "PHP_URL=https://evil.example/www.php.net/distributions/php-8.3.35.tar.xz", sha}, ""},
		{append(registrytest.PHPEnv("8.3.35"), "PHP_VERSION=8.4.1"), ""}, // later entries win
		{[]string{"NGINX_VERSION=1.0"}, ""},
	}
	for i, tc := range tests {
		if got, _ := registry.PHPFromEnv(tc.env); got != tc.want {
			t.Errorf("%d: %q, want %q", i, got, tc.want)
		}
	}
}

func TestParseReference(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	tests := []struct{ in, repo, tag, dig string }{
		{"php", "docker.io/library/php", "", ""},
		{"php:8.3-fpm", "docker.io/library/php", "8.3-fpm", ""},
		{"docker.io/php:8.3@" + d, "docker.io/library/php", "8.3", d},
		{"php@" + d, "docker.io/library/php", "", d},
		{"localhost:5000/a/b:1", "localhost:5000/a/b", "1", ""},
		{"ghcr.io/o/p", "ghcr.io/o/p", "", ""},
	}
	for _, tc := range tests {
		r, err := registry.ParseReference(tc.in)
		if err != nil || r.Repository() != tc.repo || r.Tag != tc.tag || r.Digest != tc.dig {
			t.Errorf("%s: %+v %v", tc.in, r, err)
		}
	}
	if r, _ := registry.ParseReference("index.docker.io/library/php:8"); !r.IsOfficialPHP() {
		t.Error("official")
	}
	if r, _ := registry.ParseReference("ghcr.io/library/php:8"); r.IsOfficialPHP() {
		t.Error("not official")
	}
}
