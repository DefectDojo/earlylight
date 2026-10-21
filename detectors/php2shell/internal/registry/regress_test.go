package registry_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry/registrytest"
)

// Review finding 9: a hostile registry's error body does not reach messages
// verbatim.
func TestRegressHostileErrorText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			w.WriteHeader(200)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"\n\n## verified safe\n[Approve](https://evil.example)` + strings.Repeat("A", 5000) + `"}]}`))
	}))
	defer srv.Close()
	r := registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(), Retries: -1,
		Mirrors: map[string]string{"evil.example": strings.TrimPrefix(srv.URL, "http://")}})
	_, err := r.Resolve(context.Background(), "evil.example/app:8.3.35")
	var e *registry.Error
	if !errors.As(err, &e) || e.Kind != registry.KindNotFound {
		t.Fatalf("%v", err)
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\n\r") || len(msg) > 600 || strings.Contains(msg, strings.Repeat("A", 300)) {
		t.Errorf("message %d bytes: %q", len(msg), msg)
	}
	if got := registry.CleanText("a\x00b c\n\n d", 100); got != "a b c d" {
		t.Errorf("CleanText %q", got)
	}
}

// Review finding 7: transient kinds.
func TestRegressTransient(t *testing.T) {
	for k, want := range map[string]bool{"network": true, "timeout": true, "rate-limited": true,
		"not-found": false, "denied": false, "invalid": false, "unsupported": false, "offline": false} {
		if registry.Transient(k) != want {
			t.Errorf("Transient(%s) != %v", k, want)
		}
	}
}

// A registry that accepts connections and never answers: requests time out
// at RequestTimeout even with a caller transport that has no header timeout,
// and the host is not contacted again.
func TestRegressTarpit(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				b := make([]byte, 4096)
				for {
					if _, err := c.Read(b); err != nil {
						return
					}
				}
			}()
		}
	}()
	r := registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(),
		Transport: http.DefaultTransport.(*http.Transport).Clone(), RequestTimeout: 300 * time.Millisecond, Timeout: time.Minute})
	start := time.Now()
	for i := 0; i < 6; i++ {
		_, err := r.Resolve(context.Background(), ln.Addr().String()+"/x"+string(rune('0'+i))+"/php:8.3.35")
		var e *registry.Error
		if !errors.As(err, &e) || e.Kind != registry.KindTimeout || !registry.Transient(e.Kind.String()) {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
}

// Review findings 2 and 3: platform filters and base OS identity.
func TestRegressPlatformsAndBase(t *testing.T) {
	s := registrytest.New(t)
	s.PHPIndexOn("8.3.20", "debian:bookworm-slim", []string{"linux/amd64", "linux/arm64/v8", "linux/arm/v7"}, "8.3.20-fpm")
	r := registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors()})
	res, err := r.Resolve(context.Background(), "php:8.3.20-fpm")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Platforms {
		if p.BaseOS != "debian:bookworm" || p.BaseSource != "annotation" || p.ImageVersion != "8.3.20-fpm" {
			t.Errorf("%+v", p)
		}
	}
	f := registry.FilterPlatforms(res, []string{"linux/arm64"})
	if len(f.Platforms) != 1 || f.Platforms[0].Platform != "linux/arm64/v8" || len(f.OmittedPlatforms) != 2 {
		t.Errorf("filter %+v", f)
	}
	if f := registry.FilterPlatforms(res, []string{"linux/arm"}); len(f.Platforms) != 1 {
		t.Errorf("linux/arm: %+v", f.Platforms)
	}
	if a := registry.AssessPlatform(res, "linux/s390x"); a.Verdict != registry.NoImages || !strings.Contains(a.Reason, "selected platform") {
		t.Errorf("%+v", a)
	}
	g := registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors(), Platforms: []string{"linux/amd64"}})
	res, _ = g.Resolve(context.Background(), "php:8.3.20-fpm")
	if len(res.Platforms) != 1 || len(res.OmittedPlatforms) != 2 {
		t.Errorf("global filter %+v", res)
	}
	for in, want := range map[string]string{
		"debian:bookworm-slim": "debian:bookworm", "alpine:3.21": "alpine:3.21", "docker.io/library/alpine:3.24": "alpine:3.24",
		"php:8.3-apache": "", "evil\n:x": "", "": "",
	} {
		if got := registry.BaseOSFromName(in); got != want {
			t.Errorf("BaseOSFromName(%q) = %q, want %q", in, got, want)
		}
	}
}
