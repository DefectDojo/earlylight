package repocheck

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/refs"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry/registrytest"
)

func TestCheck(t *testing.T) {
	s := registrytest.New(t)
	s.PHPIndex("8.3.35", "8.3-fpm")
	s.PHPIndex("8.3.36", "8.3.36-cli")
	s.EmptyIndex("library/php", "8.3.36-fpm")
	s.PushIndex("library/nginx", "latest", s.Index(registrytest.Spec{OS: "linux", Arch: "amd64", Env: []string{"NGINX_VERSION=1"}}))
	r := registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors(), MinBackoff: time.Millisecond})
	rs := []refs.Ref{
		{File: "a", Image: "php:8.3-fpm"},
		{File: "b", Image: "php:8.3-fpm"},
		{File: "c", Image: "php:8.3.36-cli"},
		{File: "d", Image: "php:8.3.36-fpm"},
		{File: "e", Image: "nginx"},
		{File: "f", Image: "php:0.0.0-missing"},
	}
	results, st := Check(context.Background(), rs, r, 2)
	want := Stats{Refs: 6, Images: 5, Vulnerable: 2, Fixed: 1, NoImages: 1, NoPHP: 1, Unresolved: 1}
	if st != want {
		t.Errorf("stats %+v, want %+v", st, want)
	}
	if !results[0].Finding() || results[4].Finding() || results[5].ErrorKind != "not-found" {
		t.Errorf("results %+v", results)
	}
}

// Review findings 2 and 7: a literal FROM --platform is judged on that
// platform only, and transient failures are marked.
func TestCheckPlatformAndTransient(t *testing.T) {
	s := registrytest.New(t)
	s.PushIndex("library/php", "8.4-fpm", s.Index(
		registrytest.Spec{OS: "linux", Arch: "amd64", Env: registrytest.PHPEnv("8.4.27")},
		registrytest.Spec{OS: "linux", Arch: "arm64", Variant: "v8", Env: registrytest.PHPEnv("8.4.26")},
	))
	r := registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors(), MinBackoff: time.Millisecond, Retries: -1})
	rs := []refs.Ref{
		{File: "a", Image: "php:8.4-fpm", Platform: "linux/amd64"},
		{File: "b", Image: "php:8.4-fpm"},
		{File: "c", Image: "php:8.4-fpm", Platform: "linux/arm64"},
	}
	results, _ := Check(context.Background(), rs, r, 2)
	if v := results[0].Assessment.Verdict; v != registry.Fixed {
		t.Errorf("amd64 only: %s", v)
	}
	if results[1].Assessment.Verdict != registry.Vulnerable || results[2].Assessment.Verdict != registry.Vulnerable {
		t.Errorf("%+v", results)
	}
	if len(results[0].Resolution.Platforms) != 1 {
		t.Errorf("resolution not filtered: %+v", results[0].Resolution)
	}

	s.Fail = func(*http.Request) (int, int) { return http.StatusTooManyRequests, -1 }
	r = registry.NewResolver(registry.Options{Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors(), Retries: -1})
	results, st := Check(context.Background(), []refs.Ref{{File: "a", Image: "php:8.4-fpm"}}, r, 1)
	if !results[0].Transient || results[0].ErrorKind != "rate-limited" || st.Transient != 1 {
		t.Errorf("%+v %+v", results[0], st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if k := ErrorKind(ctx.Err()); k != "timeout" || !registry.Transient(k) {
		t.Errorf("cancelled: %s", k)
	}
}
