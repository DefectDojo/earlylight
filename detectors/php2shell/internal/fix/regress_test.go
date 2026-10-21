package fix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry/registrytest"
)

func regressFixture(t *testing.T, platforms []string) *fixture {
	s := registrytest.New(t)
	// Implicit OS suffixes that moved: alpine 3.21 -> 3.24, bookworm -> trixie.
	pushPHP(s, "8.3.20", a321, both, "8.3.20-fpm-alpine")
	pushPHP(s, "8.3.36", a324, both, "8.3.36-fpm-alpine", "8.3.36-fpm-alpine3.24")
	pushPHP(s, "8.3.36", a321, both, "8.3.36-fpm-alpine3.21")
	pushPHP(s, "8.3.20", bookworm, both, "8.3.20-fpm")
	pushPHP(s, "8.3.36", trixie, both, "8.3.36-fpm", "8.3.36-fpm-trixie")
	pushPHP(s, "8.3.36", bookworm, both, "8.3.36-fpm-bookworm")
	// No base annotations at all.
	s.PHPIndex("8.3.20", "8.3.20-zts", "8.3.20-zts-bookworm")
	s.PHPIndex("8.3.36", "8.3.36-zts", "8.3.36-zts-bookworm")
	// Base only in the config history.
	hist := func(v, rel string) {
		var specs []registrytest.Spec
		for _, a := range []string{"amd64", "arm64"} {
			specs = append(specs, registrytest.Spec{OS: "linux", Arch: a, Env: registrytest.PHPEnv(v),
				History: "ADD alpine-minirootfs-" + rel + ".1-x86_64.tar.gz / # buildkit"})
		}
		s.PushIndex("library/php", v+"-cli-alpine", s.Index(specs...))
	}
	hist("8.3.20", "3.21")
	hist("8.3.36", "3.24")
	// Retired: mips64le was built for 8.3.20, dropped by 8.3.35.
	pushPHP(s, "8.3.20", trixie, []string{"linux/amd64", "linux/mips64le"}, "8.3.20-apache")
	pushPHP(s, "8.3.35", trixie, []string{"linux/amd64"}, "8.3.35-apache")
	pushPHP(s, "8.3.36", trixie, []string{"linux/amd64"}, "8.3.36-apache")
	// Pending: arm64 still built for 8.3.35, not yet for 8.3.36.
	pushPHP(s, "8.3.20", trixie, both, "8.3.20-cli-trixie")
	pushPHP(s, "8.3.35", trixie, both, "8.3.35-cli-trixie")
	pushPHP(s, "8.3.36", trixie, []string{"linux/amd64"}, "8.3.36-cli-trixie")
	return &fixture{s: s, r: registry.NewResolver(registry.Options{
		Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors(), Platforms: platforms,
		MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	})}
}

// Review findings 2, 3 and 4.
func TestRegressBaseOSAndPlatforms(t *testing.T) {
	f := regressFixture(t, nil)
	tests := []struct {
		name, df string
		code     DeclineCode // "" for a change
		says     string
	}{
		{"implicit alpine release", "FROM php:8.3.20-fpm-alpine\n", DeclineBaseOSChanged, "alpine:3.21 -> alpine:3.24"},
		{"implicit alpine release hint", "FROM php:8.3.20-fpm-alpine\n", DeclineBaseOSChanged, "use docker.io/library/php:8.3.36-fpm-alpine3.21 (published)"},
		{"implicit debian release", "FROM php:8.3.20-fpm\n", DeclineBaseOSChanged, "use docker.io/library/php:8.3.36-fpm-bookworm (published)"},
		{"unknown base, implicit tag", "FROM php:8.3.20-zts\n", DeclineBaseOSUnknown, "does not name one"},
		{"unknown base, tag names the release", "FROM php:8.3.20-zts-bookworm\n", "", "8.3.36-zts-bookworm"},
		{"base from history", "FROM php:8.3.20-cli-alpine\n", DeclineBaseOSChanged, "alpine:3.21 -> alpine:3.24"},
		{"retired platform", "FROM php:8.3.20-apache\n", "", "linux/mips64le: retired by Docker Hub before 8.3.36"},
		{"pending platform", "FROM php:8.3.20-cli-trixie\n", DeclinePlatformsMissing, "not yet published for linux/arm64/v8"},
		{"literal FROM --platform", "FROM --platform=linux/amd64 php:8.3.20-cli-trixie\n", "", "8.3.36-cli-trixie"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, c, err := f.plan(t, map[string]string{"Dockerfile": tc.df}, "Dockerfile", 1)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("plan: %v", err)
				}
				all := c.After + " " + strings.Join(c.Verified, "; ") + " " + c.Reason
				t.Logf("change: %s -> %s; %s", c.Before, c.After, c.Reason)
				if !strings.Contains(all, tc.says) {
					t.Errorf("change %+v lacks %q", c, tc.says)
				}
				return
			}
			d, ok := IsDecline(err)
			if !ok {
				t.Fatalf("got %+v, %v; want %s", c, err, tc.code)
			}
			t.Logf("decline %s: %s", d.Code, d.Reason)
			if d.Code != tc.code || !strings.Contains(d.Reason, tc.says) {
				t.Errorf("decline %s %q, want %s with %q", d.Code, d.Reason, tc.code, tc.says)
			}
		})
	}
}

// Review finding 2: a global platform restriction.
func TestRegressGlobalPlatforms(t *testing.T) {
	f := regressFixture(t, []string{"linux/amd64"})
	_, c, err := f.plan(t, map[string]string{"Dockerfile": "FROM php:8.3.20-cli-trixie\n"}, "Dockerfile", 1)
	if err != nil {
		t.Fatal(err)
	}
	if c.After != "php:8.3.36-cli-trixie" || len(c.Verified) != 1 {
		t.Errorf("%+v", c)
	}
}

// Review finding 6: concurrent Apply calls on one file keep both edits.
func TestRegressApplyConcurrent(t *testing.T) {
	for i := 0; i < 200; i++ {
		dir := t.TempDir()
		p := filepath.Join(dir, ".env")
		if err := os.WriteFile(p, []byte("A=8.3.35-fpm\nB=8.3.35-cli\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for k, c := range []Change{
			{File: ".env", Line: 1, Old: "A=8.3.35-fpm", New: "A=8.3.36-fpm"},
			{File: ".env", Line: 2, Old: "B=8.3.35-cli", New: "B=8.3.36-cli"},
		} {
			wg.Add(1)
			go func() { defer wg.Done(); errs[k] = Apply(dir, []Change{c}) }()
		}
		wg.Wait()
		b, _ := os.ReadFile(p)
		if errs[0] != nil || errs[1] != nil || string(b) != "A=8.3.36-fpm\nB=8.3.36-cli\n" {
			t.Fatalf("run %d: %v %v %q", i, errs[0], errs[1], b)
		}
	}
}

// Review finding 9: reasons are single-line.
func TestRegressReasonsSingleLine(t *testing.T) {
	d := decline(DeclineUnresolved, "a\nb\r\x1b[31mc %s", strings.Repeat("x", 5000))
	if strings.ContainsAny(d.Reason, "\n\r\x1b") || len(d.Reason) > 2010 {
		t.Errorf("%q", d.Reason[:80])
	}
	_ = context.Background
}
