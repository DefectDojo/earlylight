package registry_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
)

// TestNetwork resolves real Docker Hub references. Run with
// PHP2SHELL_NETWORK_TESTS=1; it makes about 30 manifest requests.
func TestNetwork(t *testing.T) {
	if os.Getenv("PHP2SHELL_NETWORK_TESTS") != "1" {
		t.Skip("set PHP2SHELL_NETWORK_TESTS=1 to run against Docker Hub")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r := registry.NewResolver(registry.Options{})
	check := func(ref string, ok func(*registry.Resolution, registry.Assessment) bool) {
		res, err := r.Resolve(ctx, ref)
		if err != nil {
			t.Errorf("%s: %v", ref, err)
			return
		}
		a := registry.Assess(res)
		var ps []string
		for _, p := range res.Platforms {
			ps = append(ps, p.Platform+"="+p.PHPVersion)
		}
		t.Logf("%s -> %s index=%v empty=%v verdict=%s platforms=[%s]\n    %s", ref, res.Digest, res.Index, res.Empty, a.Verdict, strings.Join(ps, " "), a.Reason)
		if !ok(res, a) {
			t.Errorf("%s: unexpected verdict %s", ref, a.Verdict)
		}
	}
	check("php:8.3.35-fpm", func(res *registry.Resolution, a registry.Assessment) bool {
		for _, p := range res.Platforms {
			if p.PHPVersion != "8.3.35" {
				return false
			}
		}
		return a.Verdict == registry.Vulnerable && len(res.Platforms) > 1
	})
	check("php:8.3-fpm", func(res *registry.Resolution, a registry.Assessment) bool {
		return a.Verdict == registry.Vulnerable || a.Verdict == registry.Fixed
	})
	check("php:8.3.36-fpm", func(res *registry.Resolution, a registry.Assessment) bool {
		return a.Verdict == registry.NoImages || a.Verdict == registry.Fixed
	})
	check("wordpress:latest", func(res *registry.Resolution, a registry.Assessment) bool {
		return a.Verdict == registry.Vulnerable || a.Verdict == registry.Fixed
	})
	check("nginx:latest", func(res *registry.Resolution, a registry.Assessment) bool {
		return a.Verdict == registry.NoPHP
	})
	st := r.Stats()
	t.Logf("requests: %+v", st)
	if st.BlobGets > st.ManifestGets {
		t.Errorf("more blob fetches (%d) than manifests (%d): layers fetched?", st.BlobGets, st.ManifestGets)
	}
}
