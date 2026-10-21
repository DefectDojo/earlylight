package fix

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/refs"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
)

// TestNetworkPlan plans fixes against Docker Hub. Run with
// PHP2SHELL_NETWORK_TESTS=1.
func TestNetworkPlan(t *testing.T) {
	if os.Getenv("PHP2SHELL_NETWORK_TESTS") != "1" {
		t.Skip("set PHP2SHELL_NETWORK_TESTS=1 to run against Docker Hub")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	root := t.TempDir()
	df := "FROM php:8.3.35-fpm AS a\nFROM php:8.3-fpm AS b\nFROM php:8.3.20-fpm-alpine3.20 AS c\nFROM php:8.1.33-cli\n"
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(df), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, _, err := refs.Scan(root, refs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := registry.NewResolver(registry.Options{})
	for _, ref := range rs {
		res, err := r.Resolve(ctx, ref.Image)
		if err != nil {
			t.Logf("%s: %v", ref.Image, err)
			continue
		}
		c, err := Plan(ctx, root, ref, res, r)
		if d, ok := IsDecline(err); ok {
			t.Logf("%s: declined (%s): %s", ref.Image, d.Code, d.Reason)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", ref.Image, err)
			continue
		}
		t.Logf("%s: fix %s:%d %q -> %q\n    %s", ref.Image, c.File, c.Line, c.Old, c.New, c.Reason)
	}
	t.Logf("requests: %+v", r.Stats())
}
