package reposcan

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry/registrytest"
)

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRunReportsAndPlans(t *testing.T) {
	srv := registrytest.New(t)
	srv.PHPIndexOn("8.3.35", "debian:trixie-slim", nil, "8.3.35-fpm")
	srv.PHPIndexOn("8.3.36", "debian:trixie-slim", nil, "8.3.36-fpm")
	srv.PHPIndexOn("8.4.27", "debian:trixie-slim", nil, "8.4.27-cli")
	dir := writeRepo(t, map[string]string{
		"Dockerfile":         "FROM php:8.3.35-fpm\n",
		"tools/Dockerfile":   "FROM php:8.4.27-cli\n",
		"deploy/compose.yml": "services:\n  web:\n    image: php:8.3.35-fpm\n",
	})
	tg, items, err := Run(context.Background(), dir, Options{Registry: registry.Options{Mirrors: srv.Mirrors(), Transport: http.DefaultTransport}})
	if err != nil {
		t.Fatal(err)
	}
	if tg.Count(assess.Vulnerable) != 2 || tg.Count(assess.Fixed) != 1 || tg.RefsChecked != 3 {
		t.Fatalf("vulnerable %d fixed %d checked %d", tg.Count(assess.Vulnerable), tg.Count(assess.Fixed), tg.RefsChecked)
	}
	planned := 0
	for _, it := range items {
		if it.Change != nil {
			planned++
			if it.Change.After != "php:8.3.36-fpm" {
				t.Errorf("planned %s", it.Change.After)
			}
		}
	}
	if planned != 2 {
		t.Errorf("%d changes planned, want 2", planned)
	}
}

// A registry that fails (rate limit) must not produce a short findings list that
// looks complete: Run says which references were not checked.
func TestRunTransientFailureIsAnError(t *testing.T) {
	srv := registrytest.New(t)
	srv.PHPIndexOn("8.3.35", "debian:trixie-slim", nil, "8.3.35-fpm")
	srv.Fail = func(r *http.Request) (int, int) { return http.StatusTooManyRequests, 3600 }
	dir := writeRepo(t, map[string]string{"Dockerfile": "FROM php:8.3.35-fpm\n"})
	tg, _, err := Run(context.Background(), dir, Options{Registry: registry.Options{Mirrors: srv.Mirrors(), Transport: http.DefaultTransport, Retries: -1}})
	var te *TransientError
	if !errors.As(err, &te) || len(te.Refs) != 1 || tg == nil || tg.Gaps() == 0 {
		t.Fatalf("err=%v target=%+v", err, tg)
	}
}

func TestRunCapsDistinctImages(t *testing.T) {
	srv := registrytest.New(t)
	var df strings.Builder
	for i := 0; i < 5; i++ {
		df.WriteString("FROM example.com/img" + string(rune('a'+i)) + ":1\n")
	}
	dir := writeRepo(t, map[string]string{"Dockerfile": df.String()})
	tg, _, _ := Run(context.Background(), dir, Options{MaxImages: 2, Registry: registry.Options{Mirrors: srv.Mirrors(), Transport: http.DefaultTransport, Offline: true}})
	capped := 0
	for _, s := range tg.Skipped {
		if strings.Contains(s.Reason, "more than 2 distinct images") {
			capped++
		}
	}
	if capped != 3 {
		t.Fatalf("%d references capped, want 3: %+v", capped, tg.Skipped)
	}
}
