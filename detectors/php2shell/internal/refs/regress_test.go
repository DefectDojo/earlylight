package refs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review finding 1: a FROM names a stage only when an EARLIER FROM declared
// it.
func TestStageNamesOnlyEarlier(t *testing.T) {
	tests := []struct {
		in   string
		want []string // image@line
	}{
		{"FROM wordpress AS wordpress\nRUN true\n", []string{"wordpress@1"}},
		{"FROM php AS first\nRUN php -v\nFROM alpine:3.20 AS php\n", []string{"php@1", "alpine:3.20@3"}},
		{"FROM php:8.2.20-cli AS tools\nFROM tools AS php\nFROM php AS final\n", []string{"php:8.2.20-cli@1"}},
		{"FROM php:8.3 AS Base\nFROM BASE\n", []string{"php:8.3@1"}},
	}
	for _, tc := range tests {
		rs, skips := scanContent(t, "Dockerfile", tc.in)
		var got []string
		for _, r := range rs {
			got = append(got, r.Image+"@"+itoa(r.Line))
		}
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("%q: got %v (skips %+v), want %v", tc.in, got, skips, tc.want)
		}
	}
}

// Review finding 5: names and formats that were silently missed.
func TestMoreFileKinds(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"b/Dockerfile-prod":   "FROM php:8.2.35-fpm\n",
		"b/Dockerfile_dev":    "FROM php:8.2.36-fpm\n",
		"b/DOCKERFILE.Worker": "FROM php:8.2.37-fpm\n",
		"b/app.dockerfile":    "FROM php:8.2.38-fpm\n",
		"b/Dockerfile-gen.py": "from x import y\n",
		"c/docker-stack.yml":  "services:\n  web:\n    image: php:8.2.20-fpm\n",
		"c/prod-stack.yaml":   "services:\n  web:\n    image: php:8.2.21-fpm\n",
		"d/deploy.yml":        "version: '3'\nservices:\n  web:\n    image: php:8.2.22-fpm\n",
		"r4/pod.json":         `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"a","image":"php:8.2.23-cli"}]}}`,
		"r4/package.json":     `{"name":"x","image":"php:1"}`,
		"r4/wf.yaml":          "apiVersion: argoproj.io/v1alpha1\nkind: Workflow\nspec:\n  templates:\n  - name: a\n    container:\n      image: php:8.2.24-cli\n  - name: b\n    script:\n      image: php:8.2.25-cli\n      source: echo\n  - name: c\n    containerSet:\n      containers:\n      - image: php:8.2.26-cli\n    sidecars:\n    - image: php:8.2.27-cli\n    initContainers:\n    - image: php:8.2.28-cli\n",
		"r4/task.yaml":        "apiVersion: tekton.dev/v1\nkind: Task\nspec:\n  stepTemplate:\n    image: php:8.2.29-cli\n  steps:\n  - name: s\n    image: php:8.2.30-cli\n  sidecars:\n  - image: php:8.2.31-cli\n",
		"r4/rollout.yaml":     "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nspec:\n  template:\n    spec:\n      containers:\n      - image: php:8.2.32-cli\n",
		"r4/cron.yaml":        "apiVersion: batch/v1\nkind: CronJob\nspec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          containers:\n          - image: php:8.2.33-cli\n",
	}
	for n, b := range files {
		p := filepath.Join(root, filepath.FromSlash(n))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, skips, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rs {
		got[r.Image] = true
	}
	for i := 20; i <= 38; i++ {
		var img string
		switch {
		case i <= 22:
			img = "php:8.2." + itoa(i) + "-fpm"
		case i <= 33:
			img = "php:8.2." + itoa(i) + "-cli"
		case i <= 34:
			continue
		default:
			img = "php:8.2." + itoa(i) + "-fpm"
		}
		if !got[img] {
			t.Errorf("missing %s", img)
		}
	}
	if got["php:1"] || len(rs) != 18 {
		t.Errorf("refs %d: %+v", len(rs), rs)
	}
	for _, s := range skips {
		if strings.Contains(s.File, "Dockerfile-gen.py") || strings.Contains(s.File, "package.json") {
			t.Errorf("skip %+v", s)
		}
	}
}

// Review finding 5: ScanFiles applies Scan's directory rules, and a changed
// .env brings in the Compose files beside it.
func TestScanFilesRules(t *testing.T) {
	root := t.TempDir()
	w := func(n, b string) {
		p := filepath.Join(root, filepath.FromSlash(n))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(b), 0o644)
	}
	w("vendor/autoload.php", "<?php\n")
	w("vendor/x/Dockerfile", "FROM php:7.3\n")
	w("node_modules/y/Dockerfile", "FROM php:7.2\n")
	w(".git/Dockerfile", "FROM php:7.1\n")
	w("e/compose.yaml", "services:\n  web:\n    image: php:${PHP_TAG}\n")
	w("e/docker-compose.override.yml", "services:\n  web:\n    image: php:${PHP_TAG}-x\n")
	w("e/.env", "PHP_TAG=8.3.35-fpm\n")
	rs, skips, err := ScanFiles(root, []string{"vendor/x/Dockerfile", "node_modules/y/Dockerfile", ".git/Dockerfile", "e/.env"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rs {
		got = append(got, r.File+"="+r.Image)
	}
	if strings.Join(got, " ") != "e/compose.yaml=php:8.3.35-fpm e/docker-compose.override.yml=php:8.3.35-fpm-x" {
		t.Errorf("refs %v", got)
	}
	if len(skips) != 2 || !strings.Contains(skips[0].Reason, "node_modules") || !strings.Contains(skips[1].Reason, "Composer") {
		t.Errorf("skips %+v", skips)
	}
	rs, _, _ = ScanFiles(root, []string{"vendor/x/Dockerfile"}, Options{IncludeDependencyDirs: true})
	if len(rs) != 1 {
		t.Errorf("IncludeDependencyDirs: %+v", rs)
	}
}

// Review finding 9: reasons are single-line and bounded.
func TestSkipReasonsSingleLine(t *testing.T) {
	_, skips := scanContent(t, "docker-compose.yml", "services:\n  a:\n    image: \"php:${X:?line1\\nline2 "+strings.Repeat("x", 2000)+"}\"\n")
	if len(skips) != 1 {
		t.Fatalf("%+v", skips)
	}
	r := skips[0].Reason + skips[0].Text
	if strings.ContainsAny(r, "\n\r") || len(skips[0].Reason) > 510 || len(skips[0].Text) > 310 {
		t.Errorf("reason %q", skips[0].Reason)
	}
}
