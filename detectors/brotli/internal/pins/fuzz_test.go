package pins_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
)

// fuzzNames are the file names the pin finder reads, one per parser.
var fuzzNames = []string{".nvmrc", ".tool-versions", "mise.toml", "package.json", ".github/workflows/ci.yml", "azure-pipelines.yml",
	".circleci/config.yml", "global.json", "app.csproj", "netlify.toml", "Dockerfile", "template.yaml", "stack.ts", "requirements.txt",
	"poetry.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "Gemfile", "Gemfile.lock", "pom.xml",
	"build.gradle.kts", "gradle.lockfile", "libs.versions.toml", "Cargo.lock", "go.mod", "packages.lock.json", "compose.yaml"}

// Hostile file content never panics the scan or a plan, and a plan only
// ever edits the file the finding names.
func FuzzPins(f *testing.F) {
	for _, s := range []string{"20\n", "FROM node:24.22.0-slim\n", "{\"engines\":{\"node\":\"20.x\"}}", "pycurl==7.48.0\n",
		"jobs:\n  a:\n    strategy:\n      matrix:\n        n: [20]\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.n }}\n"} {
		for i := range fuzzNames {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, content string) {
		dir := t.TempDir()
		name := fuzzNames[int(which)%len(fuzzNames)]
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Skip()
		}
		res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
		if err != nil {
			return
		}
		for _, fd := range res.Findings {
			ch, _, err := pins.Plan(context.Background(), dir, fd.File, fd.Line, fd.Rule, fd.Props)
			if err != nil || ch == nil {
				continue
			}
			if ch.File != name {
				t.Fatalf("a finding in %s planned an edit to %s", name, ch.File)
			}
			for _, e := range ch.Edits {
				if len(e.Old) != 1 || len(e.New) != 1 {
					t.Fatalf("a pin edit changed %d lines into %d", len(e.Old), len(e.New))
				}
			}
		}
	})
}
