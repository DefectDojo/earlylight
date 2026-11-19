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

// Hostile file content never panics the scan or a plan, a finding the scan
// just reported never plans as already fixed, and a plan only ever edits
// the file the finding names.
func FuzzPins(f *testing.F) {
	for _, s := range []string{"20\n", "FROM node:24.22.0-slim\n", "{\"engines\":{\"node\":\"20.x\"}}", "pycurl==7.48.0\n",
		"ARG B=24.22.0\nFROM debian:12\nENV NODE_VERSION=${B:-24.21.0}\n# nvm install $V\nnvm install $(cat .nvmrc)\n",
		"ARG B=24.22.0\nFROM node:${B} AS a\nARG B\nENV NODE_VERSION=$B\nFROM debian:12\nENV NODE_VERSION=${B:?x}\nRUN nvm install 24$S\n",
		"\ufeff{\"sdk\": {/* \"version\": \"8.0.1\" */ \"version\": \"8.0.415\"}} // \"https://x\"\n",
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
			ch, already, err := pins.Plan(context.Background(), dir, fd.File, fd.Line, fd.Rule, fd.Props)
			if already {
				// The file has not changed since the scan: a finding it
				// just reported is never already fixed.
				t.Fatalf("%s:%d %s %v, just reported, plans as already fixed", fd.File, fd.Line, fd.Rule, fd.Props)
			}
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
