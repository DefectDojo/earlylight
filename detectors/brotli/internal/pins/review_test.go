package pins_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
)

// A file with mixed line endings changes only on the edited line.
func TestApplyMixedEndings(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"Dockerfile": "ARG NODE_VERSION=22.23.1\r\nRUN a\nRUN b\r\n"})
	ch, _, err := pins.Plan(context.Background(), dir, "Dockerfile", 1, pins.RuleNode, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pins.Apply(dir, ch); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if string(b) != "ARG NODE_VERSION=22.23.4\r\nRUN a\nRUN b\r\n" {
		t.Fatalf("got %q", b)
	}
}

// Values the one-place edit cannot change correctly stay manual.
func TestManualWhenWrittenTwiceOrHashed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"Dockerfile":       "RUN curl -fsSLO https://nodejs.org/dist/v22.23.1/node-v22.23.1-linux-x64.tar.xz && tar -xJf node-v22.23.1-linux-x64.tar.xz\nRUN nvm install 20 && nvm use 20\n",
		"requirements.txt": "pycurl==7.45.3 \\\n    --hash=sha256:abc\n",
	})
	res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("got %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.Fixable {
			t.Errorf("%s:%d fixable: %s", f.File, f.Line, f.Fix)
		}
	}
}

// matrix.include values are judged, and an unresolved reference is not checked, not clean.
func TestMatrixIncludeAndUnresolved(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{".github/workflows/ci.yml": "jobs:\n  a:\n    strategy:\n      matrix:\n        include:\n          - node: 20\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.node }}\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.other }}\n"})
	res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Line != 6 {
		t.Fatalf("findings %+v", res.Findings)
	}
	if len(res.Skips) != 1 || !strings.Contains(res.Skips[0].Reason, "matrix.other") {
		t.Fatalf("skips %+v", res.Skips)
	}
}

// An old-style engines array leaves the rest of package.json readable.
func TestPackageJSONOddShapes(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"package.json": `{"engines": ["node >= 0.8"], "volta": {"node": "22.23.1"}}`})
	res, _ := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if len(res.Findings) != 1 || len(res.Skips) != 0 {
		t.Fatalf("findings %+v skips %+v", res.Findings, res.Skips)
	}
}

// A pre-release of the fixed release is not the fixed release.
func TestPreReleaseIsNotFixed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"requirements.txt": "pycurl==7.49.0rc1\nPyMuPDF==1.28.0\n", "go.mod": "module x\n\nrequire github.com/andybalholm/brotli v1.2.7-0.20261022010101-abcdefabcdef\n"})
	res, _ := pins.Scan(context.Background(), dir, nil, pins.Options{})
	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.File+":"+f.Props["current"]] = true
	}
	if !got["requirements.txt:7.49.0rc1"] || got["requirements.txt:1.28.0"] || !got["go.mod:1.2.7-0.20261022010101-abcdefabcdef"] {
		t.Fatalf("got %v", got)
	}
}

// A file the plan cannot read is not reported as already fixed.
func TestPlanUnreadableIsNotFixed(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{".nvmrc": "22.23.1\n"})
	p := filepath.Join(dir, ".nvmrc")
	os.WriteFile(p, []byte("22.23.1\n"+strings.Repeat("#\n", 3<<20)), 0o644) // over the 4 MiB default
	_, already, err := pins.Plan(context.Background(), dir, ".nvmrc", 1, pins.RuleNode, nil)
	if already || err == nil {
		t.Fatalf("already=%v err=%v", already, err)
	}
}

func TestPrintable(t *testing.T) {
	if got := pins.Printable("a\x1b[31mb\rc  d"); got != `a\u001b[31mb\u000dc  d` {
		t.Fatalf("got %q", got)
	}
}

// An ARG default its FROM reads is one pin, planned through the image.
func TestARGDefaultIsOnePin(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{"Dockerfile": "ARG NODE_VERSION=24.22.0\nFROM node:${NODE_VERSION}-slim\n"})
	res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Props["source"] != "node-image" {
		t.Fatalf("findings %+v", res.Findings)
	}
}

// A line image moves at the line the scan read, not at the first match of
// its text.
func TestPlanLineImage(t *testing.T) {
	srv := fakeRegistry(t)
	for _, k := range []string{"gcr.io/distroless/nodejs20-debian12", "gcr.io/distroless/nodejs22-debian12"} {
		srv[k] = struct {
			platforms []string
			base      string
		}{both, ""}
	}
	dir := t.TempDir()
	write(t, dir, map[string]string{"Dockerfile": "FROM gcr.io/distroless/nodejs20-debian12\n"})
	ch, _, err := pins.Plan(context.Background(), dir, "Dockerfile", 1, pins.RuleNode, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ch.Edits[0].New[0]; got != "FROM gcr.io/distroless/nodejs22-debian12" {
		t.Fatalf("got %q", got)
	}
}
