package pins_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
)

func write(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

var repo = map[string]string{
	"Dockerfile": "ARG BUN=1.4.3\n" +
		"FROM node:24.22.0-slim AS build\n" +
		"FROM mcr.microsoft.com/dotnet/aspnet:8.0.32-bookworm-slim AS api\n" +
		"FROM oven/bun:${BUN}-slim AS edge\n" +
		"FROM node:20-alpine AS legacy\n" +
		"FROM node:24-slim AS fine\n" +
		"FROM node:24.22.1 AS fixed\n" +
		"FROM mcr.microsoft.com/dotnet/sdk:8.0.415 AS sdk\n" +
		"FROM node@sha256:" + strings.Repeat("a", 64) + " AS pinned\n",
	".nvmrc":                   "v22.23.3\n",
	"web/.node-version":        "24.22.1\n",
	"tools/.tool-versions":     "python 3.13.1\nnodejs 24.21.0\nbun 1.4.3 # pinned\n",
	"mise.toml":                "[env]\nnode = \"20\"\n[tools]\nnode = \"22.23.3\"\nbun = [\"1.3\"]\n",
	"app/package.json":         "{\n  \"name\": \"app\",\n  \"engines\": { \"node\": \">=22\" },\n  \"volta\": {\n    \"node\": \"24.22.0\"\n  },\n  \"packageManager\": \"bun@1.4.3+sha512.abc\"\n}\n",
	".github/workflows/ci.yml": "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        node: [20, 22]\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: '24.22.0'\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.node }}\n      - uses: oven-sh/setup-bun@v2\n        with:\n          bun-version: latest\n",
	"testdata/old/.nvmrc":      "22.23.3\n",
	"node_modules/x/.nvmrc":    "18.0.0\n",
	"docs/README.md":           "FROM node:18\n",
}

type want struct {
	rule, current, fixed, source, level string
	fixable                             bool
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, repo)
	res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]want{}
	for _, f := range res.Findings {
		k := f.File + ":" + itoa(f.Line)
		got[k] = want{f.Rule, f.Props["current"], f.Props["fixed"], f.Props["source"], f.Level, f.Fixable}
		if !strings.Contains(f.Message, "CVE-2026-111497") || f.Fix == "" {
			t.Errorf("%s: message %q fix %q", k, f.Message, f.Fix)
		}
	}
	exp := map[string]want{
		"Dockerfile:2":                {pins.RuleNode, "24.22.0", "24.22.1", "node-image", "error", true},
		"Dockerfile:3":                {pins.RuleDotnet, "8.0.32", "8.0.33", "dotnet-image", "error", true},
		"Dockerfile:4":                {pins.RuleBun, "1.4.3", "1.4.4", "bun-image", "error", true},
		"Dockerfile:5":                {pins.RuleNode, "20", "22.23.4, 24.22.1 or 26.12.1", "node-image", "error", true},
		"Dockerfile:8":                {pins.RuleDotnet, "8.0.415", "8.0.427", "dotnet-sdk-image", "error", true},
		".nvmrc:1":                    {pins.RuleNode, "22.23.3", "22.23.4", "nvmrc", "error", true},
		"tools/.tool-versions:2":      {pins.RuleNode, "24.21.0", "24.22.1", "tool-versions", "error", true},
		"tools/.tool-versions:3":      {pins.RuleBun, "1.4.3", "1.4.4", "tool-versions", "error", true},
		"mise.toml:4":                 {pins.RuleNode, "22.23.3", "22.23.4", "mise", "error", true},
		"mise.toml:5":                 {pins.RuleBun, "1.3", "1.4.4", "mise", "error", true},
		"app/package.json:5":          {pins.RuleNode, "24.22.0", "24.22.1", "volta", "error", true},
		"app/package.json:7":          {pins.RuleBun, "1.4.3", "1.4.4", "package-manager", "error", true},
		".github/workflows/ci.yml:11": {pins.RuleNode, "24.22.0", "24.22.1", "setup-node", "error", true},
		".github/workflows/ci.yml:7":  {pins.RuleNode, "20", "22.23.4, 24.22.1 or 26.12.1", "setup-node", "error", false},
		"testdata/old/.nvmrc:1":       {pins.RuleNode, "22.23.3", "22.23.4", "nvmrc", "note", false},
	}
	for k, w := range exp {
		if g, ok := got[k]; !ok {
			t.Errorf("%s: not found", k)
		} else if g != w {
			t.Errorf("%s: got %+v, want %+v", k, g, w)
		}
	}
	for k := range got {
		if _, ok := exp[k]; !ok {
			t.Errorf("%s: unexpected %+v", k, got[k])
		}
	}
	digest := false
	for _, s := range res.Skips {
		if s.File == "Dockerfile" && strings.Contains(s.Reason, "pinned by digest") {
			digest = true
		}
	}
	if !digest {
		t.Errorf("digest-pinned image not listed as not checked: %+v", res.Skips)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestScanFilesOnlyThoseFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, repo)
	res, err := pins.Scan(context.Background(), dir, []string{".nvmrc"}, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].File != ".nvmrc" {
		t.Fatalf("got %+v", res.Findings)
	}
}

func TestJudgedValues(t *testing.T) {
	cases := map[string]string{ // .nvmrc value -> fixed, "" when fine or not judged
		"24.22.0": "24.22.1", "v24.22.0": "24.22.1", "24.22.1": "", "24.23.0": "", "24": "", "24.21": "24.22",
		"22.23.3": "22.23.4", "26.12.0": "26.12.1", "26": "", "27.0.0": "", "lts/*": "", "node": "",
		"lts/jod": "", "lts/iron": "22.23.4, 24.22.1 or 26.12.1", "20": "22.23.4, 24.22.1 or 26.12.1",
		"25.9.0": "22.23.4, 24.22.1 or 26.12.1", "system": "", "24.22.0-rc.1": "",
	}
	for v, fixed := range cases {
		dir := t.TempDir()
		write(t, dir, map[string]string{".nvmrc": v + "\n"})
		res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(res.Findings) == 1 {
			got = res.Findings[0].Props["fixed"]
		} else if len(res.Findings) > 1 {
			t.Fatalf("%s: %d findings", v, len(res.Findings))
		}
		if got != fixed {
			t.Errorf("%q: fixed %q, want %q", v, got, fixed)
		}
	}
}

func TestImagesByLineAndSDK(t *testing.T) {
	cases := map[string]string{ // FROM image -> fixed, "" when not reported
		"gcr.io/distroless/nodejs20-debian12":                                    "22.23.4, 24.22.1 or 26.12.1",
		"gcr.io/distroless/nodejs22-debian12:nonroot":                            "",
		"registry.access.redhat.com/ubi9/nodejs-20-minimal:1":                    "22.23.4, 24.22.1 or 26.12.1",
		"public.ecr.aws/lambda/nodejs:20.2026.10.01.12":                          "22.23.4, 24.22.1 or 26.12.1",
		"public.ecr.aws/lambda/nodejs:22":                                        "",
		"mcr.microsoft.com/azure-functions/node:4-node18-slim":                   "22.23.4, 24.22.1 or 26.12.1",
		"mcr.microsoft.com/devcontainers/typescript-node:1-20-bookworm":          "22.23.4, 24.22.1 or 26.12.1",
		"public.ecr.aws/lambda/dotnet:6":                                         "8.0.33, 9.0.22 or 10.0.14",
		"mcr.microsoft.com/azure-functions/dotnet-isolated:4-dotnet-isolated7.0": "8.0.33, 9.0.22 or 10.0.14",
		"mcr.microsoft.com/dotnet/sdk:8.0.132":                                   "8.0.133",
		"mcr.microsoft.com/dotnet/sdk:9.0.319-bookworm-slim":                     "9.0.320",
		"mcr.microsoft.com/dotnet/sdk:8.0.319":                                   "8.0.133 or 8.0.427, 9.0.123 or 9.0.320, 10.0.114 or 10.0.403",
		"mcr.microsoft.com/dotnet/sdk:10.0":                                      "",
		"cimg/node:24.21.1-browsers":                                             "24.22.1",
		"bitnami/node:22.23.3":                                                   "22.23.4",
		"node:24.22.0@sha256:" + strings.Repeat("b", 64):                         "24.22.1",
	}
	for img, fixed := range cases {
		dir := t.TempDir()
		write(t, dir, map[string]string{"Dockerfile": "FROM " + img + "\n"})
		res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(res.Findings) == 1 {
			got = res.Findings[0].Props["fixed"]
		} else if len(res.Findings) > 1 {
			t.Fatalf("%s: %d findings", img, len(res.Findings))
		}
		if got != fixed {
			t.Errorf("%s: fixed %q, want %q", img, got, fixed)
		}
	}
}

func TestPlanTextPins(t *testing.T) {
	cases := []struct {
		file string
		line int
		rule string
		want string // the edited line
	}{
		{".nvmrc", 1, pins.RuleNode, "v22.23.4"},
		{"tools/.tool-versions", 3, pins.RuleBun, "bun 1.4.4 # pinned"},
		{"mise.toml", 4, pins.RuleNode, `node = "22.23.4"`},
		{"app/package.json", 5, pins.RuleNode, `    "node": "24.22.1"`},
		{"app/package.json", 7, pins.RuleBun, `  "packageManager": "bun@1.4.4+sha512.abc"`},
		{".github/workflows/ci.yml", 11, pins.RuleNode, "          node-version: '24.22.1'"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		write(t, dir, repo)
		res, err := pins.Scan(context.Background(), dir, []string{c.file}, pins.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var props map[string]string
		for _, f := range res.Findings {
			if f.Line == c.line {
				props = map[string]string{"current": f.Props["current"]}
			}
		}
		ch, already, err := pins.Plan(context.Background(), dir, c.file, c.line, c.rule, props)
		if err != nil || already {
			t.Fatalf("%s:%d: %v already=%v", c.file, c.line, err, already)
		}
		if len(ch.Edits) != 1 || ch.Edits[0].New[0] != c.want || ch.File != c.file {
			t.Fatalf("%s:%d: got %+v", c.file, c.line, ch)
		}
		if err := pins.Apply(dir, ch); err != nil {
			t.Fatal(err)
		}
		// Planning again finds nothing left to do.
		if _, already, err := pins.Plan(context.Background(), dir, c.file, c.line, c.rule, props); err != nil || !already {
			t.Errorf("%s:%d after apply: already=%v err=%v", c.file, c.line, already, err)
		}
	}
}

func TestPlanDeclines(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, repo)
	for _, c := range []struct {
		file string
		line int
		rule string
		why  string
	}{
		{"testdata/old/.nvmrc", 1, pins.RuleNode, "Test fixture"},
		{".nvmrc", 2, pins.RuleNode, "no longer on line 2"},
	} {
		_, _, err := pins.Plan(context.Background(), dir, c.file, c.line, c.rule, nil)
		d, ok := pins.IsDeclined(err)
		if !ok || !strings.Contains(d.Reason, c.why) {
			t.Errorf("%s:%d: %v, want a decline mentioning %q", c.file, c.line, err, c.why)
		}
	}
}

// published is the fake registry: image -> platforms, with the base OS.
type published map[string]struct {
	platforms []string
	base      string
}

func fakeRegistry(t *testing.T) published {
	t.Helper()
	reg := published{}
	old := pins.VerifyImage
	pins.VerifyImage = func(_ context.Context, current, target string) (string, error) {
		tg, ok := reg[target]
		if !ok {
			return "", errors.New("not found")
		}
		cur := reg[strings.SplitN(current, "@", 2)[0]]
		have := map[string]bool{}
		for _, p := range tg.platforms {
			have[p] = true
		}
		for _, p := range cur.platforms {
			if !have[p] {
				return "", &pins.Declined{Reason: target + " is not published for " + p}
			}
		}
		if cur.base != "" && cur.base != tg.base {
			return "", &pins.Declined{Reason: target + " is built on " + tg.base}
		}
		return "sha256:" + strings.Repeat("d", 64), nil
	}
	t.Cleanup(func() { pins.VerifyImage = old })
	return reg
}

var both = []string{"linux/amd64", "linux/arm64/v8"}

func nodeIndex(reg published, base, tag string, platforms ...string) {
	reg["node:"+tag] = struct {
		platforms []string
		base      string
	}{platforms, base}
}

func TestPlanImage(t *testing.T) {
	srv := fakeRegistry(t)
	nodeIndex(srv, "debian:bookworm-slim", "24.22.0-slim", both...)
	nodeIndex(srv, "debian:bookworm-slim", "24.22.1-slim", both...)
	dir := t.TempDir()
	write(t, dir, map[string]string{"Dockerfile": "FROM node:24.22.0-slim\nRUN npm ci\n"})
	ch, already, err := pins.Plan(context.Background(), dir, "Dockerfile", 1, pins.RuleNode, nil)
	if err != nil || already {
		t.Fatalf("%v already=%v", err, already)
	}
	if ch.Edits[0].New[0] != "FROM node:24.22.1-slim" || !strings.Contains(ch.Summary, "node:24.22.1-slim") {
		t.Fatalf("got %+v", ch)
	}
}

func TestPlanImageDeclines(t *testing.T) {
	srv := fakeRegistry(t)
	nodeIndex(srv, "debian:bookworm-slim", "22.23.3-slim", both...)
	nodeIndex(srv, "debian:bookworm-slim", "22.23.4-slim", "linux/amd64") // arm64 missing
	nodeIndex(srv, "debian:bookworm-slim", "24.22.0", both...)
	nodeIndex(srv, "debian:trixie", "24.22.1", both...) // base OS moved
	for _, c := range []struct{ from, why string }{
		{"node:22.23.3-slim", "not published for linux/arm64"},
		{"node:24.22.0", "built on debian:trixie"},
		{"node:26.12.0-alpine", "could not be verified"},
	} {
		dir := t.TempDir()
		write(t, dir, map[string]string{"Dockerfile": "FROM " + c.from + "\n"})
		_, _, err := pins.Plan(context.Background(), dir, "Dockerfile", 1, pins.RuleNode, nil)
		d, ok := pins.IsDeclined(err)
		if !ok || !strings.Contains(d.Reason, c.why) {
			t.Errorf("%s: %v, want a decline mentioning %q", c.from, err, c.why)
		}
	}
}

func TestPlanUpgrades(t *testing.T) {
	srv := fakeRegistry(t)
	nodeIndex(srv, "debian:bookworm-slim", "20-slim", both...)
	nodeIndex(srv, "debian:bookworm-slim", "22-slim", both...)
	cases := []struct {
		files      map[string]string
		file       string
		line       int
		rule, want string
	}{
		{map[string]string{".nvmrc": "20\n"}, ".nvmrc", 1, pins.RuleNode, "22"},
		{map[string]string{".nvmrc": "lts/iron\n"}, ".nvmrc", 1, pins.RuleNode, "lts/jod"},
		{map[string]string{".tool-versions": "nodejs 18.20.8\n"}, ".tool-versions", 1, pins.RuleNode, "nodejs 22.23.4"},
		{map[string]string{"package.json": "{\n  \"engines\": { \"node\": \"20.x\" }\n}\n"}, "package.json", 2, pins.RuleNode, `  "engines": { "node": "22.x" }`},
		{map[string]string{"app.yaml": "runtime: nodejs20\n"}, "app.yaml", 1, pins.RuleNode, "runtime: nodejs22"},
		{map[string]string{"template.yaml": "Resources:\n  F:\n    Properties:\n      Runtime: nodejs20.x\n"}, "template.yaml", 4, pins.RuleNode, "      Runtime: nodejs22.x"},
		{map[string]string{"stack.ts": "new Function(this, 'F', { runtime: Runtime.NODEJS_18_X });\n"}, "stack.ts", 1, pins.RuleNode, "new Function(this, 'F', { runtime: Runtime.NODEJS_22_X });"},
		{map[string]string{"Dockerfile": "FROM debian:12\nRUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -\n"}, "Dockerfile", 2, pins.RuleNode, "RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash -"},
		{map[string]string{".bun-version": "1.3.9\n"}, ".bun-version", 1, pins.RuleBun, "1.4.4"},
		{map[string]string{"global.json": "{\n  \"sdk\": {\n    \"version\": \"8.0.319\"\n  }\n}\n"}, "global.json", 3, pins.RuleDotnet, `    "version": "8.0.427"`},
		{map[string]string{"Dockerfile": "FROM node:20-slim\n"}, "Dockerfile", 1, pins.RuleNode, "FROM node:22-slim"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		write(t, dir, c.files)
		ch, _, err := pins.Plan(context.Background(), dir, c.file, c.line, c.rule, nil)
		if err != nil {
			t.Errorf("%s:%d: %v", c.file, c.line, err)
			continue
		}
		if ch.Edits[0].New[0] != c.want || !strings.Contains(ch.Summary, "upgrade") {
			t.Errorf("%s:%d: got %q (%s), want %q", c.file, c.line, ch.Edits[0].New[0], ch.Summary, c.want)
		}
	}
	// .NET and target frameworks stay manual: the app must be retargeted.
	dir := t.TempDir()
	write(t, dir, map[string]string{"template.yaml": "Resources:\n  F:\n    Properties:\n      Runtime: dotnet6\n"})
	if _, _, err := pins.Plan(context.Background(), dir, "template.yaml", 4, pins.RuleDotnet, nil); err == nil {
		t.Error("a .NET major upgrade was planned")
	}
}

func TestPlanTagAndDigest(t *testing.T) {
	srv := fakeRegistry(t)
	nodeIndex(srv, "debian:bookworm-slim", "24.22.0-slim", both...)
	nodeIndex(srv, "debian:bookworm-slim", "24.22.1-slim", both...)
	old := "sha256:" + strings.Repeat("c", 64)
	dir := t.TempDir()
	write(t, dir, map[string]string{"Dockerfile": "FROM node:24.22.0-slim@" + old + "\n"})
	ch, _, err := pins.Plan(context.Background(), dir, "Dockerfile", 1, pins.RuleNode, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := ch.Edits[0].New[0]
	if !strings.HasPrefix(got, "FROM node:24.22.1-slim@sha256:") || strings.Contains(got, old) {
		t.Fatalf("got %q", got)
	}
}

func TestPlanARGDefault(t *testing.T) {
	srv := fakeRegistry(t)
	srv["oven/bun:1.4.3-slim"] = struct {
		platforms []string
		base      string
	}{[]string{"linux/amd64"}, ""}
	srv["oven/bun:1.4.4-slim"] = struct {
		platforms []string
		base      string
	}{both, ""}
	dir := t.TempDir()
	write(t, dir, map[string]string{"Dockerfile": "ARG BUN=1.4.3\nFROM oven/bun:${BUN}-slim\n"})
	ch, _, err := pins.Plan(context.Background(), dir, "Dockerfile", 2, pins.RuleBun, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Edits[0].Line != 1 || ch.Edits[0].New[0] != "ARG BUN=1.4.4" {
		t.Fatalf("got %+v", ch.Edits)
	}
}
