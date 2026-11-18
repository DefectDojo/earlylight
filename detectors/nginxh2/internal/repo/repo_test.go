package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, s := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func scan(t *testing.T, files map[string]string) Result {
	t.Helper()
	res, err := Scan(context.Background(), tree(t, files), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func at(res Result, file string, line int) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.File == file && f.Line == line {
			out = append(out, f)
		}
	}
	return out
}

func one(t *testing.T, res Result, file string, line int, rule string, st knowledge.Status) Finding {
	t.Helper()
	fs := at(res, file, line)
	for _, f := range fs {
		if f.Rule == rule && f.Status == st {
			return f
		}
	}
	t.Fatalf("no %s %s at %s:%d; have %+v", rule, st, file, line, fs)
	return Finding{}
}

func TestClassifyAndTags(t *testing.T) {
	for img, fam := range map[string]string{
		"nginx": "nginx", "docker.io/library/nginx:1.31.8": "nginx", "mirror.gcr.io/library/nginx:1": "nginx", "harbor.corp/dockerhub/library/nginx:1.30.6": "nginx",
		"public.ecr.aws/nginx/nginx:1.31.8": "nginx", "nginxinc/nginx-unprivileged:1.31.7-alpine": "nginx-unprivileged",
		"openresty/openresty:1.31.8.1-alpine": "openresty", "bitnamilegacy/nginx:1.29.1-debian-12-r0": "bitnami-nginx",
		"registry.k8s.io/ingress-nginx/controller:v1.15.1": "ingress-nginx", "nginx/nginx-ingress:5.7.1-alpine": "nginx-ingress",
		"docker.angie.software/angie:1.12.4": "angie",
	} {
		f, ok := Classify(img)
		if !ok || f.ID != fam {
			t.Errorf("Classify(%s) = %v %v, want %s", img, f.ID, ok, fam)
		}
	}
	for _, img := range []string{"myorg/nginx:1.0", "nginxproxy/nginx-proxy:1.6", "python:3.12", "caddy:2", "traefik:3"} {
		if f, ok := Classify(img); ok {
			t.Errorf("Classify(%s) = %s", img, f.ID)
		}
	}
	cases := []struct {
		fam     Family
		tag     string
		version string
		variant string
		exact   bool
		fixed   string
	}{
		{Official, "1.31.8-alpine3.24-perl", "1.31.8", "-alpine3.24-perl", true, "1.31.9-alpine3.24-perl"},
		{Official, "1.30.6", "1.30.6", "", true, "1.30.7"},
		{Official, "1.29.8-bookworm", "1.29.8", "-bookworm", true, ""},
		{Official, "1.31", "", "", false, ""},
		{Official, "mainline-alpine", "", "", false, ""},
		{Unprivileged, "1.31.7-alpine-slim", "1.31.7", "-alpine-slim", true, "1.31.9-alpine-slim"},
		{OpenResty, "1.31.8.1-0-alpine-fat", "1.31.8.1", "-0-alpine-fat", true, ""},
		{OpenResty, "1.31-alpine", "", "", false, ""},
		{Ingress, "v1.15.1", "1.15.1", "", true, ""},
		{F5Ingress, "5.7.1-alpine", "5.7.1", "-alpine", true, "5.8.0-alpine"},
		{F5Ingress, "4.0.0", "4.0.0", "", true, ""},
	}
	for _, c := range cases {
		tg, ok := c.fam.ParseTag(c.tag)
		if ok != c.exact || tg.Version != c.version || tg.Variant != c.variant {
			t.Errorf("%s ParseTag(%s) = %+v %v", c.fam.ID, c.tag, tg, ok)
			continue
		}
		if ok {
			if got := c.fam.FixedTag(tg); got != c.fixed {
				t.Errorf("%s FixedTag(%s) = %q, want %q", c.fam.ID, c.tag, got, c.fixed)
			}
		}
	}
	if v := Ingress.Judge(Tag{Version: "0.49.3"}); v[knowledge.Reuse].Status != knowledge.Unknown || v[knowledge.Flow].Status != knowledge.Vulnerable {
		t.Errorf("ingress v0: %+v", v)
	}
	if v := F5Ingress.Judge(Tag{Version: "5.8.0"}); v[knowledge.Flow].Status != knowledge.Fixed {
		t.Errorf("F5 5.8.0: %+v", v)
	}
	if v := F5Ingress.Judge(Tag{Version: "5.9.0"}); v[knowledge.Flow].Status != knowledge.Unknown {
		t.Errorf("F5 5.9.0: %+v", v)
	}
	// R5: a tag on a line newer than any known is never cleared.
	res := scan(t, map[string]string{"Dockerfile": "FROM nginx:37.0.0\nFROM nginx:1.32.0-alpine\n"})
	one(t, res, "Dockerfile", 1, RuleNotChecked, knowledge.Unknown)
	one(t, res, "Dockerfile", 2, RuleNotChecked, knowledge.Unknown)
}

func TestImages(t *testing.T) {
	res := scan(t, map[string]string{
		"Dockerfile":   "ARG T=1.30.6\nFROM nginx:${T}-perl AS a\nFROM nginx:1.31.9\nFROM nginx:mainline\nFROM nginx@sha256:" + strings.Repeat("a", 64) + "\nFROM nginx:1.18.0\nFROM nginx:1.8.1\n",
		"compose.yaml": "services:\n  a:\n    image: registry.k8s.io/ingress-nginx/controller:v1.15.1@sha256:" + strings.Repeat("b", 64) + "\n  b:\n    image: nginx:1.31.9@sha256:" + strings.Repeat("c", 64) + "\n",
	})
	f := one(t, res, "Dockerfile", 2, RuleImage, knowledge.Vulnerable)
	if !f.Fixable || f.edit.target != "1.30.7-perl" {
		t.Errorf("ARG-driven tag: %+v", f)
	}
	if fs := at(res, "Dockerfile", 3); len(fs) != 0 {
		t.Errorf("a fixed tag gave findings: %+v", fs)
	}
	if f := one(t, res, "Dockerfile", 4, RuleNotChecked, knowledge.Unknown); f.Pull != "nginx:mainline" {
		t.Errorf("moving tag: %+v", f)
	}
	one(t, res, "Dockerfile", 5, RuleNotChecked, knowledge.Unknown)
	f = one(t, res, "Dockerfile", 6, RuleImage, knowledge.Vulnerable)
	if f.CVEs[1].Status != knowledge.NotAffected || f.Fixable {
		t.Errorf("1.18.0: %+v", f)
	}
	if fs := at(res, "Dockerfile", 7); len(fs) != 0 {
		t.Errorf("1.8.1 predates HTTP/2: %+v", fs)
	}
	// A vulnerable tag pinned by digest is judged by its tag, not fixed.
	if f := one(t, res, "compose.yaml", 3, RuleImage, knowledge.Vulnerable); f.Fixable {
		t.Errorf("digest pinned: %+v", f)
	}
	// A fixed tag with a digest: the digest decides, so it is read.
	if f := one(t, res, "compose.yaml", 5, RuleNotChecked, knowledge.Unknown); f.Pull == "" {
		t.Errorf("fixed tag with digest: %+v", f)
	}
}

func TestPackages(t *testing.T) {
	df := strings.Join([]string{
		"FROM debian:12", // 1
		"RUN apt-get update && apt-get install -y nginx=1.22.1-9+deb12u10", // 2
		"RUN apt-get install -y nginx-light",                               // 3
		"FROM alpine:3.24 AS a",                                            // 4
		"RUN apk add --no-cache nginx~1.30 openresty=1.27.1.2-r0",          // 5
		"RUN apk add 'nginx>=1.30.7-r0'",                                   // 6
		"FROM a",                                                           // 7
		"ARG PKG=nginx",                                                    // 8
		"RUN set -eux; ( apk add --no-cache $PKG )",                        // 9
		"FROM rockylinux:9",                                                // 10
		"RUN dnf install -y nginx-1.24.0-4.el9 && dnf module install -y nginx:1.26/common", // 11
		"FROM debian:trixie-slim",                   // 12
		"RUN echo nginx | xargs apt-get install -y", // 13
		"RUN bash -lc 'DEBIAN_FRONTEND=noninteractive apt-get -y install nginx=1.31.8-1~trixie'", // 14
		"RUN apt-get install -y $(cat pkgs.txt) $EXTRA",                                          // 15
		"FROM ubuntu:24.04",            // 16
		"RUN <<EOF",                    // 17
		"apt-get update",               // 18
		"apt-get install -y \\",        // 19
		"  nginx-core",                 // 20
		"EOF",                          // 21
		"FROM scratchbase/custom:1",    // 22
		"RUN apt-get install -y nginx", // 23
		"FROM debian:12",               // 24
		"RUN apt-get install -y nginx-common libnginx-mod-stream nginxify", // 25
	}, "\n")
	res := scan(t, map[string]string{"Dockerfile": df})
	f := one(t, res, "Dockerfile", 2, RulePackage, knowledge.Vulnerable)
	if f.Props["pinned"] != "=1.22.1-9+deb12u10" || !strings.Contains(f.Fix, "Debian had published no fixed nginx") {
		t.Errorf("apt pin: %+v", f)
	}
	one(t, res, "Dockerfile", 3, RulePackage, knowledge.Vulnerable)
	if fs := at(res, "Dockerfile", 5); len(fs) != 2 {
		t.Errorf("apk ~ and openresty pin: %+v", fs)
	}
	if fs := at(res, "Dockerfile", 6); len(fs) != 0 {
		t.Errorf("a floor at the fix: %+v", fs)
	}
	// ARG value, subshell, inherited Alpine 3.24 base, which has the fixed
	// package since 2026-11-18: decided at build time.
	one(t, res, "Dockerfile", 9, RuleNotChecked, knowledge.Unknown)
	if fs := at(res, "Dockerfile", 11); len(fs) != 2 {
		t.Errorf("dnf name-version and module: %+v", fs)
	}
	one(t, res, "Dockerfile", 13, RulePackage, knowledge.Vulnerable)
	f = one(t, res, "Dockerfile", 14, RulePackage, knowledge.Vulnerable)
	if !strings.Contains(f.Fix, "1.31.9-1~trixie") {
		t.Errorf("nginx.org pin fix: %s", f.Fix)
	}
	one(t, res, "Dockerfile", 17, RulePackage, knowledge.Vulnerable) // heredoc
	one(t, res, "Dockerfile", 23, RuleNotChecked, knowledge.Unknown) // base distribution unknown
	// nginx-common and nginxify install no server; the module brings one
	// in as its dependency (review 2, finding 9).
	if fs := at(res, "Dockerfile", 25); len(fs) != 1 || fs[0].Props["package"] != "libnginx-mod-stream" {
		t.Errorf("packages without a server, and a module: %+v", fs)
	}
	opaque := 0
	for _, s := range res.Skips {
		if s.Line == 15 {
			opaque++
		}
	}
	if opaque != 2 {
		t.Errorf("opaque install arguments: %+v", res.Skips)
	}
}

func TestConfigs(t *testing.T) {
	res := scan(t, map[string]string{
		"nginx/conf.d/site.conf":             "server {\n  listen 443 ssl;\n  http2 on;\n  location / { proxy_pass http://u; }\n}\n",
		"nginx/off.conf":                     "server { listen 443 ssl; http2 off; }\n",
		"deploy/templates/web.conf.template": "server {\n listen ${PORT} ssl http2;\n}\n",
		"supervisord.conf":                   "[program:x]\ncommand=/bin/true\n",
		"broken.conf":                        "server { listen 443 http2;\n",
		"k8s/cm.yaml":                        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\ndata:\n  nginx.conf: |\n    http {\n      server { listen 443 ssl http2; }\n    }\n  plain: \"server { listen 80 http2; }\"\n",
	})
	f := one(t, res, "nginx/conf.d/site.conf", 3, RuleHTTP2, knowledge.NotAffected)
	if f.Props["flow"] != "exposed" || f.Props["reuse"] != "exposed" || !strings.Contains(f.Interim, "http2 off;") {
		t.Errorf("%+v", f)
	}
	one(t, res, "deploy/templates/web.conf.template", 2, RuleHTTP2, knowledge.NotAffected)
	if fs := at(res, "nginx/off.conf", 1); len(fs) != 0 {
		t.Errorf("off: %+v", fs)
	}
	one(t, res, "k8s/cm.yaml#nginx.conf", 7, RuleHTTP2, knowledge.NotAffected)
	one(t, res, "k8s/cm.yaml#plain", 9, RuleHTTP2, knowledge.NotAffected)
	skipped := false
	for _, s := range res.Skips {
		skipped = skipped || s.File == "broken.conf"
	}
	if !skipped {
		t.Errorf("a configuration that names http2 and does not parse was not recorded: %+v", res.Skips)
	}
}

func TestChartsAndValues(t *testing.T) {
	res := scan(t, map[string]string{
		"chart/Chart.yaml": "apiVersion: v2\nname: x\nversion: 1.0.0\ndependencies:\n  - name: ingress-nginx\n    version: 4.15.1\n",
		"values.yaml":      "controller:\n  image:\n    registry: registry.k8s.io\n    image: ingress-nginx/controller\n    tag: \"v1.15.1\"\n    digest: sha256:" + strings.Repeat("d", 64) + "\n",
	})
	one(t, res, "chart/Chart.yaml", 5, RuleImage, knowledge.Vulnerable)
	f := one(t, res, "values.yaml", 5, RuleImage, knowledge.Vulnerable)
	if f.Fixable || !strings.Contains(f.Fix, "archived") {
		t.Errorf("%+v", f)
	}
}

// fakeRegistry answers Tags and Verify from memory.
type fakeRegistry struct {
	tags     []string
	verified []string
	fail     error
}

func (r *fakeRegistry) reg() Registry {
	return Registry{
		Tags: func(context.Context, string) ([]string, error) { return r.tags, nil },
		Verify: func(_ context.Context, cur, target string) (string, error) {
			r.verified = append(r.verified, cur+">"+target)
			if r.fail != nil {
				return "", r.fail
			}
			return "sha256:" + strings.Repeat("e", 64), nil
		},
	}
}

func plan(t *testing.T, root string, file string, line int, reg Registry) (*Change, error) {
	t.Helper()
	res, err := Scan(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.File == file && f.Line == line && f.Rule == RuleImage {
			return Plan(context.Background(), root, f, reg, Options{})
		}
	}
	t.Fatalf("no image finding at %s:%d: %+v", file, line, res.Findings)
	return nil, nil
}

func TestPlan(t *testing.T) {
	root := tree(t, map[string]string{
		"Dockerfile":   "ARG V=1.30.6\nFROM nginx:1.31.8-alpine AS a\nFROM nginx:${V}\nFROM nginx:1.29.8\n",
		"compose.yaml": "services:\n  web:\n    image: \"nginxinc/nginx-unprivileged:${TAG:-1.31.7-alpine}\"\n",
	})
	fr := &fakeRegistry{tags: []string{"1.31.8-alpine", "1.31.9-alpine", "1.30.7", "1.31.9-alpine-slim"}}
	ch, err := plan(t, root, "Dockerfile", 2, fr.reg())
	if err != nil || ch.New != "FROM nginx:1.31.9-alpine AS a" {
		t.Fatalf("plan: %+v %v", ch, err)
	}
	if err := Apply(root, ch); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if !strings.HasPrefix(string(b), "ARG V=1.30.6\nFROM nginx:1.31.9-alpine AS a\n") {
		t.Errorf("applied: %s", b)
	}
	// Applying the same change twice fails: the line no longer reads as planned.
	if err := Apply(root, ch); err == nil {
		t.Error("a stale change was applied")
	}
	// The tag from an ARG default is edited where it is written.
	ch, err = plan(t, root, "Dockerfile", 3, fr.reg())
	if err != nil || ch.Line != 1 || ch.New != "ARG V=1.30.7" {
		t.Fatalf("ARG: %+v %v", ch, err)
	}
	// A line with no fix is declined, with the reason.
	if _, err := plan(t, root, "Dockerfile", 4, fr.reg()); err == nil || !strings.Contains(err.Error(), "received no fix") {
		t.Errorf("1.29: %v", err)
	}
	// The target is not published yet.
	fr.tags = []string{"1.31.7-alpine", "1.31.8-alpine"}
	if _, err := plan(t, root, "compose.yaml", 3, fr.reg()); err == nil || !strings.Contains(err.Error(), "has not published 1.31.9-alpine") {
		t.Errorf("unpublished: %v", err)
	}
	// Verification fails: declined, nothing changes.
	fr.tags = append(fr.tags, "1.31.9-alpine")
	fr.fail = &Declined{Reason: "still holds /usr/sbin/nginx"}
	if _, err := plan(t, root, "compose.yaml", 3, fr.reg()); err == nil || !strings.Contains(err.Error(), "still holds") {
		t.Errorf("verify: %v", err)
	}
	fr.fail = errors.New("connection refused")
	if _, err := plan(t, root, "compose.yaml", 3, fr.reg()); err == nil || !strings.Contains(err.Error(), "not checked") {
		t.Errorf("verify error: %v", err)
	}
	// Without a registry (offline): declined.
	if _, err := plan(t, root, "compose.yaml", 3, Registry{}); err == nil {
		t.Error("offline plan was not declined")
	}
}

func TestPlanSharedVariable(t *testing.T) {
	root := tree(t, map[string]string{
		"Dockerfile": "ARG V=1.30.6\nFROM nginx:${V}\nRUN echo ${V}\n",
	})
	fr := &fakeRegistry{tags: []string{"1.30.7"}}
	if _, err := plan(t, root, "Dockerfile", 2, fr.reg()); err == nil || !strings.Contains(err.Error(), "more than one place") {
		t.Errorf("shared variable: %v", err)
	}
	if len(fr.verified) != 0 {
		t.Error("verified before declining")
	}
}

func TestSameBase(t *testing.T) {
	for _, c := range []struct {
		a, b string
		ok   bool
	}{
		{"debian 13", "debian 13", true}, {"alpine 3.23.4", "alpine 3.24.1", true}, {"debian 12", "debian 13", false},
		{"ubuntu 24.04", "ubuntu 24.10", false}, {"", "debian 13", false}, {"alpine 3.24", "debian 13", false},
	} {
		if err := SameBase(c.a, c.b); (err == nil) != c.ok {
			t.Errorf("SameBase(%q, %q) = %v", c.a, c.b, err)
		}
	}
}

func TestShell(t *testing.T) {
	got := installs(`set -e; if true; then apk add --virtual .x nginx; fi && sudo -E apt-get -o Dpkg::Options::=--force-confnew install -y nginx-full=1.2>/dev/null`, 0)
	if len(got) != 2 || got[0].args[0] != "nginx" || got[1].args[0] != "nginx-full=1.2" {
		t.Errorf("%+v", got)
	}
	if v := lineVars("P=nginx-light; apt-get install $P", nil); v["P"] != "nginx-light" {
		t.Errorf("lineVars %v", v)
	}
	if v := lineVars("P=$(cat x); apt-get install $P", map[string]string{"P": "nginx"}); v["P"] != "" {
		t.Errorf("lineVars from a command %v", v)
	}
}

func TestAlpineBranches(t *testing.T) {
	for img, want := range map[string]string{
		"alpine:3.24": "3.24", "alpine:3.24.4": "3.24", "alpine:edge": "edge", "alpine:3": "", "alpine": "", "alpine:latest": "",
		"python:3.12-alpine3.23": "3.23", "nginx:1.31.8-alpine3.24-perl": "3.24", "nginx:1.31.8-alpine": "", "node:22-alpine": "",
	} {
		if got := alpineBranchOf(img); got != want {
			t.Errorf("alpineBranchOf(%s) = %q, want %q", img, got, want)
		}
	}
	root := tree(t, map[string]string{"Dockerfile": strings.Join([]string{
		"FROM alpine:3.23",             // 1
		"RUN apk add --no-cache nginx", // 2
		"FROM alpine:3.24",             // 3
		"RUN apk add --no-cache \\",    // 4
		"    curl nginx=1.30.6-r0",     // 5
		"FROM alpine:3",                // 6
		"RUN apk add nginx",            // 7
		"FROM alpine:3.22",             // 8
		"RUN apk add nginx=1.28.3-r7",  // 9
		"FROM alpine:3.24",             // 10
		"RUN apk add nginx=1.30.7-r0",  // 11
	}, "\n") + "\n"})
	res, err := Scan(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	one(t, res, "Dockerfile", 2, RulePackage, knowledge.Vulnerable)
	f := one(t, res, "Dockerfile", 4, RulePackage, knowledge.Vulnerable)
	if !f.Fixable {
		t.Fatalf("a 3.24 pin is fixable: %+v", f)
	}
	// R14: the branch's index decides; without it (offline) nothing moves.
	if _, err := Plan(context.Background(), root, f, Registry{}, Options{}); err == nil {
		t.Fatal("a pin moved without reading the branch's index")
	}
	index := func(v string) Registry {
		return Registry{APKIndex: func(_ context.Context, branch string) (string, error) { return v, nil }}
	}
	ch, err := Plan(context.Background(), root, f, index("1.30.7-r0"), Options{})
	if err != nil || ch.Line != 5 || ch.New != "    curl nginx=1.30.7-r0" {
		t.Fatalf("pin plan: %+v %v", ch, err)
	}
	// The index has a later fixed build: that is the pin.
	if ch, err := Plan(context.Background(), root, f, index("1.30.7-r1"), Options{}); err != nil || ch.New != "    curl nginx=1.30.7-r1" {
		t.Errorf("later build: %+v %v", ch, err)
	}
	// The index has no fixed build any more (or yet): declined.
	if _, err := Plan(context.Background(), root, f, index("1.30.6-r0"), Options{}); err == nil {
		t.Error("moved to an unfixed build")
	}
	one(t, res, "Dockerfile", 7, RuleNotChecked, knowledge.Unknown)
	if f := one(t, res, "Dockerfile", 9, RulePackage, knowledge.Vulnerable); f.Fixable || !strings.Contains(f.Fix, "Alpine 3.22 had no fixed") {
		t.Errorf("3.22 pin: %+v", f)
	}
	if fs := at(res, "Dockerfile", 11); len(fs) != 0 {
		t.Errorf("the fixed pin: %+v", fs)
	}
}

// Review 2, finding 3: what a deployment changes about an image it reads
// (command, environment, mounted configuration, a Dockerfile building on
// it) is recorded, so the image's own configuration is not trusted.
func TestR3Deployment(t *testing.T) {
	res := scan(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: nginx:1.29\n    command: [nginx, -c, /etc/nginx/site/nginx.conf]\n    volumes:\n      - ./conf.d:/etc/nginx/conf.d:ro\n  plain:\n    image: nginx:1.30\n",
		"k8s.yaml":     "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: x}\nspec:\n  template:\n    spec:\n      containers:\n      - name: a\n        image: nginx:mainline\n        volumeMounts:\n        - {name: c, mountPath: /etc/nginx/conf.d}\n      - name: b\n        image: nginx:stable\n",
		"Dockerfile":   "FROM nginx:1.31 AS a\nCOPY site.conf /etc/nginx/conf.d/\nFROM nginx:alpine AS b\nLABEL x=y\n",
	})
	for _, c := range []struct {
		file string
		line int
		want bool
	}{{"compose.yaml", 3, true}, {"compose.yaml", 8, false}, {"k8s.yaml", 9, true}, {"k8s.yaml", 13, false}, {"Dockerfile", 1, true}, {"Dockerfile", 3, false}} {
		f := one(t, res, c.file, c.line, RuleNotChecked, knowledge.Unknown)
		if got := f.Props["deployment"] != ""; got != c.want {
			t.Errorf("%s:%d deployment %q, want %v", c.file, c.line, f.Props["deployment"], c.want)
		}
	}
}

// Review 2, finding 9: nothing nginx-shaped is passed over in silence.
func TestR9NeverSilent(t *testing.T) {
	root := tree(t, map[string]string{
		"Dockerfile": strings.Join([]string{
			"FROM registry.example.com/nginx:1.31.8",                   // 1
			"FROM cgr.dev/chainguard/nginx:1.31.8",                     // 2
			"FROM axizdkr/tengine:latest",                              // 3
			"FROM kong:3.9",                                            // 4
			"FROM debian:12",                                           // 5
			"COPY --from=nginx:1.31.8 /usr/sbin/nginx /usr/sbin/nginx", // 6
			"RUN apt-get install -y libnginx-mod-http-lua python3-certbot-nginx nginx-module-njs", // 7
			"RUN apt-get install -y angie-pro", // 8
		}, "\n") + "\n",
		"real/compose.yaml": "services:\n  web:\n    image: nginx:1.31.8\n",
	})
	if err := os.Symlink("real/compose.yaml", filepath.Join(root, "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("Dockerfile", filepath.Join(root, "Dockerfile.prod")); err != nil {
		t.Fatal(err)
	}
	res, err := Scan(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []int{1, 2, 3, 4} {
		if f := one(t, res, "Dockerfile", line, RuleNotChecked, knowledge.Unknown); f.Pull == "" {
			t.Errorf("line %d is not read from its registry: %+v", line, f)
		}
	}
	if f := one(t, res, "Dockerfile", 6, RuleImage, knowledge.Vulnerable); f.Fixable {
		t.Errorf("COPY --from is not edited by fix: %+v", f)
	}
	if fs := at(res, "Dockerfile", 7); len(fs) != 3 {
		t.Errorf("module packages: %+v", fs)
	}
	one(t, res, "Dockerfile", 8, RuleNotChecked, knowledge.Unknown)
	skipped := map[string]bool{}
	for _, s := range res.Skips {
		skipped[s.File] = true
	}
	if !skipped["compose.yaml"] || !skipped["Dockerfile.prod"] {
		t.Errorf("symbolic links not recorded: %+v", res.Skips)
	}
}

// R14: on edge, a pin above Alpine's fixed package is never moved down.
func TestR14EdgeNoDowngrade(t *testing.T) {
	root := tree(t, map[string]string{"Dockerfile": "FROM alpine:edge\nRUN apk add nginx=1.31.8-r0\n"})
	res, err := Scan(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	f := one(t, res, "Dockerfile", 2, RulePackage, knowledge.Vulnerable)
	if strings.Contains(f.Fix, "1.30.7-r0, the fixed package") {
		t.Errorf("fix text proposes a move down: %s", f.Fix)
	}
	reg := Registry{APKIndex: func(context.Context, string) (string, error) { return "1.30.7-r0", nil }}
	if _, err := Plan(context.Background(), root, f, reg, Options{}); err == nil {
		t.Error("planned a move down a line")
	}
}

// R15: the F5 controller's move to 5.8.0 is labelled a minor upgrade.
func TestR15MinorUpgrade(t *testing.T) {
	res := scan(t, map[string]string{"compose.yaml": "services:\n  ic:\n    image: nginx/nginx-ingress:5.7.1\n"})
	f := one(t, res, "compose.yaml", 3, RuleImage, knowledge.Vulnerable)
	if !strings.Contains(f.Fix, "minor upgrade") || strings.Contains(f.Fix, "same line") {
		t.Errorf("%s", f.Fix)
	}
}

// R16: what is known only from a date or a version is worded so.
func TestR16Wording(t *testing.T) {
	res := scan(t, map[string]string{"Dockerfile": "FROM debian:trixie-slim\nRUN echo 'deb http://nginx.org/packages/mainline/debian trixie nginx' > /etc/apt/sources.list.d/n.list && apt-get update && apt-get install -y nginx\n"})
	f := one(t, res, "Dockerfile", 2, RuleNotChecked, knowledge.Unknown)
	if strings.Contains(f.Message, "a build from 2026-11-18 on gets") {
		t.Errorf("certainty about nginx.org's packages: %s", f.Message)
	}
}

// R17: a YAML file that stops decoding, or has more documents than are
// read, is recorded as not checked.
func TestR17YAMLErrors(t *testing.T) {
	many := strings.Repeat("---\nkind: Service\n", 1100)
	res := scan(t, map[string]string{
		"bad.yaml":  "kind: ConfigMap\ndata:\n  a.conf: x\n---\nkey: [unclosed\n",
		"many.yaml": many,
	})
	got := map[string]bool{}
	for _, s := range res.Skips {
		got[s.File] = true
	}
	if !got["bad.yaml"] || !got["many.yaml"] {
		t.Errorf("%+v", res.Skips)
	}
}

// Verification 3: changes a deployment makes reach the image they apply
// to, through FROM aliases, Helm charts, Compose overrides and extends.
func TestV3Deployments(t *testing.T) {
	res := scan(t, map[string]string{
		"Dockerfile":                      "FROM nginx:1.29 AS base\nFROM base\nCOPY h2.conf /etc/nginx/conf.d/\n",
		"chart/values.yaml":               "image:\n  repository: nginx\n  tag: \"1.29\"\n",
		"chart/templates/deploy.yaml":     "spec:\n  containers:\n  - name: web\n    volumeMounts:\n    - {name: conf, mountPath: /etc/nginx/conf.d}\n",
		"app/docker-compose.yml":          "services:\n  web:\n    image: nginx:1.29\n  other:\n    image: nginx:1.30\n    extends: {file: base.yml, service: web}\n  third:\n    image: nginx:1.31\n    volumes_from: [web]\n",
		"app/docker-compose.override.yml": "services:\n  web:\n    volumes:\n      - ./conf.d:/etc/nginx/conf.d\n",
		".gitlab-ci.yml":                  "test:\n  services:\n    - name: nginx:1.29\n      command: [nginx, -c, /builds/h2.conf]\n  script: [true]\n",
	})
	for _, c := range []struct {
		file string
		line int
	}{{"Dockerfile", 1}, {"chart/values.yaml", 2}, {"app/docker-compose.yml", 3}, {"app/docker-compose.yml", 5}, {"app/docker-compose.yml", 8}, {".gitlab-ci.yml", 3}} {
		f := one(t, res, c.file, c.line, RuleNotChecked, knowledge.Unknown)
		if f.Props["deployment"] == "" {
			t.Errorf("%s:%d has no deployment note: %+v", c.file, c.line, f.Props)
		}
	}
}
