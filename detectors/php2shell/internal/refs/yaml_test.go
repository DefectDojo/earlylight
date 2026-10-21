package refs

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type yref struct {
	line     int
	image    string
	ctx      string // substring
	editLine int
	editFile string
}

func checkRefs(t *testing.T, content string, refs []Ref, want []yref) {
	t.Helper()
	if len(refs) != len(want) {
		t.Fatalf("got %d refs %+v, want %d", len(refs), refs, len(want))
	}
	for i, w := range want {
		r := refs[i]
		if r.Line != w.line || r.Image != w.image || !strings.Contains(r.Context, w.ctx) {
			t.Errorf("ref %d = line %d image %q ctx %q, want %+v", i, r.Line, r.Image, r.Context, w)
		}
		if w.editLine != 0 && r.EditLine != w.editLine {
			t.Errorf("ref %d edit line %d, want %d", i, r.EditLine, w.editLine)
		}
		if w.editFile != "" && r.EditFile != w.editFile {
			t.Errorf("ref %d edit file %q, want %q", i, r.EditFile, w.editFile)
		}
		if r.EditFile == r.File {
			checkParts(t, content, r)
		}
	}
}

func checkSkips(t *testing.T, skips []Skip, want ...string) {
	t.Helper()
	if len(skips) != len(want) {
		t.Fatalf("got skips %+v, want %v", skips, want)
	}
	for i, w := range want {
		if !strings.Contains(skips[i].Reason, w) {
			t.Errorf("skip %d = %+v, want %q", i, skips[i], w)
		}
	}
}

func TestCompose(t *testing.T) {
	in := `x-php: &php
  image: "php:8.3-fpm"
services:
  web:
    <<: *php
  worker:
    image: php:${PHP_TAG:-8.2-cli}
  env:
    image: ${REGISTRY-docker.io}/library/php:${FROM_ENV}
  nodefault:
    image: php:${MISSING}
  built:
    build: .
    image: myapp/web:1.0
  localonly:
    build: .
    pull_policy: build
    image: myapp/local
  required:
    image: 'php:${NEED:?must be set}'
  dollar:
    image: php:8.3$$x
  nothing: {}
`
	env := "# comment\nexport FROM_ENV=8.4.1-apache # trailing\nPHP_OTHER='x'\n"
	refs, skips := scanContent(t, "docker-compose.yml", in, ".env", env)
	checkRefs(t, in, refs, []yref{
		{line: 2, image: "php:8.3-fpm", ctx: "services.web.image", editLine: 2},
		{line: 7, image: "php:8.2-cli", ctx: "services.worker.image", editLine: 7},
		{line: 9, image: "docker.io/library/php:8.4.1-apache", ctx: "services.env.image", editLine: 2, editFile: ".env"},
		{line: 14, image: "myapp/web:1.0", ctx: "also has build", editLine: 14},
	})
	r := refs[2]
	if len(r.Vars) != 2 || r.Vars[0].Name != "REGISTRY" || !r.Vars[0].Default || r.Vars[1].Name != "FROM_ENV" || r.Vars[1].Line != 2 {
		t.Errorf("vars %+v", r.Vars)
	}
	if p := r.Parts[len(r.Parts)-1]; p.File != ".env" || p.Line != 2 || p.Column != 17 || p.Var != "FROM_ENV" {
		t.Errorf("env part %+v", p)
	}
	checkSkips(t, skips,
		"MISSING is not set in .env and has no default",
		"pull_policy: build",
		"NEED is required",
		"not a valid image reference",
	)
}

func TestComposeEnvUnsupported(t *testing.T) {
	in := "services:\n  a:\n    image: php:${T}\n  b:\n    image: php:${U:-8.3}\n"
	_, skips := scanContent(t, "compose.yaml", in, ".env", "T=\"8.3${X}\"\n")
	checkSkips(t, skips, "escapes and variables in double-quoted values are not supported")
	refs, skips := scanContent(t, "compose.yaml", in, ".env", "this is not dotenv\n")
	checkSkips(t, skips, "is not KEY=VALUE", "is not KEY=VALUE")
	if len(refs) != 0 {
		t.Errorf("refs %+v", refs)
	}
}

func TestKubernetes(t *testing.T) {
	in := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: busybox:1.36
      containers:
        - name: php
          image: php:8.3-fpm # comment
        - name: sidecar
          image: ""
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: c}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers: [{name: x, image: 'php:8.1-cli'}]
---
apiVersion: serving.knative.dev/v1
kind: Service
spec:
  template:
    spec:
      containers:
        - image: docker.io/library/php:8.4-apache
---
just: a config file
containers:
  - image: php:5.6
`
	refs, skips := scanContent(t, "deploy/app.yaml", in)
	checkRefs(t, in, refs, []yref{
		{line: 10, image: "busybox:1.36", ctx: "spec.template.spec.initContainers[0].image"},
		{line: 13, image: "php:8.3-fpm", ctx: "containers[0].image", editLine: 13},
		{line: 25, image: "php:8.1-cli", ctx: "jobTemplate.spec.template.spec.containers[0].image", editLine: 25},
		{line: 33, image: "docker.io/library/php:8.4-apache", ctx: "containers[0]"},
	})
	if refs[2].Column != 42 {
		t.Errorf("flow column %d", refs[2].Column)
	}
	checkSkips(t, skips)
}

func TestHelmTemplateSkipped(t *testing.T) {
	in := "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: {{ .Values.image.repository }}:{{ .Values.image.tag }}\n"
	refs, skips := scanContent(t, "chart/templates/pod.yaml", in)
	if len(refs) != 0 {
		t.Errorf("refs %+v", refs)
	}
	checkSkips(t, skips, "Go template")
}

func TestHelmValues(t *testing.T) {
	in := `image:
  registry: docker.io
  repository: library/php
  tag: "8.3.20-fpm-alpine"
  pullPolicy: IfNotPresent
worker:
  image:
    repository: php
    tag: 8.2-cli
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
empty:
  image:
    repository: php
    tag: ""
numeric:
  image:
    repository: php
    tag: 8.3
sidecar:
  image: php:8.1-cli
extraContainers:
  - name: x
    image: php:8.4-cli
dependencies:
  - repository: https://charts.example.com
`
	refs, skips := scanContent(t, "chart/values.yaml", in)
	checkRefs(t, in, refs, []yref{
		{line: 3, image: "docker.io/library/php:8.3.20-fpm-alpine", ctx: "image.repository+tag", editLine: 4},
		{line: 8, image: "php:8.2-cli@sha256:1111111111111111111111111111111111111111111111111111111111111111", ctx: "worker.image", editLine: 9},
		{line: 20, image: "php:8.1-cli", ctx: "sidecar.image", editLine: 20},
		{line: 23, image: "php:8.4-cli", ctx: "extraContainers[0].image"},
	})
	checkSkips(t, skips, "tag is empty", "unquoted YAML number")
	p := refs[0].Parts
	if len(p) != 5 || p[4].Text != "8.3.20-fpm-alpine" || p[4].Line != 4 || p[4].Column != 9 || p[1].Line != 0 {
		t.Errorf("parts %+v", p)
	}
}

func TestGitHubActions(t *testing.T) {
	in := `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    container: php:8.3-cli
    services:
      db:
        image: mysql:8
      cache:
        image: ${{ matrix.redis }}
    steps:
      - uses: actions/checkout@v4
      - uses: docker://php:8.2-cli
  other:
    container:
      image: 'php:8.1-cli'
`
	refs, skips := scanContent(t, ".github/workflows/ci.yml", in)
	checkRefs(t, in, refs, []yref{
		{line: 5, image: "php:8.3-cli", ctx: "jobs.test.container"},
		{line: 8, image: "mysql:8", ctx: "jobs.test.services.db.image"},
		{line: 13, image: "php:8.2-cli", ctx: "jobs.test.steps[1].uses", editLine: 13},
		{line: 16, image: "php:8.1-cli", ctx: "jobs.other.container.image"},
	})
	if refs[2].Parts[0].Column != 24 {
		t.Errorf("docker:// part %+v", refs[2].Parts)
	}
	checkSkips(t, skips, "GitHub Actions expression")

	action := "name: a\nruns:\n  using: docker\n  image: docker://php:8.3-cli\n"
	refs, _ = scanContent(t, "action.yml", action)
	checkRefs(t, action, refs, []yref{{line: 4, image: "php:8.3-cli", ctx: "runs.image"}})
}

func TestGitLab(t *testing.T) {
	in := `image: php:8.3-cli
services:
  - mysql:8
variables:
  image: not-a-job
default:
  image:
    name: php:8.2-cli
    entrypoint: [""]
test:
  image: $CI_REGISTRY/php:8.3
  services:
    - name: redis:7
  script: [phpunit]
.template:
  image: php:8.1-fpm
`
	refs, skips := scanContent(t, ".gitlab-ci.yml", in)
	checkRefs(t, in, refs, []yref{
		{line: 1, image: "php:8.3-cli", ctx: "image"},
		{line: 3, image: "mysql:8", ctx: "services[0]"},
		{line: 8, image: "php:8.2-cli", ctx: "default.image.name"},
		{line: 13, image: "redis:7", ctx: "test.services[0].name"},
		{line: 16, image: "php:8.1-fpm", ctx: ".template.image"},
	})
	checkSkips(t, skips, "CI variable")
}

func TestBitbucket(t *testing.T) {
	in := `image: php:8.3-cli
definitions:
  services:
    db:
      image: mysql:8
pipelines:
  default:
    - step:
        image:
          name: php:8.2-cli
        script: [composer test]
`
	refs, _ := scanContent(t, "bitbucket-pipelines.yml", in)
	checkRefs(t, in, refs, []yref{
		{line: 1, image: "php:8.3-cli"},
		{line: 5, image: "mysql:8"},
		{line: 10, image: "php:8.2-cli", ctx: "image.name"},
	})
}

func TestYAMLUnparseable(t *testing.T) {
	_, skips := scanContent(t, "docker-compose.yml", "services:\n  a: [\n")
	checkSkips(t, skips, "YAML does not parse")
	// Unrelated YAML that does not parse and never mentions images is ignored.
	_, skips = scanContent(t, "config/foo.yml", "a: [\n")
	checkSkips(t, skips)
}

func TestYAMLAliasBomb(t *testing.T) {
	// The billion laughs: each level references the previous nine times.
	var b strings.Builder
	b.WriteString("a: &a [\"lol\"]\n")
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		b.WriteString(n + ": &" + n + " [")
		for i := 0; i < 9; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString("*" + prev)
		}
		b.WriteString("]\n")
		prev = n
	}
	b.WriteString("services:\n  x:\n    image: php:8.3\n    labels: *i\n")
	refs, _ := scanContent(t, "docker-compose.yml", b.String())
	if len(refs) != 1 {
		t.Fatalf("refs %+v", refs)
	}
	refs, _ = scanContent(t, "values.yaml", b.String())
	if len(refs) != 1 {
		t.Fatalf("refs %+v", refs)
	}
	// Merge-key fan-out.
	var m strings.Builder
	m.WriteString("l0: &l0 {image: php:8.3}\n")
	for i := 1; i < 30; i++ {
		m.WriteString("l" + itoa(i) + ": &l" + itoa(i) + " {<<: [*l" + itoa(i-1) + ", *l" + itoa(i-1) + ", *l" + itoa(i-1) + "]}\n")
	}
	m.WriteString("services:\n  x:\n    <<: *l29\n")
	refs, skips := scanContent(t, "docker-compose.yml", m.String())
	if len(refs)+len(skips) == 0 {
		t.Fatalf("nothing reported")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestScanWalk(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Dockerfile", "FROM php:8.3\n")
	write("docker/app.Dockerfile", "FROM php:8.2\n")
	write("docker/Dockerfile.prod", "FROM php:8.1\n")
	write("docker/Dockerfile.dockerignore", "FROM php:7.0\n")
	write("Containerfile", "FROM php:8.4\n")
	write(".git/Dockerfile", "FROM php:7.1\n")
	write("node_modules/x/Dockerfile", "FROM php:7.2\n")
	write("vendor/autoload.php", "<?php\n")
	write("vendor/pkg/Dockerfile", "FROM php:7.3\n")
	write("ops/vendor/Dockerfile", "FROM php:8.0\n") // not a dependency directory
	write("big/Dockerfile", "FROM php:8.3\n"+strings.Repeat("#\n", 600))
	if err := os.Symlink(filepath.Join(root, "Dockerfile"), filepath.Join(root, "linked.Dockerfile")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.TempDir(), filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	refs, skips, err := Scan(root, Options{MaxFileSize: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range refs {
		got = append(got, r.File+"="+r.Image)
	}
	want := "Containerfile=php:8.4 Dockerfile=php:8.3 docker/Dockerfile.prod=php:8.1 docker/app.Dockerfile=php:8.2 ops/vendor/Dockerfile=php:8.0"
	if strings.Join(got, " ") != want {
		t.Errorf("refs %v\nwant %s", got, want)
	}
	var sk []string
	for _, s := range skips {
		sk = append(sk, s.File)
	}
	if strings.Join(sk, " ") != "big/Dockerfile linked.Dockerfile node_modules outside vendor" {
		t.Errorf("skips %+v", skips)
	}
}

func TestSafePath(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.TempDir(), filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "/etc/passwd", "../x", "a/../../x", "l/x", `a\b`} {
		if _, err := SafePath(root, bad); err == nil {
			t.Errorf("SafePath(%q) accepted", bad)
		}
	}
	if p, err := SafePath(root, "d/Dockerfile"); err != nil || p != filepath.Join(root, "d", "Dockerfile") {
		t.Errorf("SafePath = %q, %v", p, err)
	}
}
