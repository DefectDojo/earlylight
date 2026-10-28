package refs

import (
	"strings"
	"testing"
	"time"
)

// checkInvariants verifies what every Ref promises: its Parts make up its
// Image, and every Part with a Column is written verbatim there.
func checkInvariants(t *testing.T, contents map[string][]byte, rs []Ref) {
	t.Helper()
	for _, r := range rs {
		var b strings.Builder
		for _, p := range r.Parts {
			b.WriteString(p.Text)
			if p.Column == 0 {
				continue
			}
			c, ok := contents[p.File]
			if !ok {
				t.Fatalf("part %+v names an unknown file", p)
			}
			lines := rawLines(c)
			if p.Line < 1 || p.Line > len(lines) {
				t.Fatalf("part %+v: line out of range", p)
			}
			l := lines[p.Line-1]
			if p.Column-1+len(p.Text) > len(l) || l[p.Column-1:p.Column-1+len(p.Text)] != p.Text {
				t.Fatalf("part %+v not verbatim in %q", p, l)
			}
		}
		if b.String() != r.Image {
			t.Fatalf("parts %+v do not make %q", r.Parts, r.Image)
		}
		if r.Image == "" || r.Line < 1 {
			t.Fatalf("bad ref %+v", r)
		}
	}
}

func FuzzDockerfile(f *testing.F) {
	for _, s := range []string{
		"FROM php:8.3-fpm\n",
		"# escape=`\nARG V=8.3.20\nFROM `\n php:${V}-fpm AS a\nRUN <<EOF\nFROM php:7\nEOF\nFROM a\n",
		"ARG A=1 B=\"php:${A:-x}\"\r\nFROM --platform=$BUILDPLATFORM ${B:+php}:8.${A}\r\n",
		"ARG T\nFROM php:${T:-8.2}@sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
		"\uFEFFFROM \\\n# c\n\n  php:8.3 \\\n AS x\nCOPY <<-'E' <<F /x\n\tE\nF\nONBUILD RUN <<Z\nZ\n",
		"FROM ${a:-${b:-${c:-php}}}:${d-8}\nFROM \"php\":'8.3'\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		start := time.Now()
		rs, _, err := ScanFiles("/nonexistent-php2shell-root", []string{"Dockerfile"}, Options{Overlay: map[string][]byte{"Dockerfile": data}})
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("took %v on %d bytes", d, len(data))
		}
		checkInvariants(t, map[string][]byte{"Dockerfile": data}, rs)
	})
}

// fuzzYAML scans data as file name (with env as the .env beside it) and
// checks the Ref invariants and a time bound.
func fuzzYAML(t *testing.T, name string, data, env []byte) {
	envName := name[:strings.LastIndexByte(name, '/')+1] + ".env"
	ov := map[string][]byte{name: data, envName: env}
	start := time.Now()
	rs, skips, err := ScanFiles("/nonexistent-php2shell-root", []string{name}, Options{Overlay: ov})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v on %d bytes", d, len(data))
	}
	checkInvariants(t, ov, rs)
	for _, s := range skips {
		if strings.ContainsAny(s.Reason+s.Text, "\n\r") {
			t.Fatalf("multi-line skip %+v", s)
		}
	}
}

func FuzzCompose(f *testing.F) {
	for _, s := range []string{
		"services:\n  a:\n    image: php:${T:-8.3}\n  b:\n    <<: *x\n",
		"x: &x {image: \"php:8.2\"}\nservices:\n  a:\n    <<: *x\n    build: .\n",
		"a: &a [x]\nb: &b [*a,*a,*a,*a]\nc: &c [*b,*b,*b,*b]\nservices: {s: {image: php, labels: *c}}\n",
		"services:\n  a:\n    image: ${R-docker.io}/php:${T:?x}${U:+-y}$$\n",
	} {
		f.Add([]byte(s), []byte("T=8.4\nexport U='x'\n"))
	}
	f.Fuzz(func(t *testing.T, data, env []byte) { fuzzYAML(t, "docker-compose.yml", data, env) })
}

func FuzzKubernetes(f *testing.F) {
	for _, s := range []string{
		"apiVersion: v1\nkind: Pod\nspec:\n  containers: [{image: php:8.3}]\n  initContainers:\n  - image: 'php:8.2'\n",
		"apiVersion: argoproj.io/v1alpha1\nkind: Workflow\nspec:\n  templates:\n  - container: {image: php:8.2}\n    script: {image: php:8.1}\n    sidecars: [{image: x}]\n",
		"apiVersion: tekton.dev/v1\nkind: Task\nspec:\n  stepTemplate: {image: a}\n  steps: [{image: b}]\n---\nservices:\n  w: {image: php:8}\n",
		`{"apiVersion":"v1","kind":"List","items":[{"spec":{"containers":[{"image":"php:8.3"}]}}]}`,
	} {
		f.Add(false, []byte(s))
	}
	f.Fuzz(func(t *testing.T, asJSON bool, data []byte) {
		name := "deploy/app.yaml"
		if asJSON {
			name = "deploy/app.json"
		}
		fuzzYAML(t, name, data, nil)
	})
}

func FuzzHelmValues(f *testing.F) {
	for _, s := range []string{
		"image:\n  registry: docker.io\n  repository: php\n  tag: '8.3'\n  digest: sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
		"a:\n  image: php:8.3\nb:\n  image: {repository: php, tag: 8.3}\nextraContainers: [{image: php:8.2}]\n",
		"x: &x {repository: php, tag: \"1\"}\ny: {<<: *x}\nz: [*x, *x]\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) { fuzzYAML(t, "chart/values.yaml", data, nil) })
}

var ciNames = []string{".gitlab-ci.yml", ".github/workflows/ci.yml", "bitbucket-pipelines.yml", "action.yml"}

func FuzzCI(f *testing.F) {
	for i, s := range []string{
		"image: php:8.3\ntest:\n  image: {name: php:8.2}\n  services: [mysql:8, {name: $X}]\n.t:\n  image: php:8.1\n",
		"jobs:\n  a:\n    container: php:8.3\n    services: {db: {image: mysql}}\n    steps: [{uses: docker://php:8.1}, {uses: 'docker://${{ x }}'}]\n",
		"image: php:8.3\npipelines:\n  default:\n  - step: {image: {name: php:8.2}}\n",
		"runs:\n  using: docker\n  image: docker://php:8.3\n",
	} {
		f.Add(uint8(i), []byte(s))
	}
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		fuzzYAML(t, ciNames[int(kind)%len(ciNames)], data, nil)
	})
}

// FuzzDotEnv checks the .env parser on its own (every value it accepts is
// verbatim at its column) and through Compose interpolation.
func FuzzDotEnv(f *testing.F) {
	for _, s := range []string{
		"A=1\nexport B='two words' # c\nC=\"x\"\n#x\nD=e #f\n",
		"A=${B}\nC=\"$D\"\nE='\n",
		"\uFEFFX = y\r\nexport   Z=1\r\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, env []byte) {
		e := &dotEnv{file: ".env", vars: map[string]dotEnvEntry{}}
		parseDotEnv(e, env)
		lines := rawLines(env)
		for k, ent := range e.vars {
			if ent.err != nil {
				continue
			}
			for _, p := range ent.val.parts() {
				if p.Column == 0 {
					continue
				}
				l := lines[p.Line-1]
				if p.Column-1+len(p.Text) > len(l) || l[p.Column-1:p.Column-1+len(p.Text)] != p.Text || p.Var != k {
					t.Fatalf("%s: part %+v not verbatim in %q", k, p, l)
				}
			}
		}
		compose := []byte("services:\n  a:\n    image: php:${A:-8.3}-${B-x}\n  b:\n    image: $X\n")
		fuzzYAML(t, "compose.yaml", compose, env)
	})
}
