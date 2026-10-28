package pins_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
)

var depsRepo = map[string]string{
	"requirements.txt":          "requests==2.32.3\npycurl==7.48.0\nPyMuPDF==1.27.2.3\npyarrow==26.0.0\nBrotli==1.1.0\n",
	"poetry.lock":               "[[package]]\nname = \"curl-cffi\"\nversion = \"0.16.3\"\n\n[[package]]\nname = \"duckdb\"\nversion = \"1.0.0\"\n",
	"web/package.json":          "{\n  \"dependencies\": {\n    \"iltorb\": \"^2.4.5\"\n  },\n  \"devDependencies\": {\n    \"electron\": \"40.1.0\"\n  }\n}\n",
	"web/package-lock.json":     "{\n  \"packages\": {\n    \"node_modules/iltorb\": {\n      \"version\": \"2.4.5\"\n    }\n  }\n}\n",
	"Gemfile":                   "source 'https://rubygems.org'\ngem 'brotli', '0.9.0'\n",
	"Gemfile.lock":              "GEM\n  specs:\n    brotli (0.9.0)\n    rake (13.0.0)\n",
	"rb/Gemfile":                "gem \"brotli\", \"0.9.0\"\n",
	"locked/build.gradle":       "dependencies {\n  implementation 'com.aayushatharva.brotli4j:brotli4j:1.23.0'\n}\n",
	"locked/gradle.lockfile":    "com.aayushatharva.brotli4j:brotli4j:1.20.0=runtimeClasspath\n",
	"py/Pipfile.lock":           "{\n  \"_meta\": {\"hash\": {\"sha256\": \"x\"}, \"sources\": []},\n  \"default\": {\n    \"pycurl\": {\"version\": \"==7.48.0\"}\n  },\n  \"develop\": {}\n}\n",
	"java/pom.xml":              "<project>\n  <properties>\n    <brotli4j.version>1.20.0</brotli4j.version>\n  </properties>\n  <dependencies>\n    <dependency>\n      <groupId>com.aayushatharva.brotli4j</groupId>\n      <artifactId>brotli4j</artifactId>\n      <version>${brotli4j.version}</version>\n    </dependency>\n  </dependencies>\n</project>\n",
	"kt/build.gradle.kts":       "dependencies {\n  implementation(\"com.aayushatharva.brotli4j:native-linux-x86_64:1.23.0\")\n}\n",
	"gradle/libs.versions.toml": "[versions]\nbrotli4j = \"1.22.0\"\n[libraries]\nbrotli4j = { module = \"com.aayushatharva.brotli4j:brotli4j\", version.ref = \"brotli4j\" }\n",
	"rs/Cargo.lock":             "[[package]]\nname = \"brotlic-sys\"\nversion = \"0.2.2\"\n",
	"go.mod":                    "module example.com/x\n\ngo 1.27\n\nrequire github.com/andybalholm/brotli v1.2.6\n",
	"svc/packages.lock.json":    "{\n  \"version\": 1,\n  \"dependencies\": {\n    \"net8.0/linux-x64\": {\n      \"Microsoft.NETCore.App.Runtime.linux-x64\": {\n        \"type\": \"Direct\",\n        \"resolved\": \"8.0.32\"\n      }\n    }\n  }\n}\n",
}

func TestDependencies(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, depsRepo)
	res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		fx := "manual"
		if f.Fixable {
			fx = "fix"
		}
		got[f.File+":"+strconv.Itoa(f.Line)] = f.Rule + " " + f.Props["package"] + " " + f.Props["current"] + " " + f.Level + " " + fx
	}
	want := map[string]string{
		"requirements.txt:2":          "brotli/dependency pycurl 7.48.0 error fix",
		"requirements.txt:3":          "brotli/dependency PyMuPDF 1.27.2.3 error fix",
		"requirements.txt:4":          "brotli/dependency pyarrow 26.0.0 error manual",
		"poetry.lock:3":               "brotli/dependency curl-cffi 0.16.3 error manual",
		"web/package.json:3":          "brotli/dependency iltorb 2.4.5 error manual",
		"web/package.json:6":          "brotli/dependency electron 40.1.0 error manual",
		"web/package-lock.json:3":     "brotli/dependency iltorb 2.4.5 error manual",
		"Gemfile:2":                   "brotli/dependency brotli 0.9.0 error manual",
		"rb/Gemfile:1":                "brotli/dependency brotli 0.9.0 error fix",
		"locked/build.gradle:2":       "brotli/dependency com.aayushatharva.brotli4j:brotli4j 1.23.0 error manual",
		"locked/gradle.lockfile:1":    "brotli/dependency com.aayushatharva.brotli4j:brotli4j 1.20.0 error manual",
		"py/Pipfile.lock:4":           "brotli/dependency pycurl 7.48.0 error manual",
		"Gemfile.lock:3":              "brotli/dependency brotli 0.9.0 error manual",
		"java/pom.xml:3":              "brotli/dependency com.aayushatharva.brotli4j:brotli4j 1.20.0 error fix",
		"kt/build.gradle.kts:2":       "brotli/dependency com.aayushatharva.brotli4j:native-linux-x86_64 1.23.0 error fix",
		"gradle/libs.versions.toml:2": "brotli/dependency com.aayushatharva.brotli4j:brotli4j 1.22.0 error fix",
		"rs/Cargo.lock:3":             "brotli/dependency brotlic-sys 0.2.2 error manual",
		"go.mod:5":                    "brotli/dependency github.com/andybalholm/brotli 1.2.6 warning manual",
		"svc/packages.lock.json:5":    "brotli/dotnet  8.0.32 error manual",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %q, want %q", k, got[k], w)
		}
	}
	for k, g := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: unexpected %q", k, g)
		}
	}
}

func TestPlanDependencies(t *testing.T) {
	for _, c := range []struct {
		file string
		line int
		want string
	}{
		{"requirements.txt", 2, "pycurl==7.49.0"},
		{"rb/Gemfile", 1, "gem \"brotli\", \"0.9.1\""},
		{"java/pom.xml", 3, "    <brotli4j.version>1.24.0</brotli4j.version>"},
		{"kt/build.gradle.kts", 2, "  implementation(\"com.aayushatharva.brotli4j:native-linux-x86_64:1.24.0\")"},
		{"gradle/libs.versions.toml", 2, "brotli4j = \"1.24.0\""},
	} {
		dir := t.TempDir()
		write(t, dir, depsRepo)
		ch, _, err := pins.Plan(context.Background(), dir, c.file, c.line, pins.RuleDependency, nil)
		if err != nil {
			t.Errorf("%s:%d: %v", c.file, c.line, err)
			continue
		}
		if ch == nil || len(ch.Edits) == 0 {
			t.Errorf("%s:%d: no change", c.file, c.line)
			continue
		}
		if ch.Edits[0].New[0] != c.want {
			t.Errorf("%s:%d: got %q, want %q", c.file, c.line, ch.Edits[0].New[0], c.want)
		}
	}
}

// A dependency whose lockfile its tool must rewrite is not edited alone.
func TestPlanDependencyLocked(t *testing.T) {
	for _, c := range []struct {
		file string
		line int
		want string
	}{
		{"Gemfile", 2, "bundle update brotli"},
		{"locked/build.gradle", 2, "--write-locks"},
	} {
		dir := t.TempDir()
		write(t, dir, depsRepo)
		_, _, err := pins.Plan(context.Background(), dir, c.file, c.line, pins.RuleDependency, nil)
		if _, ok := pins.IsDeclined(err); !ok || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s:%d: got %v, want a decline naming %q", c.file, c.line, err, c.want)
		}
	}
}
