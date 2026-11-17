package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, s := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func scan(t *testing.T, root string) Result {
	t.Helper()
	res, err := Scan(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func find(res Result, file string, line int) (Finding, bool) {
	for _, f := range res.Findings {
		if f.File == file && f.Line == line {
			return f, true
		}
	}
	return Finding{}, false
}

func TestJudgeTag(t *testing.T) {
	fam := func(repo string) Family {
		f, _, ok := FamilyOf(repo + ":x")
		if !ok {
			t.Fatalf("no family %s", repo)
		}
		return f
	}
	for _, c := range []struct {
		image string
		want  knowledge.Status
	}{
		{"eclipse-temurin:21.0.13_9-jre-alpine", knowledge.Vulnerable},
		{"eclipse-temurin:21.0.13.1_2-jre", knowledge.Fixed},
		{"eclipse-temurin:21-jre", knowledge.Unknown},
		{"eclipse-temurin:21.0.12.1_1-jdk", knowledge.Vulnerable},
		{"eclipse-temurin:17.0.5_8-jre", knowledge.NotAffected},
		{"eclipse-temurin:17-jre", knowledge.Unknown},
		{"eclipse-temurin:11-jre", knowledge.NotAffected},
		{"eclipse-temurin:24-jre", knowledge.Vulnerable},
		{"amazoncorretto:21.0.12-al2023", knowledge.Vulnerable},
		{"amazoncorretto:21.0.13-al2023", knowledge.Unknown},
		{"amazoncorretto:21", knowledge.Unknown},
		{"azul/zulu-openjdk:21.0.12.1-21.52-jre", knowledge.Vulnerable},
		{"bellsoft/liberica-openjre-debian:21.0.13-9", knowledge.Vulnerable},
		{"bellsoft/liberica-openjre-debian:21.0.13", knowledge.Unknown},
		{"openjdk:17.0.2-jdk", knowledge.NotAffected},
		{"openjdk:18.0.2.1", knowledge.Vulnerable},
		{"sapmachine:21.0.13.1", knowledge.Fixed},
		{"docker.io/library/eclipse-temurin:25.0.5_8-jre", knowledge.Vulnerable},
	} {
		repo, tag := repoName(c.image)
		tv, ok := fam(repo).ParseTag(tag)
		if !ok {
			t.Errorf("%s: tag not read", c.image)
			continue
		}
		if got, why := JudgeTag(tv); got != c.want || why == "" {
			t.Errorf("%s: %s (%s), want %s", c.image, got, why, c.want)
		}
	}
	if f, tag, _ := FamilyOf("eclipse-temurin:latest"); f.Repo != "eclipse-temurin" {
		t.Error("family")
	} else if _, ok := f.ParseTag(tag); ok {
		t.Error("latest read as a version")
	}
}

func TestScanTree(t *testing.T) {
	root := tree(t, map[string]string{
		"Dockerfile": "FROM eclipse-temurin:21.0.13_9-jre-alpine AS run\nRUN apk add --no-cache curl\n",
		"svc/Dockerfile": "ARG JAVA=21.0.12.1_1-jdk\nFROM eclipse-temurin:${JAVA} AS build\nENV JAVA_TOOL_OPTIONS=\"-XX:-UseBASE64Intrinsics\"\n" +
			"FROM ubuntu:24.04\nRUN apt-get update && apt-get install -y openjdk-21-jre-headless\nRUN apt-get install -y openjdk-17-jre-headless=17.0.21+9-1~deb12u1\nRUN apk add openjdk24\n",
		"compose.yaml": "services:\n  app:\n    image: amazoncorretto:21.0.12-al2023\n    environment:\n      JAVA_TOOL_OPTIONS: -XX:UseAVX=2\n" +
			"  jira:\n    image: atlassian/jira-software:9.12\n  web:\n    image: nginx:1.27\n  floating:\n    image: eclipse-temurin:21-jre\n  j9:\n    image: ibm-semeru-runtimes:open-21-jre\n",
		"k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  template:\n    spec:\n      containers:\n        - name: a\n          image: sapmachine:21.0.12\n",
		".java-version":   "21.0.5\n",
		".sdkmanrc":       "java=17.0.13-tem\n",
		".tool-versions":  "nodejs 22\njava corretto-21.0.13.1.2\n",
		"mise.toml":       "[tools]\njava = \"temurin-23.0.2\"\n",
		".github/workflows/ci.yml": "jobs:\n  b:\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: corretto\n          java-version: '21.0.5'\n" +
			"      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: ${{ matrix.java }}\n      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '17'\n",
		"build.gradle.kts": "java { toolchain { languageVersion.set(JavaLanguageVersion.of(22)) } }\njib { from { image = \"eclipse-temurin:25.0.5_8-jre\" } }\n",
		"pom.xml":          "<project><build><plugins><plugin><artifactId>maven-enforcer-plugin</artifactId><configuration><rules><requireJavaVersion>\n<version>[17.0.13,)</version>\n</requireJavaVersion></rules></configuration></plugin></plugins></build></project>\n",
		"project.toml":     "[[build.env]]\nname = \"BP_JVM_VERSION\"\nvalue = \"21\"\n",
	})
	res := scan(t, root)
	check := func(file string, line int, rule, status string) Finding {
		t.Helper()
		f, ok := find(res, file, line)
		if !ok {
			t.Errorf("%s:%d: no finding (have %d)", file, line, len(res.Findings))
			for _, x := range res.Findings {
				t.Logf("  %s:%d %s %s %s", x.File, x.Line, x.Rule, x.Status, x.Message)
			}
			return f
		}
		if f.Rule != rule || f.Status != status {
			t.Errorf("%s:%d: %s %s (%s), want %s %s", file, line, f.Rule, f.Status, f.Message, rule, status)
		}
		return f
	}
	if f := check("Dockerfile", 1, RuleImagePin, StatusVulnerable); !f.Fixable || f.Props["fixed_in"] != "21.0.13.1" {
		t.Errorf("Dockerfile pin: %+v", f)
	}
	check("svc/Dockerfile", 2, RuleImagePin, StatusMitigated)
	check("svc/Dockerfile", 5, RulePackage, StatusVulnerable)
	if f := check("svc/Dockerfile", 6, RulePackage, StatusVulnerable); f.Level != "error" {
		t.Errorf("pinned package level %s", f.Level)
	}
	check("svc/Dockerfile", 7, RuleLine, StatusVulnerable)
	check("compose.yaml", 3, RuleImagePin, StatusMitigated)
	if f := check("compose.yaml", 7, RuleNotChecked, StatusUnknown); f.Pull != "atlassian/jira-software:9.12" {
		t.Errorf("jira pull: %+v", f)
	}
	if f := check("compose.yaml", 11, RuleNotChecked, StatusUnknown); f.Pull == "" {
		t.Errorf("floating pull: %+v", f)
	}
	if _, ok := find(res, "compose.yaml", 9); ok {
		t.Error("nginx reported")
	}
	if _, ok := find(res, "compose.yaml", 13); ok {
		t.Error("OpenJ9 image reported")
	}
	check("k8s/deploy.yaml", 10, RuleImagePin, StatusVulnerable)
	check(".java-version", 1, RuleJavaPin, StatusVulnerable)
	check(".sdkmanrc", 1, RuleJavaPin, StatusVulnerable)
	if _, ok := find(res, ".tool-versions", 2); ok {
		t.Error("a fixed Corretto pin reported")
	}
	check("mise.toml", 2, RuleLine, StatusVulnerable)
	if f := check(".github/workflows/ci.yml", 7, RuleJavaPin, StatusVulnerable); !f.Fixable {
		t.Errorf("setup-java corretto not fixable: %+v", f)
	}
	check(".github/workflows/ci.yml", 11, RuleNotChecked, StatusUnknown)
	if _, ok := find(res, ".github/workflows/ci.yml", 15); ok {
		t.Error("a moving setup-java version of a fixed line reported")
	}
	check("build.gradle.kts", 1, RuleLine, StatusVulnerable)
	check("build.gradle.kts", 2, RuleImagePin, StatusVulnerable)
	check("pom.xml", 2, RuleJavaPin, StatusUnknown)
	if _, ok := find(res, "project.toml", 3); ok {
		t.Error("BP_JVM_VERSION 21 reported")
	}
}

func TestPlatforms(t *testing.T) {
	root := tree(t, map[string]string{"Dockerfile": "FROM eclipse-temurin:21.0.13_9-jre\n"})
	res, _ := Scan(context.Background(), root, Options{Platforms: []string{"linux/arm64"}})
	if len(res.Findings) != 0 {
		t.Errorf("arm64-only build reported: %+v", res.Findings)
	}
}

func TestPlanTag(t *testing.T) {
	root := tree(t, map[string]string{
		"Dockerfile": "ARG BASE=eclipse-temurin:21.0.13_9-jre-alpine\nFROM ${BASE}\nCMD [\"java\",\"-jar\",\"/a.jar\"]\n",
	})
	res := scan(t, root)
	f, ok := find(res, "Dockerfile", 2)
	if !ok || !f.Fixable {
		t.Fatalf("finding: %+v", res.Findings)
	}
	verified := ""
	reg := Registry{
		Tags: func(_ context.Context, repo string) ([]string, error) {
			if repo != "eclipse-temurin" {
				t.Errorf("listed %s", repo)
			}
			return []string{"21.0.13_9-jre-alpine", "21.0.13.1_2-jre", "21.0.13.1_2-jre-alpine-3.22", "21.0.13.1_2-jre-alpine", "21.0.13.1_3-jre-alpine", "21.0.14_1-jre-alpine", "25.0.5.1_2-jre-alpine"}, nil
		},
		Verify: func(_ context.Context, cur, target string) (string, error) {
			verified = target
			return "sha256:abc", nil
		},
	}
	ch, err := Plan(context.Background(), root, f, reg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if verified != "eclipse-temurin:21.0.13.1_2-jre-alpine" || ch.Line != 1 || ch.New != "ARG BASE=eclipse-temurin:21.0.13.1_2-jre-alpine" {
		t.Fatalf("plan: %+v (verified %s)", ch, verified)
	}
	if err := Apply(root, ch); err != nil {
		t.Fatal(err)
	}
	if res := scan(t, root); len(res.Findings) != 0 {
		t.Errorf("after the fix: %+v", res.Findings)
	}
	// No fixed tag published: declined with the reason.
	root = tree(t, map[string]string{"Dockerfile": "FROM eclipse-temurin:17.0.21_9-jdk\n"})
	f, _ = find(scan(t, root), "Dockerfile", 1)
	reg.Tags = func(context.Context, string) ([]string, error) { return []string{"17.0.21_9-jdk", "17-jdk"}, nil }
	if _, err := Plan(context.Background(), root, f, reg, Options{}); err == nil || !strings.Contains(err.Error(), "no published tag") {
		t.Errorf("no fixed tag: %v", err)
	}
	// Offline: declined.
	if _, err := Plan(context.Background(), root, f, Registry{}, Options{}); err == nil || !strings.Contains(err.Error(), "registry") {
		t.Errorf("offline: %v", err)
	}
}

func TestPlanSetupJava(t *testing.T) {
	root := tree(t, map[string]string{".github/workflows/ci.yml": "jobs:\n  b:\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: 'corretto'\n          java-version: '21.0.5'\n"})
	res := scan(t, root)
	f, ok := find(res, ".github/workflows/ci.yml", 7)
	if !ok {
		t.Fatalf("%+v", res.Findings)
	}
	ch, err := Plan(context.Background(), root, f, Registry{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if ch.New != "          java-version: '21'" {
		t.Errorf("plan: %+v", ch)
	}
}

func FuzzScanText(f *testing.F) {
	f.Add("Dockerfile", "FROM eclipse-temurin:21.0.13_9-jre\nRUN apt-get install -y openjdk-21-jre=21.0.5+11-1\nENV JAVA_TOOL_OPTIONS=-XX:UseAVX=2\n")
	f.Add(".github/workflows/a.yml", "jobs:\n a:\n  steps:\n   - uses: actions/setup-java@v4\n     with:\n      java-version: |\n        17\n        21.0.5\n")
	f.Add("pom.xml", "<requireJavaVersion><version>[17.0.1,)</version></requireJavaVersion><from><image>eclipse-temurin:21.0.1_12-jre</image></from>")
	f.Add(".tool-versions", "java corretto-21.0.5.11.1\n")
	f.Add("compose.yaml", "services:\n a:\n  image: amazoncorretto:21.0.1\n  environment: [\"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\"]\n")
	f.Fuzz(func(t *testing.T, name, text string) {
		if strings.ContainsAny(name, "/\\\x00") || name == "" || name == "." || name == ".." || len(text) > 1<<16 {
			return
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0o644); err != nil {
			return
		}
		res, err := Scan(context.Background(), root, Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range res.Findings {
			if x.Message == "" || x.Status == "" {
				t.Fatalf("finding without message or status: %+v", x)
			}
		}
	})
}
