package repo

import (
	"testing"
)

// Regressions from the independent review.
func TestReviewRepo(t *testing.T) {
	root := tree(t, map[string]string{
		"a/Dockerfile":     "FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nENV _JAVA_OPTIONS=-XX:+UseBASE64Intrinsics\n",
		"b/Dockerfile":     "FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nENV JAVA_TOOL_OPTIONS=-Xmx1g\n",
		"c/Dockerfile":     "FROM amazonlinux:2023\nRUN dnf install -y java-21-amazon-corretto-headless-1:21.0.13.11-1\n",
		"d/Dockerfile":     "FROM amazoncorretto:21.0.13.11\n",
		"e/.tool-versions": "java corretto-21.0.13.11\n",
		"f/.java-version":  "corretto-21.0.13.11.1\n",
		"g/.tool-versions": "java corretto-21.0.13.1.2\n",
	})
	res := scan(t, root)
	for _, c := range []struct {
		file   string
		line   int
		rule   string
		status string
	}{
		{"a/Dockerfile", 1, RuleImagePin, StatusVulnerable},
		{"b/Dockerfile", 1, RuleImagePin, StatusVulnerable},
		{"c/Dockerfile", 2, RulePackage, StatusVulnerable},
		{"d/Dockerfile", 1, RuleImagePin, StatusVulnerable},
		{"e/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"f/.java-version", 1, RuleJavaPin, StatusVulnerable},
	} {
		f, ok := find(res, c.file, c.line)
		if !ok || f.Rule != c.rule || f.Status != c.status {
			t.Errorf("%s:%d: %+v (found %v), want %s %s", c.file, c.line, f, ok, c.rule, c.status)
		}
	}
	if f, ok := find(res, "g/.tool-versions", 1); ok {
		t.Errorf("fixed Corretto reported: %+v", f)
	}
	if CorrettoJava("21.0.5.11.1") != "21.0.5" || CorrettoJava("21.0.13.1.2") != "21.0.13.1.2" || CorrettoJava("21.0.13.0.11") != "21.0.13.0.11" {
		t.Error("CorrettoJava")
	}

	// setup-java early access is not judged or rewritten.
	root = tree(t, map[string]string{".github/workflows/a.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: corretto\n          java-version: '21.0.13-ea'\n"})
	if res := scan(t, root); len(res.Findings) != 0 {
		t.Errorf("early access: %+v", res.Findings)
	}

	// The first fixed build sorts numerically.
	e := &pinEdit{family: Families[0], feature: 21}
	e.tv, _ = Families[0].ParseTag("21.0.13_9-jre")
	if got, _ := target([]string{"21.0.13.1_10-jre", "21.0.13.1_2-jre"}, e); got != "21.0.13.1_2-jre" {
		t.Errorf("target %s", got)
	}

	// Corretto: the moving tag of the fixed update is a candidate (the
	// image is read before any edit), after tags that name the fix.
	c := &pinEdit{feature: 21}
	c.family, _, _ = FamilyOf("amazoncorretto:x")
	c.tv, _ = c.family.ParseTag("21.0.12-al2023")
	if got, _ := target([]string{"21.0.12-al2023", "21.0.13-al2023", "21.0.13-alpine", "21-al2023", "21.0.14-al2023"}, c); got != "21.0.13-al2023" {
		t.Errorf("corretto target %q", got)
	}
	if got, _ := target([]string{"21.0.13-al2023", "21.0.13.1-al2023"}, c); got != "21.0.13.1-al2023" {
		t.Errorf("corretto target prefers the named fix: %q", got)
	}
}

// Review finding 2: fix never picks a build below the fixed build.
func TestTargetBelowFixedBuild(t *testing.T) {
	e := &pinEdit{family: Families[0], feature: 21}
	e.tv, _ = Families[0].ParseTag("21.0.13_9-jre")
	if got, ok := target([]string{"21.0.13.1_1-jre"}, e); ok {
		t.Errorf("picked %s, a build without the fix", got)
	}
	if got, _ := target([]string{"21.0.13.1_1-jre", "21.0.13.1_2-jre"}, e); got != "21.0.13.1_2-jre" {
		t.Errorf("picked %s", got)
	}
	tv, _ := Families[0].ParseTag("21.0.13.1_1-jre")
	if st, why := JudgeTag(tv); st != "vulnerable" {
		t.Errorf("21.0.13.1_1: %s (%s)", st, why)
	}
}

// Review finding 9: a command in the tree that turns the intrinsic back on
// voids the mitigation the stage or service sets.
func TestTreeCommandReenables(t *testing.T) {
	root := tree(t, map[string]string{
		"a/Dockerfile": "FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nENTRYPOINT [\"java\",\"-XX:+UseBASE64Intrinsics\",\"-jar\",\"/a.jar\"]\n",
		"b/Dockerfile": "FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:UseAVX=2\nCMD java -XX:UseAVX=3 -jar /a.jar\n",
		"compose.yaml": "services:\n  a:\n    image: amazoncorretto:21.0.12-al2023\n    environment:\n      JAVA_TOOL_OPTIONS: -XX:-UseBASE64Intrinsics\n    command: [\"java\", \"-XX:+UseBASE64Intrinsics\", \"-jar\", \"/a.jar\"]\n",
		"k8s.yaml":     "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\nspec:\n  containers:\n    - name: a\n      image: amazoncorretto:21.0.12-al2023\n      env:\n        - name: JAVA_TOOL_OPTIONS\n          value: -XX:-UseBASE64Intrinsics\n      args: [\"-XX:+UseBASE64Intrinsics\"]\n",
	})
	res := scan(t, root)
	for _, c := range []struct {
		file string
		line int
	}{{"a/Dockerfile", 1}, {"b/Dockerfile", 1}, {"compose.yaml", 3}, {"k8s.yaml", 8}} {
		f, ok := find(res, c.file, c.line)
		if !ok || f.Status != StatusVulnerable || f.Props["mitigation"] != "" {
			t.Errorf("%s:%d: %+v (found %v)", c.file, c.line, f, ok)
		}
	}
}
