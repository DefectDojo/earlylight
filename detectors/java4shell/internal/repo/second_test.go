package repo

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Second final review: a Compose build argument is a literal in the tree,
// so the FROM is judged with it. It is a gap only when the value cannot be
// read and the image could be a Java one, and only for the Dockerfile the
// service builds. Before, any Dockerfile that used an ARG of that name
// was marked not checked: a tree with no Java in it made fix exit 1.
func TestComposeBuildArgsAreJudged(t *testing.T) {
	const fixedDefault = "ARG TAG=21.0.13.1_2-jre\nFROM eclipse-temurin:${TAG}\n"
	compose := func(context, args string) string {
		return "services:\n  app:\n    build:\n      context: " + context + "\n      args:\n" + args
	}
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"no Java: nginx with a literal":                                   {map[string]string{"Dockerfile": "ARG NGINX=1.27\nFROM nginx:${NGINX}\n", "docker-compose.yml": compose(".", "        NGINX: 1.28\n")}, ""},
		"no Java: nginx with a variable":                                  {map[string]string{"Dockerfile": "ARG NGINX=1.27\nFROM nginx:${NGINX}\n", "docker-compose.yml": compose(".", "        NGINX: ${NGINX_VERSION}\n")}, ""},
		"a vulnerable tag over a fixed default":                           {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"the same as a list":                                              {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        - TAG=21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"a fixed tag over a fixed default":                                {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13.1_2-jdk\n")}, ""},
		"the default again":                                               {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13.1_2-jre\n")}, ""},
		"a fixed tag over a vulnerable default: the default still builds": {map[string]string{"Dockerfile": "ARG TAG=21.0.13_9-jre\nFROM eclipse-temurin:${TAG}\n", "docker-compose.yml": compose(".", "        TAG: 21.0.13.1_2-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"a value from the environment":                                    {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: ${JAVA_TAG}\n")}, "skip Dockerfile:2"},
		"a name with no value (taken from the environment)":               {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        - TAG\n")}, "skip Dockerfile:2"},
		"the whole image in the argument":                                 {map[string]string{"Dockerfile": "ARG BASE=debian:12\nFROM ${BASE}\n", "docker-compose.yml": compose(".", "        BASE: eclipse-temurin:21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"the whole image, not Java":                                       {map[string]string{"Dockerfile": "ARG BASE=debian:12\nFROM ${BASE}\n", "docker-compose.yml": compose(".", "        BASE: debian:13\n")}, ""},
		"the whole image from the environment":                            {map[string]string{"Dockerfile": "ARG BASE=debian:12\nFROM ${BASE}\n", "docker-compose.yml": compose(".", "        BASE: ${BASE_IMAGE}\n")}, "skip Dockerfile:2"},
		"two arguments, one set":                                          {map[string]string{"Dockerfile": "ARG REPO=eclipse-temurin\nARG TAG=21.0.13.1_2-jre\nFROM ${REPO}:${TAG}\n", "docker-compose.yml": compose(".", "        TAG: 21.0.13_9-jre\n")}, "skip Dockerfile:3"},
		"another service's Dockerfile is not marked":                      {map[string]string{"Dockerfile": fixedDefault, "svc/Dockerfile": "ARG TAG=3\nFROM alpine:3\n", "docker-compose.yml": compose("./svc", "        TAG: 21.0.13_9-jre\n")}, ""},
		"a Dockerfile named in a sub-directory":                           {map[string]string{"app/Dockerfile.prod": fixedDefault, "docker-compose.yml": "services:\n  a:\n    build:\n      context: ./app\n      dockerfile: Dockerfile.prod\n      args:\n        TAG: 21.0.13_9-jre\n"}, "app/Dockerfile.prod:2 image-pin vulnerable"},
		"a context the tree cannot place":                                 {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose("${APP_DIR}", "        TAG: 21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"a Compose file in a sub-directory":                               {map[string]string{"deploy/Dockerfile": fixedDefault, "deploy/compose.yaml": compose(".", "        TAG: 21.0.13_9-jre\n")}, "deploy/Dockerfile:2 image-pin vulnerable"},
	} {
		if g := strings.Join(got(t, tree(t, c.files)), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
	// The finding names the Compose file and is not one fix edits.
	res := scanTree(t, map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13_9-jre\n")})
	if len(res.Findings) != 1 || res.Findings[0].Fixable || !strings.Contains(res.Findings[0].Reason, "docker-compose.yml") {
		t.Errorf("the finding from a Compose build argument: %+v", res.Findings)
	}
}

// An unresolved reference is a java4shell gap only when it could be a
// Java image: its name says so, or a variable hides the name. A variable
// in the tag of an image that is plainly something else is not.
func TestUnresolvedReferenceThatIsNotJava(t *testing.T) {
	for name, c := range map[string]struct{ df, want string }{
		"a variable tag of another image":               {"FROM registry.example.com/acme/web:${VERSION}\n", ""},
		"a variable tag with a default-less brace form": {"FROM nginx:$NGINX\n", ""},
		"a variable tag of a Java image":                {"FROM eclipse-temurin:${VERSION}\n", "skip Dockerfile:1"},
		"a variable name":                               {"FROM ${BASE}:${VERSION}\n", "skip Dockerfile:1"},
		"a variable registry path":                      {"FROM registry.example.com/${TEAM}/app:1\n", "skip Dockerfile:1"},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{"Dockerfile": c.df})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

func scanTree(t *testing.T, files map[string]string) Result {
	t.Helper()
	res, err := Scan(context.Background(), tree(t, files), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// Second final review: Jib's base image wherever it stands in the from
// block, and never from a comment. A from block whose image this scan
// cannot read is not checked.
func TestJibFromBlock(t *testing.T) {
	const vuln, fixed = "eclipse-temurin:21.0.13_9-jre", "eclipse-temurin:21.0.13.1_2-jre"
	for name, c := range map[string]struct{ file, body, want string }{
		"image first":                     {"build.gradle", "jib {\n  from {\n    image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:3 image-pin vulnerable"},
		"platforms first":                 {"build.gradle", "jib {\n  from {\n    platforms {\n      platform {\n        architecture = \"amd64\"\n        os = \"linux\"\n      }\n    }\n    image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:9 image-pin vulnerable"},
		"auth first":                      {"build.gradle", "jib {\n  from {\n    auth {\n      username = \"u\"\n    }\n    image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:6 image-pin vulnerable"},
		"a commented fixed image first":   {"build.gradle", "jib {\n  from {\n    // image = \"" + fixed + "\"\n    image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:4 image-pin vulnerable"},
		"a block comment first":           {"build.gradle", "jib {\n  from {\n    /* image = \"" + fixed + "\"\n     */\n    image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:5 image-pin vulnerable"},
		"only a commented image":          {"build.gradle", "jib {\n  from {\n    // image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:2 not-checked unknown"},
		"the call form":                   {"build.gradle", "jib {\n  from {\n    image \"" + vuln + "\"\n  }\n}\n", "build.gradle:3 image-pin vulnerable"},
		"Kotlin, with parentheses":        {"build.gradle.kts", "jib {\n  from {\n    image(\"" + vuln + "\")\n  }\n}\n", "build.gradle.kts:3 image-pin vulnerable"},
		"an image from a variable":        {"build.gradle", "jib {\n  from {\n    image = baseImage\n  }\n}\n", "build.gradle:2 not-checked unknown"},
		"platforms only":                  {"build.gradle", "jib {\n  from {\n    platforms {\n      platform {\n        os = \"linux\"\n      }\n    }\n  }\n}\n", "build.gradle:2 not-checked unknown"},
		"the to block's image is not it":  {"build.gradle", "jib {\n  from {\n    image = \"" + fixed + "\"\n  }\n  to {\n    image = \"registry.example.com/app:" + "21.0.13_9-jre\"\n  }\n}\n", ""},
		"a URL in a string is no comment": {"build.gradle", "jib {\n  from {\n    auth { helper = \"https://x\" }\n    image = \"" + vuln + "\"\n  }\n}\n", "build.gradle:4 image-pin vulnerable"},
		"pom, image first":                {"pom.xml", "<configuration>\n<from>\n<image>" + vuln + "</image>\n</from>\n</configuration>\n", "pom.xml:3 image-pin vulnerable"},
		"pom, platforms first":            {"pom.xml", "<configuration>\n<from>\n<platforms><platform><architecture>amd64</architecture><os>linux</os></platform></platforms>\n<image>" + vuln + "</image>\n</from>\n</configuration>\n", "pom.xml:4 image-pin vulnerable"},
		"pom, auth first":                 {"pom.xml", "<configuration>\n<from>\n<auth><username>u</username></auth>\n<image>" + vuln + "</image>\n</from>\n</configuration>\n", "pom.xml:4 image-pin vulnerable"},
		"pom, a commented fixed image":    {"pom.xml", "<configuration>\n<from>\n<!-- <image>" + fixed + "</image> -->\n<image>" + vuln + "</image>\n</from>\n</configuration>\n", "pom.xml:4 image-pin vulnerable"},
		"pom, a property of the file":     {"pom.xml", "<project>\n<properties>\n<base.image>" + vuln + "</base.image>\n</properties>\n<from>\n<image>${base.image}</image>\n</from>\n</project>\n", "pom.xml:6 image-pin vulnerable"},
		"pom, a property from elsewhere":  {"pom.xml", "<project>\n<from>\n<image>${base.image}</image>\n</from>\n</project>\n", "pom.xml:3 not-checked unknown"},
		"pom, a fixed image":              {"pom.xml", "<configuration>\n<from>\n<image>" + fixed + "</image>\n</from>\n</configuration>\n", ""},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{c.file: c.body})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

// BP_JVM_VERSION with a line and no update installs the newest BellSoft
// Liberica release of the line when the image is built: a moving pin,
// whose status FACTS.md gives as not checked. It was passed in silence.
// The closing tag of a pom property is not a second, unread setting, and a
// commented setting is not one.
func TestBuildpackShortVersion(t *testing.T) {
	const notChecked, noFix = "not-checked unknown", "java-line vulnerable"
	for name, c := range map[string]struct{ file, body, want string }{
		"gradle 21":             {"build.gradle", "bootBuildImage {\n  environment = [\"BP_JVM_VERSION\": \"21\"]\n}\n", "build.gradle:2 " + notChecked},
		"gradle 17":             {"build.gradle", "bootBuildImage {\n  environment = [\"BP_JVM_VERSION\": \"17\"]\n}\n", "build.gradle:2 " + notChecked},
		"gradle 21.*":           {"build.gradle", "bootBuildImage {\n  environment = [\"BP_JVM_VERSION\": \"21.*\"]\n}\n", "build.gradle:2 " + notChecked},
		"gradle 21.0":           {"build.gradle", "bootBuildImage {\n  environment = [\"BP_JVM_VERSION\": \"21.0\"]\n}\n", "build.gradle:2 " + notChecked},
		"gradle 11":             {"build.gradle", "bootBuildImage {\n  environment = [\"BP_JVM_VERSION\": \"11\"]\n}\n", ""},
		"gradle 22":             {"build.gradle", "bootBuildImage {\n  environment = [\"BP_JVM_VERSION\": \"22\"]\n}\n", "build.gradle:2 " + noFix},
		"project.toml 21":       {"project.toml", "[[build.env]]\nname = \"BP_JVM_VERSION\"\nvalue = \"21\"\n", "project.toml:2 " + notChecked},
		"pom 21":                {"pom.xml", "<properties><BP_JVM_VERSION>21</BP_JVM_VERSION></properties>\n", "pom.xml:1 " + notChecked},
		"pom 22":                {"pom.xml", "<properties><BP_JVM_VERSION>22</BP_JVM_VERSION></properties>\n", "pom.xml:1 " + noFix},
		"pom 21.0.13":           {"pom.xml", "<properties><BP_JVM_VERSION>21.0.13</BP_JVM_VERSION></properties>\n", "pom.xml:1 java-pin vulnerable"},
		"pom 21.0.13.1":         {"pom.xml", "<properties><BP_JVM_VERSION>21.0.13.1</BP_JVM_VERSION></properties>\n", ""},
		"a commented setting":   {"build.gradle", "bootBuildImage {\n  // environment = [\"BP_JVM_VERSION\": \"21.0.13\"]\n  environment = [\"BP_JVM_VERSION\": \"21.0.13.1\"]\n}\n", ""},
		"a commented fixed pin": {"build.gradle", "bootBuildImage {\n  // environment = [\"BP_JVM_VERSION\": \"21.0.13.1\"]\n  environment = [\"BP_JVM_VERSION\": \"21.0.13\"]\n}\n", "build.gradle:3 java-pin vulnerable"},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{c.file: c.body})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

// FACTS.md, "Version-manager names in vendors' own numbers": Azul Zulu's
// own numbers start with the Java line, and a line that received no fix is
// vulnerable from that number alone. That held for .tool-versions and
// mise; an image tag, a jenv name and setup-java's zulu distribution said
// "not a Java version" (they were vulnerable before the rule that X.Y with
// Y not 0 is no Java version).
func TestZuluOwnNumbers(t *testing.T) {
	const sj = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: %s\n          java-version: %s\n"
	for name, c := range map[string]struct{ file, body, want string }{
		"image tag, 22":               {"Dockerfile", "FROM azul/zulu-openjdk:22.32.15\n", "Dockerfile:1 image-pin vulnerable"},
		"image tag, alpine 20":        {"Dockerfile", "FROM azul/zulu-openjdk-alpine:20.32.11\n", "Dockerfile:1 image-pin vulnerable"},
		"image tag, 21: a fixed line": {"Dockerfile", "FROM azul/zulu-openjdk:21.38.21\n", "Dockerfile:1 not-checked unknown"},
		"image tag of another vendor": {"Dockerfile", "FROM eclipse-temurin:22.32.15\n", "Dockerfile:1 not-checked unknown"},
		"jenv name":                   {".java-version", "zulu64-22.32.15\n", ".java-version:1 java-line vulnerable"},
		"jenv name, a fixed line":     {".java-version", "zulu64-21.38.21\n", ".java-version:1 not-checked unknown"},
		"a bare number":               {".java-version", "22.32.15\n", ".java-version:1 not-checked unknown"},
		"setup-java zulu":             {".github/workflows/ci.yml", fmt.Sprintf(sj, "zulu", "22.32.15"), ".github/workflows/ci.yml:9 java-line vulnerable"},
		"setup-java temurin":          {".github/workflows/ci.yml", fmt.Sprintf(sj, "temurin", "22.32.15"), ".github/workflows/ci.yml:9 not-checked unknown"},
		".tool-versions, as before":   {".tool-versions", "java zulu-22.32.15\n", ".tool-versions:1 java-line vulnerable"},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{c.file: c.body})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}
