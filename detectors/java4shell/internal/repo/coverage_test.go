package repo

import (
	"strings"
	"testing"
)

// The five-part releases the OpenJDK advisory names as the last affected
// (17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3) and the vendor builds
// of them (Microsoft's .0.2, Temurin's 27.0.1.0.2+1) are vulnerable in
// every place a tree can name them.
func TestFivePartRepo(t *testing.T) {
	files := map[string]string{
		"Dockerfile.tags": strings.Join([]string{
			"FROM eclipse-temurin:27.0.1.0.2_1-jre",
			"FROM eclipse-temurin:27.0.1.0-jre",
			"FROM azul/zulu-openjdk:21.0.13.0.3-jre",
			"FROM bellsoft/liberica-openjre-debian:21.0.13.0.3",
			"FROM sapmachine:21.0.13.0.3-jre-ubuntu-noble",
			"FROM mcr.microsoft.com/openjdk/jdk:17.0.21.0.2-ubuntu",
			"FROM container-registry.oracle.com/java/jdk:25.0.5.0.3",
			"FROM container-registry.oracle.com/java/openjdk:27.0.1.0.3",
		}, "\n") + "\n",
		"Dockerfile.pkgs": strings.Join([]string{
			"FROM debian:sid",
			"RUN apt-get install -y openjdk-17-jre-headless=17.0.21.0.3+1-1",
			"RUN apt-get install -y openjdk-25-jre-headless=25.0.5.0.3+1-3",
			"RUN apk add openjdk21-jre-headless=21.0.13.0.3_p1-r0",
			"RUN apk add openjdk25-jre-headless=25.0.5.0.3_p1-r1",
			"RUN dnf install -y java-17-openjdk-headless-17.0.21.0.3-1.el9",
			"RUN apt-get install -y msopenjdk-21=21.0.13.0.2-1",
			"RUN apt-get install -y temurin-27-jdk=27.0.1.0.2+1",
		}, "\n") + "\n",
		".java-version":    "27.0.1.0.2\n",
		"a/.java-version":  "temurin64-27.0.1.0.2\n",
		"b/.java-version":  "oracle64-17.0.21.0.3\n",
		".sdkmanrc":        "java=21.0.13.0.2-ms\n",
		"c/.sdkmanrc":      "java=25.0.5.0.3-oracle\n",
		".tool-versions":   "java temurin-27.0.1.0.2+1\n",
		"d/.tool-versions": "java microsoft-17.0.21.0.2\n",
		"mise.toml":        "[tools]\njava = \"oracle-25.0.5.0.3\"\n",
		".github/workflows/ci.yml": `on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-java@v5
        with:
          distribution: microsoft
          java-version: 21.0.13.0.2
      - uses: actions/setup-java@v5
        with:
          distribution: temurin
          java-version: 27.0.1.0.2+1
`,
	}
	res := scan(t, tree(t, files))
	want := map[string]int{"Dockerfile.tags": 8, "Dockerfile.pkgs": 7, ".java-version": 1, "a/.java-version": 1, "b/.java-version": 1,
		".sdkmanrc": 1, "c/.sdkmanrc": 1, ".tool-versions": 1, "d/.tool-versions": 1, "mise.toml": 1, ".github/workflows/ci.yml": 2}
	got := map[string]int{}
	for _, f := range res.Findings {
		if f.Status != StatusVulnerable {
			t.Errorf("%s:%d %s %s: %s", f.File, f.Line, f.Rule, f.Status, f.Reason)
			continue
		}
		got[f.File]++
	}
	for file, n := range want {
		if got[file] != n {
			t.Errorf("%s: %d vulnerable findings, want %d", file, got[file], n)
		}
	}
	for _, s := range res.Skips {
		t.Logf("skip %+v", s)
	}
}

func TestGraalVMRepo(t *testing.T) {
	root := tree(t, map[string]string{
		"a/.sdkmanrc":      "java=22.3.1.r17-grl\n",
		"b/.sdkmanrc":      "java=22.3.0.r17-grl\n",
		"c/.sdkmanrc":      "java=22.3.r17-grl\n",
		"d/.sdkmanrc":      "java=22.3.1.r19-grl\n",
		"e/.sdkmanrc":      "java=22.3.1.r11-grl\n",
		"f/.sdkmanrc":      "java=21.0.13.1-graal\n",
		"g/.sdkmanrc":      "java=21.0.13-graal\n",
		"h/.sdkmanrc":      "java=21.0.2-graalce\n",
		"i/.sdkmanrc":      "java=23.1.5.r21-mandrel\n",
		"j/.sdkmanrc":      "java=25.0.5.1-graalce\n",
		"a/.tool-versions": "java graalvm-22.3.1+java17\n",
		"b/.tool-versions": "java oracle-graalvm-21.0.13.1\n",
		"c/.tool-versions": "java graalvm-community-17.0.9\n",
		"d/.tool-versions": "java graalvm-22.3.0+java11\n",
		"Dockerfile": strings.Join([]string{
			"FROM container-registry.oracle.com/graalvm/jdk:21.0.13",
			"FROM container-registry.oracle.com/graalvm/jdk:21.0.13.1",
			"FROM container-registry.oracle.com/graalvm/jdk:21",
			"FROM ghcr.io/graalvm/jdk-community:21.0.2",
			"FROM ghcr.io/graalvm/native-image-community:17.0.9-ol9",
			"FROM container-registry.oracle.com/graalvm/native-image:17.0.21.0.3",
			"FROM ghcr.io/graalvm/graalvm-ce:22.3.3",
		}, "\n") + "\n",
	})
	res := scan(t, root)
	checkAll(t, res, []want{
		{"a/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{"c/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"d/.sdkmanrc", 1, RuleLine, StatusVulnerable},
		{"f/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"g/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{"h/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{"i/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{"j/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"a/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"b/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"c/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"Dockerfile", 1, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 2, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 3, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 4, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 5, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 6, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 7, RuleNotChecked, StatusUnknown},
	})
	for _, file := range []string{"b/.sdkmanrc", "e/.sdkmanrc", "d/.tool-versions"} {
		if f, ok := find(res, file, 1); ok {
			t.Errorf("%s: GraalVM for a release without the decoder reported: %+v", file, f)
		}
	}
	for _, f := range res.Findings {
		if f.Status == StatusVulnerable && (!strings.Contains(f.Reason+f.Fix, "GraalVM") || f.Fixable) {
			t.Errorf("%s:%d: a GraalVM finding must name GraalVM and not offer an edit: %+v", f.File, f.Line, f)
		}
		if f.Rule == RuleNotChecked && f.File == "Dockerfile" && f.Pull == "" {
			t.Errorf("Dockerfile:%d: an unknown image is not pulled", f.Line)
		}
	}
}
