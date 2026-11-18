package repo

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
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

func TestRedHatRepo(t *testing.T) {
	files := map[string]string{
		"Dockerfile": strings.Join([]string{
			"FROM registry.access.redhat.com/ubi9/openjdk-17:1.20",
			"FROM registry.access.redhat.com/ubi9/openjdk-17:latest",
			"FROM registry.access.redhat.com/ubi9/openjdk-21-runtime:1.20-2.1729089285",
			"FROM registry.redhat.io/ubi9/openjdk-25",
			"FROM registry.access.redhat.com/ubi8/openjdk-11",
			"FROM registry.access.redhat.com/ubi8/openjdk-8-runtime:1.20",
			"FROM registry.access.redhat.com/ubi9/openjdk-17-runtime@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"FROM registry.access.redhat.com/ubi9/openjdk-22",
			"FROM registry.access.redhat.com/ubi9/openjdk-28",
			"FROM registry.access.redhat.com/ubi9/openjdk-99",
			"FROM registry.access.redhat.com/ubi8/openjdk-1",
			"FROM registry.access.redhat.com/ubi8/openjdk-16",
		}, "\n") + "\n",
		"Dockerfile.pkg": strings.Join([]string{
			"FROM registry.access.redhat.com/ubi9/ubi-minimal",
			"RUN microdnf install -y java-17-openjdk-headless && microdnf clean all",
			"RUN dnf install -y java-21-openjdk-devel",
			"RUN dnf install -y java-17-openjdk-headless-17.0.21.0.9-1.el9",
			"RUN dnf install -y java-17-openjdk-headless-1:17.0.21.1.1-1.el9.x86_64",
			"RUN yum install -y java-11-openjdk-headless",
		}, "\n") + "\n",
	}
	res := scan(t, tree(t, files))
	checkAll(t, res, []want{
		{"Dockerfile", 1, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 2, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 3, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 4, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 7, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 8, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 9, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 10, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 11, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 12, RuleNotChecked, StatusUnknown},
		{"Dockerfile.pkg", 2, RulePackage, StatusVulnerable},
		{"Dockerfile.pkg", 3, RulePackage, StatusVulnerable},
		{"Dockerfile.pkg", 4, RulePackage, StatusVulnerable},
		{"Dockerfile.pkg", 5, RulePackage, StatusVulnerable}, // 17.0.21.1 build 1 predates the fix (build 2)
	})
	for _, l := range []int{5, 6} {
		if f, ok := find(res, "Dockerfile", l); ok {
			t.Errorf("Dockerfile:%d: Java 8 or 11 image reported: %+v", l, f)
		}
	}
	if f, ok := find(res, "Dockerfile.pkg", 6); ok {
		t.Errorf("java-11 package reported: %+v", f)
	}
	for _, f := range res.Findings {
		if !strings.Contains(f.Reason, "Red Hat") {
			t.Errorf("%s:%d: the reason does not give Red Hat's status: %s", f.File, f.Line, f.Reason)
		}
		if f.Rule == RuleNotChecked && f.Pull == "" {
			t.Errorf("%s:%d: a UBI image that has to be read is not pulled", f.File, f.Line)
		}
		if f.Fixable {
			t.Errorf("%s:%d: offers an edit", f.File, f.Line)
		}
	}

	// Once Red Hat lists a fixed build, a moving UBI tag or an unpinned
	// install may get it: only the image can tell.
	saved := knowledge.RedHatFixed
	t.Cleanup(func() { knowledge.RedHatFixed = saved })
	knowledge.RedHatFixed = []knowledge.RedHatFix{{Package: "java-17-openjdk", Dist: "el9", EVR: "1:17.0.21.0.9-2.el9", Advisory: "RHSA-2026:0000"},
		{Package: "java-21-openjdk", Dist: "el9_6", EVR: "1:21.0.13.0.9-2.el9_6", Advisory: "RHSA-2026:0001"}}
	files["Dockerfile.pkg"] += "RUN dnf install -y java-17-openjdk-headless-17.0.21.0.9-2.el9\n" +
		// The row is for 17.0.21+9: a later update's build 1 and an Oracle
		// Linux rebuild are judged by their upstream version.
		"RUN dnf install -y java-17-openjdk-headless-17.0.21.1.1-1.el9\n" +
		"RUN dnf install -y java-17-openjdk-headless-17.0.21.0.9-2.0.1.el9\n"
	res = scan(t, tree(t, files))
	checkAll(t, res, []want{
		{"Dockerfile", 2, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 3, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 4, RuleImagePin, StatusVulnerable}, // no java-25 entry
		{"Dockerfile.pkg", 2, RulePackage, StatusUnknown},
		{"Dockerfile.pkg", 4, RulePackage, StatusVulnerable},
		{"Dockerfile.pkg", 8, RulePackage, StatusVulnerable},
		{"Dockerfile.pkg", 9, RulePackage, StatusVulnerable},
	})
	if f, ok := find(res, "Dockerfile.pkg", 7); ok {
		t.Errorf("the listed fixed build reported: %+v", f)
	}
}

// Vendor status of 2026-11-18: Temurin, Microsoft, Debian, Ubuntu, Alpine
// had no fixed release and Red Hat no fixed build; Azul and Liberica were
// not checked.
func TestVendorStatus(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"Dockerfile":               "FROM ubuntu:24.04\nRUN apt-get install -y msopenjdk-21\nRUN apt-get install -y zulu21-jdk\n",
		".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v5\n        with:\n          distribution: microsoft\n          java-version: '21'\n",
		".java-version":            "21.0.13\n",
	}))
	checkAll(t, res, []want{
		{"Dockerfile", 2, RulePackage, StatusVulnerable},
		{"Dockerfile", 3, RulePackage, StatusUnknown},
		{".github/workflows/ci.yml", 7, RuleJavaPin, StatusVulnerable},
		{".java-version", 1, RuleJavaPin, StatusVulnerable},
	})
	for _, c := range []struct {
		file string
		line int
		text []string
	}{
		{"Dockerfile", 2, []string{"Microsoft", "2026-11-18"}},
		{".github/workflows/ci.yml", 7, []string{"Microsoft", "2026-11-18"}},
		{".java-version", 1, []string{"Temurin, Microsoft, Debian, Ubuntu, Alpine and Red Hat", "Azul and BellSoft Liberica were not checked"}},
	} {
		f, _ := find(res, c.file, c.line)
		for _, s := range c.text {
			if !strings.Contains(f.Reason+" "+f.Fix, s) {
				t.Errorf("%s:%d does not say %q: %s / %s", c.file, c.line, s, f.Reason, f.Fix)
			}
		}
	}
}

// Review F3: GraalVM names the data cannot settle are not checked, never
// silently cleared; GraalVM Community's own release numbers (25.1.3,
// 25.5.5.0.3) are not Java versions.
func TestGraalVMRepoStrict(t *testing.T) {
	root := tree(t, map[string]string{
		"a/.sdkmanrc":      "java=22.3.0.r17-nik\n",
		"b/.sdkmanrc":      "java=22.3.1.r1-grl\n",
		"c/.sdkmanrc":      "java=21.3.20.r8-grl\n",
		"d/.sdkmanrc":      "java=22.3.0.r19-grl\n",
		"e/.sdkmanrc":      "java=25.1.3-graalce\n",
		"f/.sdkmanrc":      "java=22.3.00.r17-grl\n",
		"a/.tool-versions": "java graalvm-22.3.1+java1\n",
		"b/.tool-versions": "java graalvm-21.3.20+java11\n",
		"c/.tool-versions": "java graalvm-22.3.0-dev+java17\n",
		"d/.tool-versions": "java graalvm-22.3.0.0+java17\n",
		"e/.tool-versions": "java mandrel-22.3.0.0-Final+java17\n",
		"f/.tool-versions": "java graalvm-community-25.5.5.0.3\n",
		"Dockerfile":       "FROM ghcr.io/graalvm/jdk-community:25.5.5.0.3\nFROM ghcr.io/graalvm/jdk-community:25.1.3-ol9\n",
	})
	res := scan(t, root)
	checkAll(t, res, []want{
		{"a/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"b/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"c/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"d/.sdkmanrc", 1, RuleLine, StatusVulnerable},
		{"e/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"f/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"a/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"b/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"c/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"d/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"e/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"f/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 1, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 2, RuleNotChecked, StatusUnknown},
	})
	for _, f := range res.Findings {
		if (f.File == "e/.sdkmanrc" || f.File == "f/.tool-versions" || f.File == "Dockerfile") && !strings.Contains(f.Reason, "GraalVM's own") {
			t.Errorf("%s:%d: %s", f.File, f.Line, f.Reason)
		}
	}
}

// Review F6: Microsoft ships no Java 27, so its status for 27 is not known.
func TestMicrosoftLines(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"Dockerfile":               "FROM ubuntu:24.04\nRUN apt-get install -y msopenjdk-27\nRUN apt-get install -y msopenjdk-25\n",
		".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v5\n        with:\n          distribution: microsoft\n          java-version: '27'\n",
	}))
	checkAll(t, res, []want{
		{"Dockerfile", 2, RulePackage, StatusUnknown},
		{"Dockerfile", 3, RulePackage, StatusVulnerable},
		{".github/workflows/ci.yml", 7, RuleNotChecked, StatusUnknown},
	})
}

// Review F7: rpm installs the scan dropped or cleared.
func TestRPMGaps(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"Dockerfile": strings.Join([]string{
			"FROM registry.access.redhat.com/ubi9/ubi",
			"RUN dnf install -y java-latest-openjdk",
			"RUN dnf install -y 'java-17-openjdk-17.0.21*'",
			"RUN rpm -ivh https://example.com/java-17-openjdk-headless-17.0.21.0.9-1.el9.x86_64.rpm",
			"RUN dnf install -y java-17-openjdk-17.0.22.0.7-1.el9",
			"RUN dnf install -y java-17-openjdk-17.0.21.9-1.oe2403",
			"RUN dnf install -y java-17-openjdk-17.0.21.2-1.oe2403",
			"RUN dnf install -y ./java-21-openjdk-headless-21.0.13.0.9-1.el9.x86_64.rpm",
			"RUN apt-get install -y openjdk-21-jre-headless=21.0.14+1-1",
			"RUN rpm -Uvh --nodeps /tmp/java-21-openjdk-headless-21.0.13.1.2-1.el9.x86_64.rpm",
			"RUN rpm -qip /tmp/java-17-openjdk-headless-17.0.21.0.9-1.el9.x86_64.rpm",
		}, "\n") + "\n",
	}))
	checkAll(t, res, []want{
		{"Dockerfile", 2, RulePackage, StatusUnknown},
		{"Dockerfile", 3, RulePackage, StatusUnknown},
		{"Dockerfile", 4, RulePackage, StatusVulnerable},
		{"Dockerfile", 5, RulePackage, StatusUnknown},
		{"Dockerfile", 6, RulePackage, StatusUnknown},
		{"Dockerfile", 7, RulePackage, StatusUnknown}, // 17.0.21.2: a fourth number may be a build
		{"Dockerfile", 8, RulePackage, StatusVulnerable},
		{"Dockerfile", 9, RulePackage, StatusUnknown},
	})
	if f, ok := find(res, "Dockerfile", 10); ok {
		t.Errorf("21.0.13.1+2 (fixed upstream) reported: %+v", f)
	}
	if f, ok := find(res, "Dockerfile", 11); ok {
		t.Errorf("an rpm query reported as an install: %+v", f)
	}
}

// Round 2, items 3 and 4: the build after a patch number is carried, so
// build 1 of a fixed release (17.0.21.1.1, 27.0.1.1.3, 17.0.21.1+1) is not
// read as fixed; a six-number rpm version is not settled.
func TestBuildOfFixedRelease(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"Dockerfile": strings.Join([]string{
			"FROM amazoncorretto:17.0.21.1.1",
			"FROM amazoncorretto:27.0.1.1.3",
			"FROM sapmachine:17.0.21.1.1",
			"FROM openjdk:17.0.21.1.1",
			"FROM amazoncorretto:17.0.21.1.2",
			"RUN dnf install -y java-17-amazon-corretto-17.0.21.1.1-1",
			"RUN dnf install -y java-17-openjdk-17.0.21.1.2.3-1.el9",
			"RUN dnf install -y java-17-amazon-corretto-headless-17.0.21+9-1.amzn2023.1",
		}, "\n") + "\n",
		"a/.tool-versions": "java corretto-17.0.21.1.1\n",
		"a/.sdkmanrc":      "java=17.0.21.1.1-amzn\n",
		".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n" +
			"      - uses: actions/setup-java@v5\n        with:\n          distribution: temurin\n          java-version: 17.0.21.1+1\n" +
			"      - uses: actions/setup-java@v5\n        with:\n          distribution: corretto\n          java-version: 17.0.21.1+1\n" +
			"      - uses: actions/setup-java@v5\n        with:\n          distribution: temurin\n          java-version: 17.0.21.1+2\n",
	}))
	checkAll(t, res, []want{
		{"Dockerfile", 1, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 2, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 3, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 4, RuleImagePin, StatusVulnerable},
		{"Dockerfile", 6, RulePackage, StatusVulnerable},
		{"Dockerfile", 7, RulePackage, StatusUnknown},
		{"Dockerfile", 8, RulePackage, StatusVulnerable},
		{"a/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"a/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{".github/workflows/ci.yml", 7, RuleJavaPin, StatusVulnerable},
		{".github/workflows/ci.yml", 11, RuleJavaPin, StatusVulnerable},
	})
	for _, l := range []struct {
		file string
		line int
	}{{"Dockerfile", 5}, {".github/workflows/ci.yml", 15}} {
		if f, ok := find(res, l.file, l.line); ok {
			t.Errorf("%s:%d, a fixed build, reported: %+v", l.file, l.line, f)
		}
	}
}

// Round 2, item 2: rpm and dnf forms that gave nothing.
func TestRPMForms(t *testing.T) {
	const f17 = "java-17-openjdk-headless-17.0.21.0.9-1.el9.x86_64"
	lines := []string{
		"FROM registry.access.redhat.com/ubi9/ubi",
		"RUN dnf install -y https://example.com/" + f17 + ".rpm?raw=true",   // 2
		"RUN dnf install -y https://example.com/" + f17 + ".rpm#sha256=abc", // 3
		"RUN dnf install -y /tmp/" + f17 + ".RPM",                           // 4
		"RUN rpm --root /mnt -i /tmp/" + f17 + ".rpm",                       // 5
		"RUN rpm -ivh *.rpm",              // 6
		"RUN rpm -ivh /tmp/java-17-*.rpm", // 7
		"RUN rpm -ivh 'https://example.com/download?file=" + f17 + ".rpm'",              // 8
		"RUN dnf localinstall -y /tmp/" + f17 + ".rpm",                                  // 9
		"RUN yum localinstall -y /tmp/" + f17 + ".rpm",                                  // 10
		"RUN dnf5 install -y java-17-openjdk-headless",                                  // 11
		"RUN dnf reinstall -y java-21-openjdk-headless",                                 // 12
		"RUN zypper in -y java-17-openjdk=17.0.21.0",                                    // 13
		"RUN apt-get install -y openjdk-21-jre-headless=21.0.13.1~2ea-1",                // 14
		"RUN dnf install -y java-21-openjdk-headless-21.0.13.1.2~ea-1.el9",              // 15
		"RUN dnf --installroot /mnt --releasever 9 install -y java-17-openjdk-headless", // 16
		"RUN rpm -ivh /tmp/epel-release-*.rpm",                                          // 17
		"RUN dnf install -y https://example.com/epel-release-latest-9.noarch.rpm",       // 18
	}
	res := scan(t, tree(t, map[string]string{"Dockerfile": strings.Join(lines, "\n") + "\n"}))
	checkAll(t, res, []want{
		{"Dockerfile", 2, RulePackage, StatusVulnerable},
		{"Dockerfile", 3, RulePackage, StatusVulnerable},
		{"Dockerfile", 4, RulePackage, StatusVulnerable},
		{"Dockerfile", 5, RulePackage, StatusVulnerable},
		{"Dockerfile", 6, RulePackage, StatusUnknown},
		{"Dockerfile", 7, RulePackage, StatusUnknown},
		{"Dockerfile", 8, RulePackage, StatusUnknown},
		{"Dockerfile", 9, RulePackage, StatusVulnerable},
		{"Dockerfile", 10, RulePackage, StatusVulnerable},
		{"Dockerfile", 11, RulePackage, StatusVulnerable},
		{"Dockerfile", 12, RulePackage, StatusVulnerable},
		{"Dockerfile", 13, RulePackage, StatusVulnerable},
		{"Dockerfile", 14, RulePackage, StatusUnknown},
		{"Dockerfile", 15, RulePackage, StatusUnknown},
		{"Dockerfile", 16, RulePackage, StatusVulnerable},
	})
	for _, l := range []int{17, 18} {
		if f, ok := find(res, "Dockerfile", l); ok {
			t.Errorf("Dockerfile:%d, not Java, reported: %+v", l, f)
		}
	}
}

// Round 2, items 5 and 7: GraalVM names the data cannot settle.
func TestGraalVMRound2Repo(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"a/.sdkmanrc":      "java=99.9.9.r11-grl\n",
		"b/.sdkmanrc":      "java=21.30.0.r11-grl\n",
		"c/.sdkmanrc":      "java=22.3.0.r17-graalce\n",
		"d/.sdkmanrc":      "java=22.3.0.r017-grl\n",
		"a/.tool-versions": "java graalvm-22.3.0+java17.0.9\n",
		"b/.tool-versions": "java graalvm-22.3.0+java11+java17\n",
		"c/.tool-versions": "java mandrel-22.3.1.0-Final+java11\n",
	}))
	checkAll(t, res, []want{
		{"a/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"b/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"c/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"d/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"a/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"b/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"c/.tool-versions", 1, RuleNotChecked, StatusUnknown},
	})
}

// Round 2, item 6: a number whose second field is not 0 is not a Java
// version wherever it appears (GraalVM Community's 25.5.5.0.3).
func TestNotJavaNumbers(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		".java-version":            "25.5.5.0.3\n",
		"a/.tool-versions":         "java 25.5.5.0.3\n",
		"b/.tool-versions":         "java openjdk-25.5.5.0.3\n",
		".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v5\n        with:\n          distribution: oracle\n          java-version: 25.1.3\n",
		"Dockerfile":               "FROM eclipse-temurin:25.5.5\n",
	}))
	checkAll(t, res, []want{
		{".java-version", 1, RuleNotChecked, StatusUnknown},
		{"a/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"b/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{".github/workflows/ci.yml", 7, RuleNotChecked, StatusUnknown},
		{"Dockerfile", 1, RuleNotChecked, StatusUnknown},
	})
	for _, f := range res.Findings {
		if !strings.Contains(f.Reason, "not a Java version") {
			t.Errorf("%s:%d: %s", f.File, f.Line, f.Reason)
		}
	}
}

// Round 2, item 8: asdf's musl, jre and lite names are read; version-file
// pins the data does not settle are not checked, as image tags are.
func TestVersionNamesAndUnsettled(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"a/.tool-versions":         "java temurin-musl-21.0.5+11.0.LTS\n",
		"b/.tool-versions":         "java temurin-jre-musl-21.0.5+11.0.LTS\n",
		"c/.tool-versions":         "java corretto-musl-21.0.5.11.1\n",
		"d/.tool-versions":         "java liberica-lite-21.0.5+11\n",
		"e/.tool-versions":         "java sapmachine-musl-21.0.5\n",
		"f/.tool-versions":         "java temurin-17.0.22+7\n",
		"a/.sdkmanrc":              "java=17.0.22-tem\n",
		".github/workflows/ci.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v5\n        with:\n          distribution: zulu\n          java-version: 17.0.22\n",
	}))
	checkAll(t, res, []want{
		{"a/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"b/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"c/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"d/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"e/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"f/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"a/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{".github/workflows/ci.yml", 7, RuleNotChecked, StatusUnknown},
	})
}

// Round 3, item 1: Dragonwell's six-number releases are vulnerable.
func TestDragonwell(t *testing.T) {
	res := scan(t, tree(t, map[string]string{
		"a/.tool-versions": "java dragonwell-21.0.8.0.8.9\n",
		"b/.tool-versions": "java dragonwell-17.0.6.0.6.9\n",
		"c/.tool-versions": "java dragonwell-25.0.5.0.5.8\n",
		"mise.toml":        "[tools]\njava = \"dragonwell-21.0.8.0.8.9\"\n",
		"a/.sdkmanrc":      "java=17.0.21.0.3.b1-kona\n",
		"Dockerfile":       "FROM registry.access.redhat.com/ubi9/ubi\nRUN dnf install -y java-17-openjdk-17.0.9.0.9.1-2.el9\n",
	}))
	checkAll(t, res, []want{
		{"a/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"b/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"c/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"mise.toml", 2, RuleJavaPin, StatusVulnerable},
		{"a/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{"Dockerfile", 2, RulePackage, StatusVulnerable},
	})
}

// Round 3, items 2 and 3: the build after + in asdf, mise and .java-version
// names, and Corretto's build in the rpm or deb release, are carried.
func TestBuildsCarried(t *testing.T) {
	saved := knowledge.GraalVMFixed
	t.Cleanup(func() { knowledge.GraalVMFixed = saved })
	knowledge.GraalVMFixed = map[knowledge.GraalVMKey]knowledge.Build{{Dist: knowledge.GraalVMCommunity, Feature: 17}: {Version: []int{17, 0, 21, 1}, Build: 2}}
	res := scan(t, tree(t, map[string]string{
		"a/.tool-versions": "java temurin-17.0.21.1+1\n",
		"b/.tool-versions": "java liberica-17.0.21.1+1\n",
		"c/.tool-versions": "java liberica-27.0.1.1+3\n",
		"d/.tool-versions": "java graalvm-community-17.0.21.1+1\n",
		"e/.tool-versions": "java temurin-17.0.21.1+2\n",
		"mise.toml":        "[tools]\njava = \"temurin-17.0.21.1+1\"\n",
		".java-version":    "temurin64-17.0.21.1+1\n",
		"Dockerfile": strings.Join([]string{
			"FROM amazonlinux:2023",
			"RUN yum install -y java-17-amazon-corretto-devel-17.0.21.1-1",
			"RUN rpm -i /tmp/java-17-amazon-corretto-devel-17.0.21.1-1.x86_64.rpm",
			"RUN dnf install -y java-27-amazon-corretto-devel-27.0.1.1-3",
			"RUN dnf install -y java-17-amazon-corretto-devel-17.0.21.1-2",
		}, "\n") + "\n",
		"d/Dockerfile": "FROM ubuntu:24.04\nRUN apt-get install -y java-17-amazon-corretto-jdk=1:17.0.21.1-1\n",
	}))
	checkAll(t, res, []want{
		{"a/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"b/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"c/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"d/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"mise.toml", 2, RuleJavaPin, StatusVulnerable},
		{".java-version", 1, RuleJavaPin, StatusVulnerable},
		{"Dockerfile", 2, RulePackage, StatusVulnerable},
		{"Dockerfile", 3, RulePackage, StatusVulnerable},
		{"Dockerfile", 4, RulePackage, StatusVulnerable},
		{"d/Dockerfile", 2, RulePackage, StatusVulnerable},
	})
	for _, w := range []struct {
		file string
		line int
	}{{"e/.tool-versions", 1}, {"Dockerfile", 5}} {
		if f, ok := find(res, w.file, w.line); ok {
			t.Errorf("%s:%d, a fixed build, reported: %+v", w.file, w.line, f)
		}
	}
}

// Round 3, item 4: Java package files and patterns no reader knows are not
// checked; vendor file names carry the Java version.
func TestVendorPackageFiles(t *testing.T) {
	lines := []string{
		"FROM registry.access.redhat.com/ubi9/ubi",
		"RUN rpm -ivh /tmp/jdk-17.0.9_linux-x64_bin.rpm",                                 // 2 Oracle
		"RUN rpm -ivh /tmp/zulu17.46.19-ca-jdk17.0.9-linux.x86_64.rpm",                   // 3
		"RUN rpm -ivh /tmp/temurin-17-jdk-17.0.13.0.0.11-2.x86_64.rpm",                   // 4
		"RUN dnf install -y temurin-17-jdk-17.0.13.0.0.11-2",                             // 5
		"RUN rpm -ivh /tmp/bellsoft-jdk17.0.9+11-linux-amd64.rpm",                        // 6
		"RUN rpm -ivh /tmp/sapmachine-jdk-17.0.9-1.x86_64.rpm",                           // 7
		"RUN rpm -ivh /tmp/jdk.rpm",                                                      // 8
		"RUN rpm -ivh /tmp/jdk*.rpm",                                                     // 9
		"RUN rpm -ivh /tmp/zulu*.rpm",                                                    // 10
		"RUN rpm -ivh /tmp/temurin-*.rpm",                                                // 11
		"RUN rpm -ivh /rpms/*",                                                           // 12
		"RUN dnf install -y java-17-openjdk-17.0.2?.0.9-1.el9",                           // 13
		"RUN rpm --reinstall /tmp/java-17-openjdk-headless-17.0.21.0.9-1.el9.x86_64.rpm", // 14
		"RUN rpm -ivh /tmp/jdk-21.0.13.1_linux-x64_bin.rpm",                              // 15 not cleared
		"RUN rpm -ivh /tmp/epel-release-latest-9.noarch.rpm /tmp/nginx-*.rpm",            // 16
	}
	res := scan(t, tree(t, map[string]string{"Dockerfile": strings.Join(lines, "\n") + "\n"}))
	checkAll(t, res, []want{
		{"Dockerfile", 2, RulePackage, StatusVulnerable},
		{"Dockerfile", 3, RulePackage, StatusVulnerable},
		{"Dockerfile", 4, RulePackage, StatusVulnerable},
		{"Dockerfile", 5, RulePackage, StatusVulnerable},
		{"Dockerfile", 6, RulePackage, StatusVulnerable},
		{"Dockerfile", 7, RulePackage, StatusVulnerable},
		{"Dockerfile", 8, RulePackage, StatusUnknown},
		{"Dockerfile", 9, RulePackage, StatusUnknown},
		{"Dockerfile", 10, RulePackage, StatusUnknown},
		{"Dockerfile", 11, RulePackage, StatusUnknown},
		{"Dockerfile", 12, RulePackage, StatusUnknown},
		{"Dockerfile", 13, RulePackage, StatusUnknown},
		{"Dockerfile", 14, RulePackage, StatusVulnerable},
		{"Dockerfile", 15, RulePackage, StatusUnknown},
	})
	if f, ok := find(res, "Dockerfile", 16); ok {
		t.Errorf("non-Java files reported: %+v", f)
	}
}

// Round 3, item 5: javafx and crac names, GA and EA names without an
// update, Corretto's apk packages, Zulu's own numbers for a line without a
// fix, and JetBrains Runtime versions.
func TestRound3Names(t *testing.T) {
	files := map[string]string{
		"Dockerfile": "FROM alpine:3.23\nRUN apk add amazon-corretto-17=17.0.20.13.1-r0\nRUN apk add amazon-corretto-22\n",
	}
	add := func(name, value string) { files[name+"/.tool-versions"] = "java " + value + "\n" }
	add("a", "liberica-javafx-17.0.9+11")
	add("b", "liberica-crac-17.0.9+16")
	add("c", "zulu-crac-22.32.17")
	add("d", "openjdk-21")
	add("e", "sapmachine-21")
	add("f", "liberica-21+37")
	add("g", "openjdk-21-ea+26")
	add("h", "java-se-ri-22+36")
	add("i", "zulu-22.32.15")
	add("j", "jetbrains-17.0.9b1087.7")
	add("k", "openjdk-17")             // 17.0.0: before the decoder
	add("l", "openjdk-17.0.21.1-ea+2") // pre-release of the fixed update
	add("m", "jetbrains-17.0.21b1234.5")
	files["a/.sdkmanrc"] = "java=21-tem\n"
	res := scan(t, tree(t, files))
	checkAll(t, res, []want{
		{"a/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"b/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"c/.tool-versions", 1, RuleLine, StatusVulnerable},
		{"d/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"e/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"f/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"g/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"h/.tool-versions", 1, RuleLine, StatusVulnerable},
		{"i/.tool-versions", 1, RuleLine, StatusVulnerable},
		{"j/.tool-versions", 1, RuleJavaPin, StatusVulnerable},
		{"l/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"m/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{"a/.sdkmanrc", 1, RuleJavaPin, StatusVulnerable},
		{"Dockerfile", 2, RulePackage, StatusVulnerable},
		{"Dockerfile", 3, RuleLine, StatusVulnerable},
	})
	if f, ok := find(res, "k/.tool-versions", 1); ok {
		t.Errorf("openjdk-17 (17.0.0) reported: %+v", f)
	}
}
