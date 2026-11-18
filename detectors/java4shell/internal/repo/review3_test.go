package repo

import "testing"

type want struct {
	file   string
	line   int
	rule   string
	status string
}

func checkAll(t *testing.T, res Result, ws []want) {
	t.Helper()
	for _, w := range ws {
		f, ok := find(res, w.file, w.line)
		if !ok || f.Rule != w.rule || f.Status != w.status {
			t.Errorf("%s:%d: got %s %s (%s) found %v, want %s %s", w.file, w.line, f.Rule, f.Status, f.Message, ok, w.rule, w.status)
		}
	}
}

// Review finding 8: installs written with flags first, partial versions and
// vendor packages.
func TestReviewPackages(t *testing.T) {
	root := tree(t, map[string]string{
		"a/Dockerfile": "FROM rockylinux:9\nRUN yum -y install java-17-openjdk-headless\nRUN dnf -y install java-21-openjdk\nRUN microdnf -y install java-21-openjdk-headless\n",
		"b/Dockerfile": "FROM debian:12\nRUN apt-get -y install openjdk-17-jre-headless\nRUN apt-get install -y openjdk-17-jdk=17.*\nRUN apt-get install -y default-jre-headless\nRUN apt-get install -y temurin-21-jdk\n",
		"c/Dockerfile": "FROM alpine:3.23\nRUN apk --no-cache add openjdk21\nRUN apk -U add openjdk21-jre\nRUN apk add openjdk17~17\n",
	})
	checkAll(t, scan(t, root), []want{
		{"a/Dockerfile", 2, RulePackage, StatusVulnerable}, {"a/Dockerfile", 3, RulePackage, StatusVulnerable}, {"a/Dockerfile", 4, RulePackage, StatusVulnerable},
		{"b/Dockerfile", 2, RulePackage, StatusVulnerable}, {"b/Dockerfile", 3, RulePackage, StatusVulnerable}, {"b/Dockerfile", 4, RulePackage, StatusVulnerable},
		{"b/Dockerfile", 5, RulePackage, StatusVulnerable},
		{"c/Dockerfile", 2, RulePackage, StatusVulnerable}, {"c/Dockerfile", 3, RulePackage, StatusVulnerable}, {"c/Dockerfile", 4, RulePackage, StatusVulnerable},
	})
}

// Review findings 11 and 12.
func TestReviewVersionNames(t *testing.T) {
	root := tree(t, map[string]string{
		"a/.java-version":  "temurin64-21.0.13\n",
		"b/.java-version":  "openjdk64-17.0.21\n",
		"c/.sdkmanrc":      "java=22.3.r17-nik\n",
		"d/.sdkmanrc":      "java=22.3.r17-grl\n",
		"e/.tool-versions": "java zulu-21.50.19\n",
		".github/workflows/a.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: temurin\n          java-version: '21'\n" +
			"      - uses: actions/setup-java@v4\n        with:\n          distribution: corretto\n          java-version: '21'\n",
		"f/Dockerfile": "FROM amazonlinux:2023\nRUN dnf install -y java-21-amazon-corretto-headless\nRUN dnf install -y java-28-openjdk\n",
		"g/Dockerfile": "FROM --platform=linux/arm64 eclipse-temurin:21.0.13_9-jre\n",
	})
	res := scan(t, root)
	checkAll(t, res, []want{
		{"a/.java-version", 1, RuleJavaPin, StatusVulnerable},
		{"b/.java-version", 1, RuleJavaPin, StatusVulnerable},
		{"c/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"d/.sdkmanrc", 1, RuleNotChecked, StatusUnknown},
		{"e/.tool-versions", 1, RuleNotChecked, StatusUnknown},
		{".github/workflows/a.yml", 7, RuleJavaPin, StatusVulnerable},
		{"f/Dockerfile", 2, RulePackage, StatusUnknown},
		{"f/Dockerfile", 3, RuleNotChecked, StatusUnknown},
	})
	if f, ok := find(res, ".github/workflows/a.yml", 11); ok {
		t.Errorf("setup-java corretto 21 reported: %+v", f)
	}
	if f, ok := find(res, "g/Dockerfile", 1); ok {
		t.Errorf("an arm64 stage reported: %+v", f)
	}
}
