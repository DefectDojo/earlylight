package repo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// got lists a scan's findings as "file:line rule status" and its skips as
// "skip file:line".
func got(t *testing.T, dir string) []string {
	t.Helper()
	res, err := Scan(context.Background(), dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range res.Findings {
		out = append(out, fmt.Sprintf("%s:%d %s %s", f.File, f.Line, f.Rule, f.Status))
	}
	for _, s := range res.Skips {
		out = append(out, fmt.Sprintf("skip %s:%d", s.File, s.Line))
	}
	return out
}

// Final review B6: a RUN that installs an OpenJDK package is read the way
// the builder reads it, whatever its form; an install whose package names
// this file does not give is a gap, not silence.
func TestRunForms(t *testing.T) {
	const vuln = "Dockerfile:2 os-package vulnerable"
	for name, c := range map[string]struct{ df, want string }{
		"plain":                       {"FROM debian:12\nRUN apt-get install -y openjdk-17-jdk\n", vuln},
		"a comment in a continuation": {"FROM debian:12\nRUN apt-get update && \\\n    # install java\n    apt-get install -y openjdk-17-jdk\n", vuln},
		"a comment between packages":  {"FROM debian:12\nRUN apt-get install -y curl \\\n    # java\n    openjdk-17-jdk \\\n    git\n", vuln},
		"a blank line":                {"FROM debian:12\nRUN apt-get update && \\\n\n    apt-get install -y openjdk-17-jdk\n", vuln},
		"a tab after RUN":             {"FROM debian:12\nRUN\tapt-get install -y openjdk-17-jdk\n", vuln},
		"exec form":                   {"FROM debian:12\nRUN [\"apt-get\", \"install\", \"-y\", \"openjdk-17-jdk\"]\n", vuln},
		"exec form of a shell":        {"FROM debian:12\nRUN [\"/bin/sh\", \"-c\", \"apt-get update && apt-get install -y openjdk-17-jdk\"]\n", vuln},
		"a heredoc":                   {"FROM debian:12\nRUN <<EOF\napt-get update\n# java\napt-get install -y \\\n  openjdk-17-jdk\nEOF\n", vuln},
		"ONBUILD":                     {"FROM debian:12\nONBUILD RUN apt-get install -y openjdk-17-jdk\n", vuln},
		"backtick escape":             {"# escape=`\nRUN apt-get update `\n && apt-get install -y openjdk-17-jdk\n", "Dockerfile:2 os-package vulnerable"},
		"a subshell":                  {"FROM debian:12\nRUN (apt-get install -y openjdk-17-jdk)\n", vuln},
		"a group":                     {"FROM debian:12\nRUN { apt-get update; apt-get install -y openjdk-17-jdk; }\n", vuln},
		"bash -c":                     {"FROM debian:12\nRUN bash -c \"apt-get install -y openjdk-17-jdk\"\n", vuln},
		"sh -ec":                      {"FROM debian:12\nRUN sh -ec 'apt-get update; apt-get install -y openjdk-17-jdk'\n", vuln},
		"a redirect on the name":      {"FROM debian:12\nRUN apt-get install -y openjdk-17-jdk>/dev/null 2>&1\n", vuln},
		"aptitude":                    {"FROM debian:12\nRUN aptitude install -y openjdk-17-jdk\n", vuln},
		"the name in an ARG":          {"FROM debian:12\nARG JDK=openjdk-17-jdk\nRUN apt-get install -y ${JDK}\n", "Dockerfile:3 os-package vulnerable"},
		"the name in an ENV":          {"FROM debian:12\nENV JAVA_PKG=openjdk-17-jdk\nRUN apt-get install -y \"$JAVA_PKG\"\n", "Dockerfile:3 os-package vulnerable"},
		"an ARG default in braces":    {"FROM debian:12\nRUN apt-get install -y ${JDK:-openjdk-17-jdk}\n", vuln},
		"an ARG without a value":      {"FROM debian:12\nARG PKGS\nRUN apt-get install -y $PKGS\n", "skip Dockerfile:3"},
		"a command's output":          {"FROM debian:12\nRUN apt-get install -y $(cat packages.txt)\n", "skip Dockerfile:2"},
		"apk with a range":            {"FROM alpine:3.22\nRUN apk add --no-cache 'openjdk17>17.0.6'\n", vuln},
		// Not an install, and not Java: nothing.
		"another package":           {"FROM debian:12\nRUN apt-get install -y curl ca-certificates\n", ""},
		"a flag from a variable":    {"FROM debian:12\nRUN apt-get install -y $APT_FLAGS curl\n", "skip Dockerfile:2"},
		"a version from a variable": {"FROM debian:12\nRUN apt-get install -y openjdk-17-jdk=${JDK_VERSION}\n", "Dockerfile:2 os-package unknown"},
		"a query":                   {"FROM debian:12\nRUN rpm -q java-17-openjdk\n", ""},
		"an unterminated heredoc":   {"FROM debian:12\nRUN <<EOF\napt-get install -y openjdk-17-jdk\n", "skip Dockerfile:0"},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{"Dockerfile": c.df})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

const zeroDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Final review B6: image references that were cleared or dropped in
// silence.
func TestReferenceForms(t *testing.T) {
	for name, c := range map[string]struct{ df, want string }{
		// A digest decides which image runs: a tag next to it clears nothing.
		"a fixed tag with a digest":   {"FROM eclipse-temurin:21.0.13.1_2-jre@" + zeroDigest + "\n", "Dockerfile:1 not-checked unknown"},
		"a Java 11 tag with a digest": {"FROM eclipse-temurin:11@" + zeroDigest + "\n", "Dockerfile:1 not-checked unknown"},
		"a vulnerable tag with one":   {"FROM eclipse-temurin:21.0.13_9-jre@" + zeroDigest + "\n", "Dockerfile:1 image-pin vulnerable"},
		"a fixed tag":                 {"FROM sapmachine:21.0.13.1\n", ""},
		// --platform, spelled the ways the builder takes for x86-64.
		"linux/x86-64": {"FROM --platform=linux/x86-64 eclipse-temurin:21.0.13_9-jre\n", "Dockerfile:1 image-pin vulnerable"},
		"linux/AMD64":  {"FROM --platform=linux/AMD64 eclipse-temurin:21.0.13_9-jre\n", "Dockerfile:1 image-pin vulnerable"},
		"linux":        {"FROM --platform=linux eclipse-temurin:21.0.13_9-jre\n", "Dockerfile:1 image-pin vulnerable"},
		"linux/arm64":  {"FROM --platform=linux/arm64 eclipse-temurin:21.0.13_9-jre\n", ""},
		// Images a stage copies from or mounts.
		"COPY --from an image":       {"FROM scratch\nCOPY --from=eclipse-temurin:21.0.13_9-jre /opt/java/openjdk /opt/java/openjdk\n", "Dockerfile:2 image-pin vulnerable"},
		"COPY --link --from":         {"FROM debian\nCOPY --link --from=amazoncorretto:21.0.12 /usr/lib/jvm /usr/lib/jvm\n", "Dockerfile:2 image-pin vulnerable"},
		"RUN --mount from an image":  {"FROM debian\nRUN --mount=type=bind,from=eclipse-temurin:21.0.13_9-jre,source=/opt/java,target=/j cp -r /j /opt/java\n", "Dockerfile:2 image-pin vulnerable"},
		"COPY --from a moving tag":   {"FROM debian\nCOPY --from=eclipse-temurin:21-jre /opt/java/openjdk /opt/java\n", "Dockerfile:2 not-checked unknown"},
		"COPY --from a stage":        {"FROM debian AS build\nFROM debian\nCOPY --from=build /x /x\nCOPY --from=0 /y /y\n", ""},
		"COPY --from another image":  {"FROM debian\nCOPY --from=busybox:1.36 /bin/busybox /bin/busybox\n", ""},
		"an unresolved Java FROM":    {"ARG BASE=eclipse-temurin\nARG VER\nFROM ${BASE}:${VER}\n", "skip Dockerfile:3"},
		"an unresolved FROM, quoted": {"ARG VER\nFROM $IMG:$VER AS b\n", "skip Dockerfile:2"},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{"Dockerfile": c.df})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

// Final review B6: what the walk left out without a record.
func TestWalkLeavesNothingOut(t *testing.T) {
	const run = "FROM debian:12\nRUN apt-get install -y openjdk-17-jdk\n"
	for _, dir := range []string{"build", "build/package", "vendor/docker", "target", "venv", ".gradle"} {
		if g := strings.Join(got(t, tree(t, map[string]string{dir + "/Dockerfile": run})), ", "); g != dir+"/Dockerfile:2 os-package vulnerable" {
			t.Errorf("%s: [%s]", dir, g)
		}
	}
	if g := strings.Join(got(t, tree(t, map[string]string{"target/.java-version": "22\n"})), ", "); g != "target/.java-version:1 java-line vulnerable" {
		t.Errorf("target/.java-version: [%s]", g)
	}
	// A scan root that is a symbolic link is walked at its target.
	real := tree(t, map[string]string{".java-version": "22\n"})
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(got(t, link), ", "); g != ".java-version:1 java-line vulnerable" {
		t.Errorf("a linked root: [%s]", g)
	}
	// A version file that is a symbolic link is not followed, and says so.
	dir := tree(t, map[string]string{"out/java-version": "22\n", "app/keep": ""})
	if err := os.Symlink("../out/java-version", filepath.Join(dir, "app/.java-version")); err != nil {
		t.Fatal(err)
	}
	if g := strings.Join(got(t, dir), ", "); g != "skip app/.java-version:0" {
		t.Errorf("a linked version file: [%s]", g)
	}
}

// Final review B6: rpm names that install whichever OpenJDK provides them,
// and a version range written in one quoted word.
func TestRpmVirtualNames(t *testing.T) {
	for name, c := range map[string]struct{ run, want string }{
		"java-17":            {"yum install -y java-17", "Dockerfile:2 os-package unknown"},
		"java and devel":     {"yum install -y java java-devel", "Dockerfile:2 os-package unknown, Dockerfile:2 os-package unknown"},
		"jre-21 headless":    {"dnf install -y jre-21-headless java-sdk-25", "Dockerfile:2 os-package unknown, Dockerfile:2 os-package unknown"},
		"Java 8 and 11":      {"dnf install -y java-11 jre-1.8.0", ""},
		"a quoted range":     {"dnf install -y 'java-17-openjdk >= 17.0.21.1'", "Dockerfile:2 os-package vulnerable"},
		"not a Java package": {"dnf install -y javascript-common jreen", ""},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{"Dockerfile": "FROM fedora:43\nRUN " + c.run + "\n"})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}
