package repo

import (
	"runtime"
	"strings"
	"testing"
)

// one scans a tree that holds one Dockerfile.
func one(t *testing.T, df string) string {
	t.Helper()
	return strings.Join(got(t, tree(t, map[string]string{"Dockerfile": df})), ", ")
}

// Second final review, finding 1: a Dockerfile the instruction parser
// refuses keeps its skip record, and its RUN lines are still read line by
// line: a finding is never traded for a gap. Nothing in such a file is
// reported as mitigated.
func TestUnparsedDockerfileIsStillRead(t *testing.T) {
	const skip = ", skip Dockerfile:0"
	for name, c := range map[string]struct{ df, want string }{
		"an unterminated heredoc":         {"FROM debian:12\nRUN apt-get install -y openjdk-17-jdk\nRUN cat <<EOF > /x\nhello\n", "Dockerfile:2 os-package vulnerable" + skip},
		"its body":                        {"FROM debian:12\nRUN <<EOF\napt-get update\napt-get install -y \\\n  openjdk-17-jdk\n", "Dockerfile:2 os-package vulnerable" + skip},
		"an install after it":             {"FROM debian:12\nRUN cat <<EOF > /x\nhello\nRUN apt-get install -y openjdk-17-jdk\n", "Dockerfile:4 os-package vulnerable" + skip},
		"a heredoc on a descriptor":       {"FROM debian:12\nRUN test 1 -lt 2 && cat 3<<EOF && apt-get install -y openjdk-17-jdk\n", "Dockerfile:2 os-package vulnerable" + skip},
		"an old syntax, a shell heredoc":  {"# syntax=docker/dockerfile:1.2\nFROM debian:12\nRUN echo <<EOF; apt-get install -y openjdk-17-jdk\n", "Dockerfile:3 os-package vulnerable" + skip},
		"an escape directive it refuses":  {"# escape=x\nFROM debian:12\nRUN apt-get install -y openjdk-17-jdk\n", "Dockerfile:3 os-package vulnerable" + skip},
		"a directive given twice":         {"# escape=\\\n# escape=\\\nFROM debian:12\nRUN apt-get update && \\\n  # java\n  apt-get install -y openjdk-17-jdk\n", "Dockerfile:4 os-package vulnerable" + skip},
		"a backtick escape":               {"# escape=`\n# escape=`\nFROM debian:12\nRUN apt-get update && `\n  apt-get install -y openjdk-17-jdk\n", "Dockerfile:4 os-package vulnerable" + skip},
		"exec form":                       {"# syntax=a\n# syntax=a\nFROM debian:12\nRUN [\"apt-get\", \"install\", \"-y\", \"openjdk-17-jdk\"]\n", "Dockerfile:4 os-package vulnerable" + skip},
		"ONBUILD RUN":                     {"# syntax=a\n# syntax=a\nFROM debian:12\nonbuild run apt-get install -y openjdk-17-jdk\n", "Dockerfile:4 os-package vulnerable" + skip},
		"its FROM and COPY --from":        {"# syntax=a\n# syntax=a\nFROM eclipse-temurin:21.0.13_9-jre AS base\nCOPY --from=eclipse-temurin:17.0.21_9-jre /opt/java /opt/java17\nCOPY --from=base /x /x\n", "Dockerfile:3 image-pin vulnerable, Dockerfile:4 image-pin vulnerable" + skip},
		"a FROM on another architecture":  {"# syntax=a\n# syntax=a\nFROM --platform=linux/arm64 eclipse-temurin:21.0.13_9-jre\n", "skip Dockerfile:0"},
		"the name in an ARG":              {"# syntax=a\n# syntax=a\nFROM debian:12\nARG JDK=openjdk-17-jdk\nRUN apt-get install -y $JDK\n", "Dockerfile:5 os-package vulnerable" + skip},
		"ENV is no mitigation here":       {"# syntax=a\n# syntax=a\nFROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nRUN apt-get install -y openjdk-17-jdk\n", "Dockerfile:3 image-pin vulnerable, Dockerfile:5 os-package vulnerable" + skip},
		"nothing about Java":              {"FROM debian:12\nRUN apt-get install -y curl\nRUN cat <<EOF > /x\nhello\n", "skip Dockerfile:0"},
		"a file larger than the parser's": {"FROM debian:12\nRUN apt-get install -y openjdk-17-jdk\n" + strings.Repeat("# "+strings.Repeat("x", 78)+"\n", 13200), "Dockerfile:2 os-package vulnerable" + skip},
	} {
		if g := one(t, c.df); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

// Finding 8: the instruction parser keeps the position of every byte, and
// the image reference scan caps it at refs.MaxDockerfileSize. A larger
// Dockerfile is read line by line here, in memory of the file's own order.
func TestLargeDockerfileMemory(t *testing.T) {
	var b strings.Builder
	b.WriteString("FROM debian:12\nRUN apt-get update \\\n")
	for b.Len() < maxFileSize-256 {
		b.WriteString(" && echo 0123456789012345678901234567890123456789012345678901234567890123456789 \\\n")
	}
	b.WriteString(" && apt-get install -y openjdk-17-jdk\n")
	dir := tree(t, map[string]string{"Dockerfile": b.String()})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	g := strings.Join(got(t, dir), ", ")
	runtime.ReadMemStats(&after)
	if want := "Dockerfile:2 os-package vulnerable, skip Dockerfile:0"; g != want {
		t.Errorf("[%s], want [%s]", g, want)
	}
	if mb := (after.TotalAlloc - before.TotalAlloc) >> 20; mb > 160 && !raceDetector {
		t.Errorf("scanning a %d MiB Dockerfile allocated %d MiB", b.Len()>>20, mb)
	}
}

// Finding 3: a RUN whose install is the text of a shell's -c, whatever
// stands before the shell or between it and -c.
func TestRunShellTexts(t *testing.T) {
	const vuln = "Dockerfile:2 os-package vulnerable"
	for name, c := range map[string]struct{ run, want string }{
		"exec form, sh -c, one command":   {`RUN ["sh", "-c", "apt-get install -y openjdk-17-jdk"]`, vuln},
		"exec form, bash -c":              {`RUN ["bash", "-c", "apt-get install -y openjdk-17-jdk"]`, vuln},
		"exec form, bash -lc":             {`RUN ["/bin/bash", "-lc", "apt-get install -y openjdk-17-jdk"]`, vuln},
		"exec form, -o pipefail -c":       {`RUN ["/bin/bash", "-o", "pipefail", "-c", "apt-get install -y openjdk-17-jdk"]`, vuln},
		"exec form, two commands":         {`RUN ["/bin/sh", "-c", "apt-get update; apt-get install -y openjdk-17-jdk"]`, vuln},
		"exec form, two lines":            {`RUN ["sh", "-c", "apt-get update\napt-get install -y openjdk-17-jdk"]`, vuln},
		"exec form, no shell":             {`RUN ["apt-get", "install", "-y", "openjdk-17-jdk"]`, vuln},
		"exec form, a word with &&":       {`RUN ["apt-get", "install", "-y", "curl", "&&", "openjdk-17-jdk"]`, vuln},
		"exec form, two names in a word":  {`RUN ["apt-get", "install", "-y", "curl openjdk-17-jdk"]`, vuln},
		"exec form, a quote in the text":  {`RUN ["sh", "-c", "echo 'it''s' && apt-get install -y 'openjdk-17-jdk'"]`, vuln},
		"bash -o pipefail -c":             {`RUN bash -o pipefail -c "apt-get install -y openjdk-17-jdk"`, vuln},
		"bash -euo pipefail -c":           {`RUN bash -euo pipefail -c "apt-get install -y openjdk-17-jdk"`, vuln},
		"bash --login -c":                 {`RUN bash --login -c "apt-get install -y openjdk-17-jdk"`, vuln},
		"bash -c -x":                      {`RUN bash -c -x "apt-get install -y openjdk-17-jdk"`, vuln},
		"su -c":                           {`RUN su -c "apt-get install -y openjdk-17-jdk" root`, vuln},
		"su user -c":                      {`RUN su - root -c "apt-get install -y openjdk-17-jdk"`, vuln},
		"sudo sh -c":                      {`RUN sudo -E sh -c "apt-get install -y openjdk-17-jdk"`, vuln},
		"chroot sh -c":                    {`RUN chroot /mnt /bin/sh -c "apt-get install -y openjdk-17-jdk"`, vuln},
		"eval":                            {`RUN eval "apt-get install -y openjdk-17-jdk"`, vuln},
		"a nested text":                   {`RUN sh -c 'sh -c "apt-get install -y openjdk-17-jdk"'`, vuln},
		"a text that is only printed":     {`RUN echo "run apt-get install -y openjdk-17-jdk to get Java"`, ""},
		"a text that is only written out": {`RUN printf '%s\n' "apt-get install -y openjdk-17-jdk" > /usr/local/bin/get-java`, ""},
		"a script file, not a text":       {`RUN bash /tmp/setup.sh apt-get`, ""},
	} {
		if g := one(t, "FROM debian:12\n"+c.run+"\n"); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

// Finding 4: installs that named a Java package, or took their package
// list from somewhere this file does not show, and gave nothing.
func TestRunInstallForms(t *testing.T) {
	const vuln, skip = "Dockerfile:2 os-package vulnerable", "skip Dockerfile:2"
	for name, c := range map[string]struct{ df, want string }{
		"xargs from a file":             {"FROM debian:12\nRUN xargs apt-get install -y < packages.txt\n", skip},
		"xargs -a":                      {"FROM debian:12\nRUN xargs -a packages.txt apt-get install -y\n", skip},
		"xargs after cat":               {"FROM debian:12\nRUN cat packages.txt | xargs -r apt-get install -y --no-install-recommends\n", skip},
		"xargs after echo":              {"FROM debian:12\nRUN echo openjdk-17-jdk | xargs apt-get install -y\n", vuln},
		"xargs after echo, no Java":     {"FROM debian:12\nRUN echo curl git | xargs apt-get install -y\n", ""},
		"xargs with a name of its own":  {"FROM debian:12\nRUN xargs apt-get install -y openjdk-17-jdk < more.txt\n", vuln + ", " + skip},
		"Bitnami install_packages":      {"FROM bitnami/minideb:bookworm\nRUN install_packages openjdk-17-jdk\n", vuln},
		"install_packages, no Java":     {"FROM bitnami/minideb:bookworm\nRUN install_packages curl ca-certificates\n", ""},
		"nala":                          {"FROM debian:12\nRUN nala install -y openjdk-17-jdk\n", vuln},
		"apt-fast":                      {"FROM debian:12\nRUN apt-fast install -y openjdk-17-jdk\n", vuln},
		"apt-get satisfy":               {"FROM debian:12\nRUN apt-get satisfy -y \"openjdk-17-jdk (>= 17)\"\n", vuln},
		"dnf upgrade":                   {"FROM rockylinux:9\nRUN dnf upgrade -y java-21-openjdk-headless\n", vuln},
		"yum update":                    {"FROM rockylinux:9\nRUN yum update -y java-21-openjdk-headless\n", vuln},
		"dnf downgrade":                 {"FROM rockylinux:9\nRUN dnf downgrade -y java-21-openjdk-headless\n", vuln},
		"apk upgrade":                   {"FROM alpine:3.22\nRUN apk upgrade --no-cache openjdk21-jre-headless\n", vuln},
		"apt-get update, no package":    {"FROM debian:12\nRUN apt-get update && apt-get upgrade -y\n", ""},
		"the tool in an ARG":            {"FROM debian:12\nARG APT=\"apt-get install -y\"\nRUN $APT openjdk-17-jdk\n", "Dockerfile:3 os-package vulnerable"},
		"the tool in a variable unset":  {"FROM debian:12\nARG INSTALL\nRUN $INSTALL openjdk-17-jdk\n", "Dockerfile:3 os-package vulnerable"},
		"a variable tool, no Java":      {"FROM debian:12\nARG INSTALL\nRUN $INSTALL curl && $JAVA_HOME/bin/java -version\n", ""},
		"a shell variable over an ARG":  {"FROM debian:12\nARG PKG=curl\nRUN PKG=openjdk-17-jdk && apt-get install -y $PKG\n", "Dockerfile:3 os-package vulnerable"},
		"an exported one":               {"FROM debian:12\nARG PKG=curl\nRUN export PKG=openjdk-17-jdk; apt-get install -y \"$PKG\"\n", "Dockerfile:3 os-package vulnerable"},
		"one from a command":            {"FROM debian:12\nARG PKG=curl\nRUN PKG=$(cat /pkg) && apt-get install -y $PKG\n", "skip Dockerfile:3"},
		"one that is read":              {"FROM debian:12\nARG PKG=curl\nRUN cat /pkgs | while read PKG; do apt-get install -y $PKG; done\n", "skip Dockerfile:3"},
		"a prefix assignment is not it": {"FROM debian:12\nARG PKG=openjdk-17-jdk\nRUN PKG=curl apt-get install -y $PKG\n", "Dockerfile:3 os-package vulnerable"},
		"a for loop":                    {"FROM debian:12\nRUN for p in curl openjdk-17-jdk; do apt-get install -y $p; done\n", vuln},
		"a later stage's ARG, unset":    {"FROM debian:12 AS a\nARG PKG=curl\nRUN apt-get install -y $PKG\nFROM debian:12\nARG PKG\nRUN apt-get install -y $PKG\n", "skip Dockerfile:6"},
		"a later stage's ARG, global":   {"ARG PKG=openjdk-17-jdk\nFROM debian:12 AS a\nARG PKG=curl\nRUN apt-get install -y $PKG\nFROM debian:12\nARG PKG\nRUN apt-get install -y $PKG\n", "Dockerfile:7 os-package vulnerable"},
		"an ENV of the name stays":      {"FROM debian:12\nENV PKG=openjdk-17-jdk\nARG PKG\nRUN apt-get install -y $PKG\n", "Dockerfile:4 os-package vulnerable"},
		"a comment after the install":   {"FROM debian:12\nRUN apt-get install -y openjdk-17-jdk # java\n", vuln},
		"a comment that hides it":       {"FROM debian:12\nRUN apt-get install -y curl # openjdk-17-jdk\n", ""},
		"a # inside a word":             {"FROM debian:12\nRUN apt-get install -y curl#x openjdk-17-jdk\n", vuln},
		"a heredoc with a comment":      {"FROM debian:12\nRUN <<EOF\napt-get update # refresh\napt-get install -y openjdk-17-jdk\nEOF\n", vuln},
	} {
		if g := one(t, c.df); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

// Finding 2: an ONBUILD instruction runs in the build of another image.
// Its ENV, ARG, CMD and ENTRYPOINT set nothing in this one; its RUN and
// COPY --from are still read.
func TestOnbuildSetsNothingHere(t *testing.T) {
	res := scan(t, tree(t, map[string]string{"Dockerfile": "FROM eclipse-temurin:21.0.13_9-jre\nONBUILD ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nRUN apt-get install -y openjdk-17-jdk\n"}))
	if len(res.Findings) != 2 {
		t.Fatalf("%d findings, want 2: %+v", len(res.Findings), res.Findings)
	}
	for _, f := range res.Findings {
		if f.Status != StatusVulnerable || f.Props["mitigation"] != "" || strings.Contains(f.Message+f.Reason, "mitigated") {
			t.Errorf("%s:%d %s %s: an ONBUILD ENV is reported as a mitigation: %q %q", f.File, f.Line, f.Rule, f.Status, f.Props["mitigation"], f.Reason)
		}
	}
	for name, c := range map[string]struct{ df, want string }{
		"ONBUILD ARG is not this stage's":  {"FROM debian:12\nONBUILD ARG PKG=openjdk-17-jdk\nRUN apt-get install -y ${PKG:-curl}\n", ""},
		"ONBUILD ENV is not this stage's":  {"FROM debian:12\nONBUILD ENV PKG=openjdk-17-jdk\nRUN apt-get install -y ${PKG:-curl}\n", ""},
		"ONBUILD CMD does not undo an ENV": {"FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nONBUILD CMD [\"java\", \"-XX:+UseBASE64Intrinsics\", \"-jar\", \"/a.jar\"]\n", "Dockerfile:1 image-pin mitigated"},
		"a CMD does":                       {"FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nCMD [\"java\", \"-XX:+UseBASE64Intrinsics\", \"-jar\", \"/a.jar\"]\n", "Dockerfile:1 image-pin vulnerable"},
		"ONBUILD RUN is read":              {"FROM debian:12\nONBUILD RUN apt-get install -y openjdk-17-jdk\n", "Dockerfile:2 os-package vulnerable"},
		"ONBUILD COPY --from is read":      {"FROM debian:12\nONBUILD COPY --from=eclipse-temurin:21.0.13_9-jre /opt/java /opt/java\n", "Dockerfile:2 image-pin vulnerable"},
		"ONBUILD FROM is not a stage":      {"FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nONBUILD FROM x\nRUN apt-get install -y openjdk-17-jdk\n", "Dockerfile:1 image-pin mitigated, Dockerfile:4 os-package mitigated"},
		"an ENV of the stage, as it was":   {"FROM eclipse-temurin:21.0.13_9-jre\nENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nRUN apt-get install -y openjdk-17-jdk\n", "Dockerfile:1 image-pin mitigated, Dockerfile:3 os-package mitigated"},
	} {
		if g := one(t, c.df); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}
