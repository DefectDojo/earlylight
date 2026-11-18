package repo

import (
	"context"
	"fmt"
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
