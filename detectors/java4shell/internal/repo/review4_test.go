package repo

import (
	"context"
	"strings"
	"testing"
)

func fakeRegistry(tags ...string) Registry {
	return Registry{
		Tags:   func(context.Context, string) ([]string, error) { return tags, nil },
		Verify: func(context.Context, string, string) (string, error) { return "sha256:0123abcd", nil },
	}
}

// Review finding 10.
func TestReviewFixEdits(t *testing.T) {
	// The verified digest and, for a republished tag, the re-pull warning
	// are in the summary.
	root := tree(t, map[string]string{"Dockerfile": "FROM amazoncorretto:21.0.12-al2023\n"})
	f, _ := find(scan(t, root), "Dockerfile", 1)
	ch, err := Plan(context.Background(), root, f, fakeRegistry("21.0.13-al2023"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ch.Summary, "sha256:0123abcd") || !strings.Contains(ch.Summary, "pull") {
		t.Errorf("summary: %s", ch.Summary)
	}
	// An ARG the edit would change is used elsewhere too: declined.
	root = tree(t, map[string]string{"Dockerfile": "ARG TAG=21.0.13_9-jre\nFROM eclipse-temurin:${TAG}\nRUN curl -o /a.jar https://example.invalid/agent-${TAG}.jar\n"})
	f, ok := find(scan(t, root), "Dockerfile", 2)
	if !ok {
		t.Fatal("no finding")
	}
	if _, err := Plan(context.Background(), root, f, fakeRegistry("21.0.13.1_2-jre"), Options{}); err == nil || !strings.Contains(err.Error(), "TAG") {
		t.Errorf("ARG used elsewhere: %v", err)
	}
	// setup-java: the summary says check-latest.
	root = tree(t, map[string]string{".github/workflows/a.yml": "jobs:\n  a:\n    steps:\n      - uses: actions/setup-java@v4\n        with:\n          distribution: corretto\n          java-version: '21.0.5'\n"})
	f, _ = find(scan(t, root), ".github/workflows/a.yml", 7)
	if ch, err := Plan(context.Background(), root, f, Registry{}, Options{}); err != nil || !strings.Contains(ch.Summary, "check-latest") {
		t.Errorf("setup-java summary: %v %v", ch, err)
	}
}

// Review finding 10: when a tag's variant does not name its base OS, the
// replacement must be on the same one.
func TestSameBase(t *testing.T) {
	if !NamesBaseOS("-jre-alpine") || !NamesBaseOS("-al2023-headless") || NamesBaseOS("-jre") || NamesBaseOS("") {
		t.Error("NamesBaseOS")
	}
	if err := SameBase("ubuntu 24.04", "ubuntu 26.04"); err == nil {
		t.Error("different base accepted")
	}
	if err := SameBase("ubuntu 24.04", "ubuntu 24.04"); err != nil {
		t.Error(err)
	}
	if err := SameBase("", "ubuntu 24.04"); err == nil {
		t.Error("unknown base accepted")
	}
}

// Round-2 finding 7: the base OS is compared on ID and major version.
func TestSameBaseMajor(t *testing.T) {
	for _, c := range []struct {
		cur, tgt string
		ok       bool
	}{
		{"ol 9.5", "ol 9.6", true},
		{"alpine 3.21.4", "alpine 3.22.1", true},
		{"ubuntu 24.04", "ubuntu 26.04", false},
		{"debian 12", "debian 13", false},
		{"ubuntu 24.04", "debian 12", false},
	} {
		if err := SameBase(c.cur, c.tgt); (err == nil) != c.ok {
			t.Errorf("SameBase(%q, %q) = %v", c.cur, c.tgt, err)
		}
	}
	if err := SameBase(strings.Repeat("x", 5000)+" 1", "ubuntu 24.04"); err == nil || len(err.Error()) > 400 {
		t.Errorf("unbounded reason: %d bytes", len(err.Error()))
	}
}

// Round-3 nit: Ubuntu's YY.04 and YY.10 are different releases.
func TestSameBaseUbuntu(t *testing.T) {
	if err := SameBase("ubuntu 24.04", "ubuntu 24.10"); err == nil {
		t.Error("Ubuntu 24.04 to 24.10 accepted")
	}
	if err := SameBase("ubuntu 24.04", "ubuntu 24.04"); err != nil {
		t.Error(err)
	}
	if err := SameBase("rhel 9.4", "rhel 9.6"); err != nil {
		t.Error(err)
	}
}
