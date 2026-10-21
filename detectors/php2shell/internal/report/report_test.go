package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/assess"
)

type sarifDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID         string         `json:"id"`
					Properties map[string]any `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID       string `json:"ruleId"`
			Level        string `json:"level"`
			Message      struct{ Text string }
			Fingerprints map[string]string `json:"fingerprints"`
			Locations    []struct {
				PhysicalLocation struct {
					ArtifactLocation struct{ URI string }     `json:"artifactLocation"`
					Region           *struct{ StartLine int } `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
		} `json:"invocations"`
	} `json:"runs"`
}

func render(t *testing.T, r *Report) sarifDoc {
	t.Helper()
	var b bytes.Buffer
	if err := SARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	var d sarifDoc
	if err := json.Unmarshal(b.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSARIFShape(t *testing.T) {
	r := &Report{Tool: "php2shell-scan", Version: "test", Targets: []*Target{{
		Name: "app:prod", Type: "image",
		Findings: []assess.Finding{
			{Path: "/usr/local/sbin/php-fpm", PHPVersion: "8.3.35", SAPI: "fpm-fcgi", WebFacing: true, Status: assess.Vulnerable, Reason: "r", Fix: "f"},
			{Path: "/usr/local/bin/php", PHPVersion: "8.3.35", SAPI: "cli", Status: assess.Vulnerable, Reason: "r"},
			{Path: "/usr/bin/php8.3", PHPVersion: "8.3.6", SAPI: "cli", Status: assess.Unknown, Reason: "r"},
			{Path: "/opt/php/bin/php", PHPVersion: "8.3.36", SAPI: "cli", Status: assess.Fixed},
		},
	}}}
	d := render(t, r)
	res := d.Runs[0].Results
	if len(res) != 3 {
		t.Fatalf("%d results, want 3 (fixed ones are not reported)", len(res))
	}
	want := []string{RuleRuntimeWeb, RuleRuntimeCLI, RuleRuntimeUnknown}
	for i, x := range res {
		if x.RuleID != want[i] {
			t.Errorf("result %d rule %s, want %s", i, x.RuleID, want[i])
		}
		if !strings.Contains(x.Message.Text, "CVE-2026-109618") || !strings.Contains(x.Message.Text, "CVE-2026-109619") {
			t.Errorf("message %q lacks a CVE", x.Message.Text)
		}
		if len(x.Fingerprints["php2shell/v1"]) != 64 {
			t.Errorf("result %d has no fingerprint", i)
		}
	}
	sev := map[string]any{}
	for _, ru := range d.Runs[0].Tool.Driver.Rules {
		sev[ru.ID] = ru.Properties["security-severity"]
		// DefectDojo takes the CVE from the rule ID, and only the first one.
		if strings.HasPrefix(ru.ID, "CVE-") && !strings.HasPrefix(ru.ID, "CVE-2026-109618/") {
			t.Errorf("rule %s", ru.ID)
		}
	}
	if sev[RuleRuntimeWeb] != "9.2" || sev[RuleRuntimeCLI] != "7.5" || sev[RuleImage] != "9.2" || sev[RuleRuntimeUnknown] != "Info" {
		t.Errorf("severities %v", sev)
	}
	if !d.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("execution not successful")
	}
}

// A result keeps its fingerprint when its line or message changes (a line
// inserted above it, a registry finishing a publish), so DefectDojo updates the
// finding rather than closing it and opening a new one.
func TestFingerprintsAreStable(t *testing.T) {
	mk := func(line int, reason string) *Report {
		return &Report{Targets: []*Target{{Name: "repo", Type: "repository", Refs: []RefFinding{
			{File: "Dockerfile", Line: line, Kind: "dockerfile", Image: "php:8.3.35-fpm", Status: assess.Vulnerable, Reason: reason},
			{File: "Dockerfile", Line: line + 5, Kind: "dockerfile", Image: "php:8.3.35-fpm", Status: assess.Vulnerable, Reason: reason},
		}}}}
	}
	a, b := render(t, mk(1, "linux/amd64 (PHP 8.3.35)")).Runs[0].Results, render(t, mk(3, "linux/arm64 (PHP 8.3.34)")).Runs[0].Results
	for i := range a {
		if a[i].Fingerprints["php2shell/v1"] != b[i].Fingerprints["php2shell/v1"] {
			t.Errorf("result %d fingerprint changed", i)
		}
	}
	if a[0].Fingerprints["php2shell/v1"] == a[1].Fingerprints["php2shell/v1"] {
		t.Error("two references to the same image in one file share a fingerprint")
	}
	if a[0].Locations[0].PhysicalLocation.Region.StartLine != 1 || !strings.HasPrefix(a[0].Message.Text, "Image php:8.3.35-fpm has PHP vulnerable to CVE-2026-109618") {
		t.Errorf("result %+v", a[0])
	}
}

func TestIncompleteIsNotSuccess(t *testing.T) {
	d := render(t, &Report{Targets: []*Target{{Name: "repo", Type: "repository", Incomplete: "registry timed out"}}})
	if d.Runs[0].Invocations[0].ExecutionSuccessful || d.Runs[0].Results == nil {
		t.Fatalf("incomplete scan: %+v", d.Runs[0])
	}
}

func TestTextQuotesHostileNames(t *testing.T) {
	var b bytes.Buffer
	Text(&b, &Report{Targets: []*Target{{Name: "img", Type: "image", Findings: []assess.Finding{
		{Path: "/usr/bin/php\x1b[2J\nFAKE OK", PHPVersion: "8.3.35", SAPI: "cli", Status: assess.Vulnerable, Reason: "r"},
	}}}}, false, false)
	if strings.Contains(b.String(), "\x1b") || strings.Contains(b.String(), "\nFAKE OK") {
		t.Fatalf("control characters reached the terminal:\n%q", b.String())
	}
}
