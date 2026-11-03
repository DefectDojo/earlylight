package all_test

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"testing"
	"time"

	_ "github.com/DefectDojo/earlylight/detectors/all"
	"github.com/DefectDojo/earlylight/internal/cli"
)

// The catalog is a contract: tools such as DefectDojo read detectors.json from
// each release to tell which detectors it contains and how to run each one.
// Every real detector must fill it in completely.
func TestCatalogContract(t *testing.T) {
	var out, errb bytes.Buffer
	if got := cli.Run(cli.Config{Tool: "earlylight", Version: "v0.0.0", Summary: "t"}, []string{"detectors", "--format", "json"}, &out, &errb); got != 0 {
		t.Fatalf("exit %d: %s", got, errb.String())
	}
	var cat cli.Catalog
	if err := json.Unmarshal(out.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Detectors) < 3 {
		t.Fatalf("only %d detectors", len(cat.Detectors))
	}
	id := regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	cve := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	modes := map[string]bool{"fs": true, "image": true, "host": true, "repo": true, "fix": true}
	levels := map[string]bool{"error": true, "warning": true, "note": true}
	for _, d := range cat.Detectors {
		if !id.MatchString(d.ID) || d.Title == "" {
			t.Errorf("%q: id or title", d.ID)
		}
		if _, err := time.Parse("2006-01-02", d.Disclosed); err != nil {
			t.Errorf("%s: disclosed %q is not YYYY-MM-DD", d.ID, d.Disclosed)
		}
		for _, c := range d.CVEs {
			if !cve.MatchString(c) {
				t.Errorf("%s: CVE %q", d.ID, c)
			}
		}
		if len(d.Advisories) == 0 {
			t.Errorf("%s: no advisory link (the first one is the SARIF help link)", d.ID)
		}
		for _, a := range d.Advisories {
			if u, err := url.Parse(a); err != nil || u.Scheme != "https" || u.Host == "" {
				t.Errorf("%s: advisory %q is not an https link", d.ID, a)
			}
		}
		if len(d.Modes) == 0 {
			t.Errorf("%s: no modes", d.ID)
		}
		for _, m := range d.Modes {
			if !modes[m] {
				t.Errorf("%s: mode %q", d.ID, m)
			}
		}
		if len(d.Kinds) == 0 {
			t.Errorf("%s: no kinds", d.ID)
		}
		seen := map[string]bool{}
		for _, k := range d.Kinds {
			if !id.MatchString(k.ID) || seen[k.ID] || k.Title == "" || !levels[k.Level] {
				t.Errorf("%s/%s: kind id, title or level (%q)", d.ID, k.ID, k.Level)
			}
			seen[k.ID] = true
		}
	}
}
