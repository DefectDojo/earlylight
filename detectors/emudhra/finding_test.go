package emudhra

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/detect"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Only a Go binary without the blocklist is CVE-2026-111943. DefectDojo files
// findings under their CVEs, so a trust finding that carried it would be
// grouped with a Go bug it has nothing to do with.
func TestOnlyUnpatchedGoCarriesTheCVE(t *testing.T) {
	gof := finding(assess.Result{Finding: detect.Finding{Kind: detect.UnpatchedGo, Path: "/usr/bin/app"}, Status: assess.Active})
	if len(gof.CVEs) != 1 || gof.CVEs[0].ID != goCVE || gof.CVEs[0].Verdict != engine.Vulnerable {
		t.Errorf("unpatched-go CVEs = %+v, want %s vulnerable", gof.CVEs, goCVE)
	}
	inactive := finding(assess.Result{Finding: detect.Finding{Kind: detect.UnpatchedGo, Path: "/usr/bin/app"}, Status: assess.Inactive, Reason: "never verifies chains"})
	if len(inactive.CVEs) != 1 || inactive.CVEs[0].Verdict != engine.Inactive || inactive.CVEs[0].Reason == "" {
		t.Errorf("an inactive Go binary's CVE must say inactive and why: %+v", inactive.CVEs)
	}
	trust := finding(assess.Result{Finding: detect.Finding{Kind: detect.TrustsCompromisedKey, Path: "/etc/ssl/cert.pem"}, Status: assess.Active})
	if len(trust.CVEs) != 0 {
		t.Errorf("trust finding carries CVEs %+v", trust.CVEs)
	}
}
