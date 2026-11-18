package nginxh2

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/repo"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/source"
)

func pullFinding() repo.Finding {
	return repo.Finding{Rule: repo.RuleNotChecked, File: "Dockerfile", Line: 1, Level: "note", Status: knowledge.Unknown,
		Reason: "only reading the image says which nginx it holds", Message: "nginx:mainline is not judged", Pull: "nginx:mainline"}
}

func TestFromPulled(t *testing.T) {
	f := pullFinding()
	// An image that could not be read is not checked.
	out := fromPulled(f, &engine.Target{Error: "no such host"})
	if len(out) != 1 || out[0].Verdict != engine.Unknown || len(out[0].CVEs) != 2 {
		t.Errorf("error: %+v", out)
	}
	// Read in part, nothing found: not checked, never clear.
	out = fromPulled(f, &engine.Target{Platform: "linux/arm64", Skipped: []source.Skip{{Path: "/usr/sbin/nginx", Reason: "larger than --max-file-size"}}})
	if len(out) != 1 || out[0].Verdict != engine.Unknown {
		t.Errorf("partial: %+v", out)
	}
	// Read in full, nothing found: no finding.
	if out = fromPulled(f, &engine.Target{Files: 10}); len(out) != 0 {
		t.Errorf("clean: %+v", out)
	}
	// A vulnerable server is reported at the reference with the platform
	// and digest; a fixed one is not.
	it := &engine.Target{Platform: "linux/amd64", Digest: "sha256:abc", Findings: []engine.Finding{
		{Kind: KindFlow, Path: "/usr/sbin/nginx", Verdict: engine.Vulnerable, Message: "m", Facts: map[string]string{"version": "1.31.8"}},
		{Kind: KindReuse, Path: "/usr/sbin/nginx", Verdict: engine.Fixed, Reason: "r"},
	}}
	out = fromPulled(f, it)
	if len(out) != 1 || out[0].Kind != KindImage || out[0].Facts["platform"] != "linux/amd64" || out[0].Facts["digest"] != "sha256:abc" || out[0].Path != "Dockerfile" {
		t.Errorf("vulnerable: %+v", out)
	}
}

func TestRepoFinding(t *testing.T) {
	g := repoFinding(repo.Finding{Rule: repo.RuleHTTP2, File: "a.conf", Line: 3, Level: "note", Status: knowledge.NotAffected, Reason: "a setting", Message: "m"})
	if g.Verdict != engine.Inactive || g.Reason == "" || len(g.CVEs) != 0 {
		t.Errorf("http2 note: %+v", g)
	}
	g = repoFinding(pullFinding())
	if g.Verdict != engine.Unknown || len(g.CVEs) != 2 {
		t.Errorf("not checked: %+v", g)
	}
}

func TestRepoPlatforms(t *testing.T) {
	if p := repoPlatforms(engine.Options{}, ""); len(p) != 2 {
		t.Errorf("default %v", p)
	}
	if p := repoPlatforms(engine.Options{Platforms: []string{"linux/arm64"}}, ""); len(p) != 1 || p[0] != "linux/arm64" {
		t.Errorf("--platform %v", p)
	}
	if p := repoPlatforms(engine.Options{}, "linux/amd64"); len(p) != 1 {
		t.Errorf("FROM --platform %v", p)
	}
	if !containsPlatform([]string{"linux/arm64/v8"}, "linux/arm64") || containsPlatform([]string{"linux/arm/v7"}, "linux/arm64") {
		t.Error("containsPlatform")
	}
	if registryRef("docker-archive:/x.tar") == nil || registryRef("rootfs:/x") == nil || registryRef("nginx:1.31.9") != nil {
		t.Error("registryRef")
	}
}
