package java4shell

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/repo"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/source"
)

// Review finding 14: a pulled image that was read only in part, with no
// finding, does not make the reference vanish.
func TestPulledPartlyRead(t *testing.T) {
	f := repo.Finding{Rule: repo.RuleNotChecked, File: "compose.yaml", Line: 3, Status: repo.StatusUnknown, Pull: "x/jira:9", Props: map[string]string{"image": "x/jira:9"}}
	it := &engine.Target{Type: engine.Image, Skipped: []source.Skip{{Path: "/opt/atlassian/jira/jre/lib/server/libjvm.so", Reason: "larger than --max-file-size"}}}
	got := fromPulled(f, it)
	if len(got) != 1 || got[0].Verdict != engine.Unknown || !strings.Contains(got[0].Reason, "in full") {
		t.Fatalf("partly read image: %+v", got)
	}
	it = &engine.Target{Type: engine.Image, Problems: []string{"a damaged package database"}}
	if got := fromPulled(f, it); len(got) != 1 || got[0].Verdict != engine.Unknown {
		t.Errorf("image with problems: %+v", got)
	}
	if got := fromPulled(f, &engine.Target{Type: engine.Image}); len(got) != 0 {
		t.Errorf("image read in full with no Java runtime: %+v", got)
	}
}

// Review finding 14: the platform lookup goes through the guarded
// transport and has a deadline.
func TestPlatformsGuarded(t *testing.T) {
	start := time.Now()
	_, err := platforms(context.Background(), "169.254.169.254/library/x:1", engine.Options{Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("a link-local registry was contacted")
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("no deadline: %s", time.Since(start))
	}
}
