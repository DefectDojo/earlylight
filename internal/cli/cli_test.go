package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/engine"
)

// unsure reports every file as unknown, like a detector that found a runtime
// whose vendor may have backported the fix.
type unsure struct{}

func (unsure) Manifest() engine.Manifest {
	return engine.Manifest{ID: "t-unsure", Targets: []engine.TargetKind{engine.Filesystem}, Kinds: []engine.Kind{{ID: "runtime", Title: "runtime", Level: "error"}}}
}
func (unsure) Load() error                           { return nil }
func (unsure) NewScan(engine.TargetKind) engine.Scan { return &unsureScan{} }

type unsureScan struct{ paths []string }

func (s *unsureScan) Visit(f engine.File) []engine.Skip {
	s.paths = append(s.paths, f.Path)
	return nil
}
func (s *unsureScan) Finish(engine.TargetContext) []engine.Finding {
	var out []engine.Finding
	for _, p := range s.paths {
		out = append(out, engine.Finding{Kind: "runtime", Path: p, Verdict: engine.Unknown, Reason: "vendor backport not known", Message: "PHP 8.3.6",
			CVEs: []engine.CVEResult{{ID: "CVE-2026-109618", Verdict: engine.Fixed, Reason: "backported"}, {ID: "CVE-2026-109619", Verdict: engine.Unknown}}})
	}
	return out
}

func init() { engine.Register(unsure{}) }

func TestUnknownExitsThree(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "php"), []byte("x"), 0o600)
	c := Config{Tool: "earlylight", Version: "test", Summary: "test"}
	var out, errb bytes.Buffer
	if got := Run(c, []string{"scan", "fs", "--detector", "t-unsure", dir}, &out, &errb); got != 3 {
		t.Fatalf("exit %d, want 3\n%s%s", got, out.String(), errb.String())
	}
	for _, want := range []string{"UNKNOWN:", "CVE-2026-109618: fixed (backported)", "CVE-2026-109619: unknown"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text report missing %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if got := Run(c, []string{"scan", "fs", "--detector", "t-unsure", "--exit-zero", dir}, &out, &errb); got != 0 {
		t.Fatalf("--exit-zero: exit %d", got)
	}
	out.Reset()
	Run(c, []string{"scan", "fs", "--detector", "t-unsure", "--format", "sarif", dir}, &out, &errb)
	if !strings.Contains(out.String(), `"level": "note"`) || !strings.Contains(out.String(), `"ruleId": "t-unsure/runtime"`) {
		t.Errorf("unknown findings must reach SARIF as notes:\n%s", out.String())
	}
}

func TestUnknownDetectorRefused(t *testing.T) {
	var out, errb bytes.Buffer
	if got := Run(Config{Tool: "earlylight", Summary: "t"}, []string{"scan", "fs", "--detector", "nope", "."}, &out, &errb); got != 2 {
		t.Fatalf("exit %d", got)
	}
}
