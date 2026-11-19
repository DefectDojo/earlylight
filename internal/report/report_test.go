package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/source"
)

func TestSafe(t *testing.T) {
	for _, s := range []string{"\x1b[31mred", "a\nfake line", "\x9b31m", "bad\xffutf8", "tab\there"} {
		if got := safe(s); got == s {
			t.Errorf("%q passed through unescaped", s)
		}
	}
	for _, s := range []string{"/etc/ssl/certs/ca-certificates.crt", "app.jar!/BOOT-INF/lib/x.jar!/cacerts", "émSign ✓"} {
		if got := safe(s); got != s {
			t.Errorf("%q changed to %q", s, got)
		}
	}
}

type kindsDetector struct{}

func (kindsDetector) Manifest() engine.Manifest {
	return engine.Manifest{ID: "t-kinds", Kinds: []engine.Kind{
		{ID: "lib", Title: "Library", Level: "error", SecuritySeverity: "9.2"},
		{ID: "pin", Title: "Pin not checked", Level: "note"},
	}}
}
func (kindsDetector) Load() error                           { return nil }
func (kindsDetector) NewScan(engine.TargetKind) engine.Scan { return nil }

// Importers rank findings by kind. The JSON report carries each kind's level
// and score so they don't need a table that goes stale with every detector.
func TestJSONCarriesKinds(t *testing.T) {
	r := New("earlylight", "test", []engine.Detector{kindsDetector{}})
	var b bytes.Buffer
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Detectors []DetectorInfo `json:"detectors"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := []KindInfo{{ID: "lib", Title: "Library", Level: "error", Severity: "9.2"}, {ID: "pin", Title: "Pin not checked", Level: "note"}}
	if len(got.Detectors) != 1 || !reflect.DeepEqual(got.Detectors[0].Kinds, want) {
		t.Errorf("kinds = %+v, want %+v", got.Detectors, want)
	}
}

// Round-2 review finding 8: a path with a record for each detector that
// left it unchecked is one item.
func TestNoteCountsAPathOnce(t *testing.T) {
	tg := &engine.Target{Name: "img", Type: engine.Image, Files: 2, Skipped: []source.Skip{
		{Path: "/usr/bin/gprofng-display-html", Reason: "excluded: larger than the 262144-byte limit of java4shell for this file (300000 bytes)", Excluded: true},
		{Path: "/usr/bin/gprofng-display-html", Reason: "excluded: larger than the 262144-byte limit of sshole for this file (300000 bytes)", Excluded: true},
	}}
	var b bytes.Buffer
	Text(&b, &Report{Tool: "t", Targets: []*engine.Target{tg}}, Options{})
	if !strings.Contains(b.String(), "NOTE: 1 item(s) were not scanned (0 coverage gaps") {
		t.Errorf("%s", b.String())
	}
}
