package brotli

import (
	"testing"

	"github.com/DefectDojo/earlylight/internal/engine"
)

// When an image names a path again, what was found in the first entry,
// and inside it, is dropped.
func TestForget(t *testing.T) {
	s := &scan{findings: []engine.Finding{{Path: "/a"}, {Path: "/a!/x.so"}, {Path: "/ab"}, {Path: "/b"}}}
	s.Forget("/a")
	if len(s.findings) != 2 || s.findings[0].Path != "/ab" || s.findings[1].Path != "/b" {
		t.Errorf("%+v", s.findings)
	}
}
