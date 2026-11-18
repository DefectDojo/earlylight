package brotli

import (
	"fmt"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/testbin"
	"github.com/DefectDojo/earlylight/internal/engine"
)

var vulnerable = testbin.ELF([]testbin.Symbol{{Name: "BrotliDecoderDecompressStream", Defined: true}}, testbin.Table("1.0.9"))

func paths(fs []engine.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Path)
	}
	return fmt.Sprint(out)
}

// When an image names a path again, what was found in the first entry,
// and inside it, is dropped. Final review A3: "inside it" is what the
// engine says is a member of it, not a path that starts the same way: a
// directory named "a!" next to a file "a" is not an archive.
func TestForget(t *testing.T) {
	s := (&Detector{}).NewScan(engine.Image).(*scan)
	s.Visit(engine.File{Path: "/a", Data: vulnerable})
	s.Visit(engine.File{Path: "/a!/x.so", Data: vulnerable, Member: true, Outer: "/a"})
	s.Visit(engine.File{Path: "/ab", Data: vulnerable})
	s.Visit(engine.File{Path: "/b", Data: vulnerable})
	s.Visit(engine.File{Path: "/opt/app", Data: []byte("hello")})
	s.Visit(engine.File{Path: "/opt/app!/libbrotlidec.so.1", Data: vulnerable}) // a file in the directory "app!"
	s.Forget("/a")
	s.Forget("/opt/app")
	if got := paths(s.Finish(nil)); got != "[/ab /b /opt/app!/libbrotlidec.so.1]" {
		t.Errorf("after Forget: %s", got)
	}
	s.Forget("/opt/app!/libbrotlidec.so.1")
	s.Visit(engine.File{Path: "/a", Data: vulnerable})
	if got := paths(s.Finish(nil)); got != "[/ab /b /a]" {
		t.Errorf("after the second Forget: %s", got)
	}
}

// Final review A6: forgetting a path costs what the path held, not every
// finding kept.
func TestForgetIsCheap(t *testing.T) {
	s := (&Detector{}).NewScan(engine.Image).(*scan)
	for i := 0; i < 20000; i++ {
		s.Visit(engine.File{Path: fmt.Sprintf("/lib/%d.so", i), Data: vulnerable})
	}
	start := time.Now()
	for i := 0; i < 100000; i++ {
		s.Forget("/x")
		s.Visit(engine.File{Path: "/x", Data: []byte("x")})
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("100,000 repeats over 20,000 findings took %s", d)
	}
	if n := len(s.Finish(nil)); n != 20000 {
		t.Errorf("%d findings, want 20000", n)
	}
}
