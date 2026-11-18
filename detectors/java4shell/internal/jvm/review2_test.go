package jvm

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

// Review finding 1: musl builds name their platform linux-amd64-musl.
func TestInspectMusl(t *testing.T) {
	l, ok := Inspect("/opt/java/openjdk/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true, Musl: true, Extra: "\x00j9vm\x00"}))
	if !ok || !l.HotSpot() || l.JREVersion != "21.0.13+9-LTS" || l.Platform != "linux-amd64-musl" {
		t.Fatalf("musl: %+v", l)
	}
	if l.OpenJ9 {
		t.Error("the bytes j9vm made a HotSpot library OpenJ9")
	}
	// Without a readable version line, four bytes do not make it OpenJ9
	// when the HotSpot decoder stubs are there.
	l, _ = Inspect("/opt/java/openjdk/lib/server/libjvm.so", testlib.Build(testlib.Lib{VBMI: true, Extra: "\x00j9vm\x00"}))
	if l.OpenJ9 {
		t.Error("an unreadable HotSpot library with j9vm bytes taken for OpenJ9")
	}
}
