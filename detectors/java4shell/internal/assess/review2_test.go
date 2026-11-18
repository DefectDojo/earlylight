package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

// Review finding 1: the release file alone never clears a runtime whose VM
// library carries the decoder.
func TestReleaseAloneDoesNotClear(t *testing.T) {
	musl := Input{
		Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true, Musl: true})},
		Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13.1", "JAVA_RUNTIME_VERSION", "21.0.13.1+2-LTS")},
	}
	if f := one(t, musl); f.Status != Vulnerable || f.VersionFrom != "vm-library" {
		t.Errorf("musl library with a forged release: %s from %s", f.Status, f.VersionFrom)
	}
	for _, v := range []string{"21.0.13.1", "11.0.20"} {
		in := Input{
			Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{VBMI: true})},
			Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", v)},
		}
		if f := one(t, in); f.Status != Unknown {
			t.Errorf("unreadable library with the decoder, release %s: %s (%s)", v, f.Status, f.Reason)
		}
	}
}

// Review finding 6: a release file that contradicts a HotSpot library that
// was read makes the verdict unknown.
func TestReleaseContradiction(t *testing.T) {
	in := Input{
		Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})},
		Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13", "JVM_VARIANT", "Openj9")},
	}
	if f := one(t, in); f.Status != Unknown {
		t.Errorf("HotSpot library, OpenJ9 release: %s (%s)", f.Status, f.Reason)
	}
}
