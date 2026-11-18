package knowledge

import (
	"strings"
	"testing"
)

// Review findings 2, 12 and 13.
func TestReviewBuilds(t *testing.T) {
	for _, c := range []struct {
		v    string
		want Status
	}{
		// Builds of the fixed release before the fix landed (+2; 27: +4).
		{"17.0.21.1+0", Vulnerable},
		{"17.0.21.1+1", Vulnerable},
		{"17.0.21.1+2", Fixed},
		{"21.0.13.1+1-LTS", Vulnerable},
		{"21.0.13.1+2-LTS", Fixed},
		{"25.0.5.1+1", Vulnerable},
		{"25.0.5.1+2", Fixed},
		{"27.0.1.1+0", Vulnerable},
		{"27.0.1.1+3", Vulnerable},
		{"27.0.1.1+4", Fixed},
		{"17.0.21.1", Fixed}, // a release named without its build is the GA
		{"17.0.21.2+1", Fixed},
		// Pre-release builds are not judged fixed.
		{"21.0.13.1-beta+1-202611100000", Vulnerable},
		{"21.0.13.1-beta+2-202611150000", Unknown},
		{"17.0.21.1-internal+0-adhoc.root.jdk17u", Unknown}, // self-built: the build number says nothing (round 2)
		{"17.0.21.1-internal+2-adhoc.root.jdk17u", Unknown},
		{"17.0.21.1+2-adhoc.builder.jdk", Unknown},
		// Older than the fix whatever the fourth number means.
		{"21.0.2.13.1", Vulnerable},
		// A JDK 28 update release is not an early-access build.
		{"28.0.1+2", Unknown},
		{"28+24", Vulnerable},
	} {
		v, ok := Parse(c.v)
		if !ok {
			t.Fatalf("Parse(%q) failed", c.v)
		}
		if got, why := Judge(v); got != c.want {
			t.Errorf("Judge(%s) = %s (%s), want %s", c.v, got, why, c.want)
		}
	}
}

// Round-2 finding 3: self-built JDKs have no meaningful build number, and
// -LTS or an rpm release suffix is not a pre-release.
func TestReviewSelfBuilt(t *testing.T) {
	for _, c := range []struct {
		v    string
		want Status
	}{
		{"17.0.6-internal+0-adhoc.root.jdk17u", Unknown},
		{"17.0.21.1-internal+0-adhoc.root.jdk17u", Unknown},
		{"21.0.2-internal+0-adhoc.root.jdk21u", Vulnerable}, // the source predates the fix
		{"24.0.2-internal+0-adhoc.root.jdk24u", Vulnerable}, // the line has no fix
		{"21.0.13.1-LTS", Fixed},
		{"21.0.13.1.2-1.el9", Fixed},
		{"21.0.13-LTS", Vulnerable},
	} {
		v, ok := Parse(c.v)
		if !ok {
			t.Fatalf("Parse(%q)", c.v)
		}
		if got, why := Judge(v); got != c.want {
			t.Errorf("Judge(%s) = %s (%s), want %s", c.v, got, why, c.want)
		}
	}
}

func TestReasonWording(t *testing.T) {
	v, _ := Parse("21.0.13.11")
	if _, why := Judge(v); strings.Contains(why, "fix is in") {
		t.Errorf("reason: %s", why)
	}
}
