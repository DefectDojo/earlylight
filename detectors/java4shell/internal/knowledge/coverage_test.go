package knowledge

import "testing"

// The OpenJDK advisory of 2026-11-17 names 17.0.21.0.3, 21.0.13.0.3,
// 25.0.5.0.3 and 27.0.1.0.3 as the last affected releases; vendors ship
// five-part versions of them (Oracle, Debian sid, Microsoft's .0.2,
// Temurin's 27.0.1.0.2+1). Every one is vulnerable, however it is written.
func TestFivePartVersionsVulnerable(t *testing.T) {
	for _, s := range []string{
		"17.0.21.0.3", "21.0.13.0.3", "25.0.5.0.3", "27.0.1.0.3",
		"17.0.21.0.3+1-LTS", "21.0.13.0.3+1-LTS", "25.0.5.0.3+1-LTS", "27.0.1.0.3+1",
		"17.0.21.0.2", "21.0.13.0.2", "25.0.5.0.2",
		"17.0.21.0.2+1-LTS", "21.0.13.0.2+1-LTS", "25.0.5.0.2+1-LTS",
		"27.0.1.0.2+1", "27.0.1.0.2+1-LTS",
		"17.0.21.0.3+1-Debian-1", "21.0.13.0.3+1-Debian-1", "25.0.5.0.3+1-Debian-3", "27.0.1.0.3+1-Debian-1",
		"17.0.21.0.3+1-Ubuntu-1ubuntu124.04.1", "21.0.13.0.3+1-alpine-r0",
		// GraalVM's version line: the JDK version, then jvmci.
		"17.0.21.0.3+1-LTS-jvmci-23.0-b99", "21.0.13.0.3+1-LTS-jvmci-23.1-b99",
	} {
		v, ok := Parse(s)
		if !ok {
			t.Errorf("Parse(%q) failed", s)
			continue
		}
		if st, why := Judge(v); st != Vulnerable {
			t.Errorf("Judge(%q) = %s (%s), want vulnerable", s, st, why)
		}
	}
}
