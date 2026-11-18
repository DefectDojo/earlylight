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

func TestGraalVM(t *testing.T) {
	if !IsGraalVM("17.0.6+10-jvmci-22.3-b13") || IsGraalVM("21.0.13+9-LTS") {
		t.Fatal("IsGraalVM")
	}
	for _, c := range []struct {
		v    string
		want Status
	}{
		{"17.0.5+8-jvmci-22.3-b08", NotAffected}, // GraalVM CE 22.3.0
		{"17.0.6+10-jvmci-22.3-b13", Vulnerable}, // GraalVM CE 22.3.1
		{"21.0.2+13-jvmci-23.1-b30", Vulnerable}, // GraalVM CE for JDK 21 (23.1.2)
		{"17.0.21.0.3+1-LTS-jvmci-23.0-b99", Vulnerable},
		{"21.0.13.0.3+1-LTS-jvmci-23.1-b99", Vulnerable},
		// At or past the OpenJDK fix, but no fixed GraalVM build is known.
		{"21.0.13.1+2-LTS-jvmci-23.1-b99", Unknown},
		{"25.0.5.1+2-LTS-jvmci-b01", Unknown},
		{"11.0.33+8-LTS-jvmci-21.3-b99", NotAffected},
	} {
		v, _ := Parse(c.v)
		if st, why := JudgeGraalVM(v); st != c.want || why == "" {
			t.Errorf("JudgeGraalVM(%s) = %s (%s), want %s", c.v, st, why, c.want)
		}
	}
	// A published fixed GraalVM build, once listed, clears later builds.
	saved := GraalVMFixed
	t.Cleanup(func() { GraalVMFixed = saved })
	GraalVMFixed = map[int]Build{21: {Version: []int{21, 0, 13, 1}, Build: 2}}
	for v, want := range map[string]Status{"21.0.13.1+2-LTS-jvmci-23.1-b99": Fixed, "21.0.13.1+1-LTS-jvmci-23.1-b99": Vulnerable, "21.0.13.0.3+1-LTS-jvmci-23.1-b99": Vulnerable} {
		p, _ := Parse(v)
		if st, why := JudgeGraalVM(p); st != want {
			t.Errorf("with a fixed build listed, JudgeGraalVM(%s) = %s (%s), want %s", v, st, why, want)
		}
	}
	// A GraalVM build of Java 11 whose VM library carries the decoder:
	// Oracle names GraalVM Enterprise 21.3.20.0.3 as affected.
	v, _ := Parse("11.0.33+8-LTS-jvmci-21.3-b99")
	if st, why := JudgeBackportGraalVM(v); st != Vulnerable {
		t.Errorf("GraalVM 11 backport: %s (%s)", st, why)
	}
}

func TestGraalVMRelease(t *testing.T) {
	for _, c := range []struct {
		graal string
		java  int
		want  Status
	}{
		{"22.3.0", 17, NotAffected}, // built on 17.0.5
		{"22.3.1", 17, Vulnerable},  // built on 17.0.6
		{"22.3.3", 17, Vulnerable},
		{"23.0.1", 17, Vulnerable},
		{"22.3", 17, Unknown}, // 22.3.0 or a later patch
		{"21.3.5", 17, Unknown},
		{"22.3.1", 11, NotAffected},
		{"21.3.0", 8, Unknown}, // 21.3.x: GraalVM Enterprise 21.3 is listed
		{"22.3.1", 19, Vulnerable},
		{"23.1.2", 21, Vulnerable},
		{"22.3.1", 16, NotAffected},
		{"22.3.1", 30, Unknown},
	} {
		if st, why := JudgeGraalVMRelease(c.graal, c.java, true); st != c.want || why == "" {
			t.Errorf("JudgeGraalVMRelease(%s, %d) = %s (%s), want %s", c.graal, c.java, st, why, c.want)
		}
	}
}

// Review F3: GraalVM's own numbers clear a release only for GraalVM
// Community names with Java 8 to 16 (not 21.3.x, whose Enterprise build is
// listed as affected) or exactly 22.3.0 for Java 17; NIK, Mandrel, other
// vendors and malformed numbers stay unknown.
func TestGraalVMReleaseStrict(t *testing.T) {
	for _, c := range []struct {
		graal     string
		java      int
		community bool
		want      Status
	}{
		{"22.3.0", 17, true, NotAffected},
		{"22.3.0", 17, false, Unknown}, // NIK, Mandrel: numbering inferred
		{"22.3.1", 17, false, Vulnerable},
		{"22.3.1", 11, true, NotAffected},
		{"22.3.1", 11, false, Unknown},
		{"22.3.1", 1, true, Unknown},
		{"22.3.1", 0, true, Unknown},
		{"22.3.1", 7, true, Unknown},
		{"21.3.20", 11, true, Unknown},
		{"21.3.20", 8, true, Unknown},
		{"22.3.0-dev", 17, true, Unknown},
		{"22.3.00", 17, true, Unknown},
		{"22.3.0.0", 17, true, Unknown},
		{"22.3.0", 19, true, Vulnerable}, // every Java 19 release has the decoder
		{"22.3.0", 19, false, Vulnerable},
	} {
		if st, why := JudgeGraalVMRelease(c.graal, c.java, c.community); st != c.want || why == "" {
			t.Errorf("JudgeGraalVMRelease(%s, %d, community %v) = %s (%s), want %s", c.graal, c.java, c.community, st, why, c.want)
		}
	}
}

// Review F4: with a fixed GraalVM row, only a version OpenJDK's data also
// judges fixed is fixed; a vendor build number or a later update stays
// unknown, and pre-release or older builds are not fixed.
func TestGraalVMRow(t *testing.T) {
	saved := GraalVMFixed
	t.Cleanup(func() { GraalVMFixed = saved })
	GraalVMFixed = map[int]Build{17: {Version: []int{17, 0, 21, 1}, Build: 2}}
	for v, want := range map[string]Status{
		"17.0.21.1+2-jvmci-23.0-b99":       Fixed,
		"17.0.21.1+3-jvmci-23.0-b99":       Fixed,
		"17.0.21.9+1-jvmci-23.0-b99":       Unknown,
		"17.0.22+7-jvmci-23.0-b99":         Unknown,
		"17.0.21.1+1-jvmci-23.0-b99":       Vulnerable,
		"17.0.21.1-ea+2-jvmci-23.0-b99":    Unknown,
		"17.0.21.1-ea+1-jvmci-23.0-b99":    Vulnerable,
		"17.0.21.0.3+1-LTS-jvmci-23.0-b99": Vulnerable,
	} {
		p, ok := Parse(v)
		if !ok {
			t.Fatalf("Parse(%s)", v)
		}
		if st, why := JudgeGraalVM(p); st != want {
			t.Errorf("row 17.0.21.1+2: JudgeGraalVM(%s) = %s (%s), want %s", v, st, why, want)
		}
	}
}

// A row whose first fixed GraalVM build comes after OpenJDK's: the builds
// in between are OpenJDK-fixed but not GraalVM-fixed.
func TestGraalVMRowLaterBuild(t *testing.T) {
	saved := GraalVMFixed
	t.Cleanup(func() { GraalVMFixed = saved })
	GraalVMFixed = map[int]Build{21: {Version: []int{21, 0, 13, 1}, Build: 5}}
	for v, want := range map[string]Status{
		"21.0.13.1+3-jvmci-23.1-b99": Vulnerable,
		"21.0.13.1+5-jvmci-23.1-b99": Fixed,
	} {
		p, _ := Parse(v)
		if st, why := JudgeGraalVM(p); st != want {
			t.Errorf("row 21.0.13.1+5: JudgeGraalVM(%s) = %s (%s), want %s", v, st, why, want)
		}
	}
}

// GraalVM Community's own release numbers (graal-25.5.5.0.3 is JDK
// 25.0.5.0.3, graal-25.1.3 is JDK 25.0.3) are never Java versions.
func TestGraalVMOwnNumbersNotJava(t *testing.T) {
	for _, s := range []string{"25.1.3", "25.5.5.0.3", "23.1.2"} {
		if !GraalVMOwnNumber(s) {
			t.Errorf("%s not recognised as GraalVM's own number", s)
		}
	}
	for _, s := range []string{"25.0.3", "25.0.5.0.3", "17.0.21.1", "21"} {
		if GraalVMOwnNumber(s) {
			t.Errorf("%s taken as GraalVM's own number", s)
		}
	}
}
