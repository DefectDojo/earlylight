package knowledge

import "testing"

func TestCompareRPM(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"17.0.21.0.9-1.el9", "17.0.21.0.9-1.el9", 0},
		{"17.0.21.0.9-2.el9", "17.0.21.0.9-1.el9", 1},
		{"17.0.21.0.9-1.el9", "17.0.21.0.10-1.el9", -1},
		{"17.0.21.0.9-1.el9_6", "17.0.21.0.9-1.el9", 1},
		{"1:17.0.21.0.9-1.el9", "17.0.21.0.9-2.el9", 1},
		{"17.0.21.1.2-1.el9", "17.0.21.0.9-9.el9", 1},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0a-1", "1.0-1", 1},
		{"1.010-1", "1.9-1", 1},
		{"1.0-1.el9", "1.0-1.el10", -1},
	} {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareRPM(c.b, c.a); got != -c.want {
			t.Errorf("CompareRPM(%s, %s) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestRedHatTable(t *testing.T) {
	// Empty today: Red Hat had published no fixed build.
	if len(RedHatFixed) != 0 {
		t.Fatalf("RedHatFixed has entries; update this test and FACTS.md: %+v", RedHatFixed)
	}
	if _, _, known := JudgeRedHat("java-17-openjdk-headless", "17.0.21.0.9-1.el9"); known {
		t.Error("a build was judged from an empty table")
	}
	saved := RedHatFixed
	t.Cleanup(func() { RedHatFixed = saved })
	RedHatFixed = []RedHatFix{{Package: "java-17-openjdk", Dist: "el9_6", EVR: "1:17.0.21.0.9-2.el9_6", Advisory: "RHSA-2026:0000"}}
	for _, c := range []struct {
		name, evr string
		want      Status
		known     bool
	}{
		{"java-17-openjdk-headless", "17.0.21.0.9-1.el9_6", Vulnerable, true},
		{"java-17-openjdk-headless", "1:17.0.21.0.9-1.el9_6", Vulnerable, true},
		{"java-17-openjdk-headless", "1:17.0.21.0.9-2.el9_6", Fixed, true},
		// An install path or a dnf argument omits the epoch: compared without it.
		{"java-17-openjdk-headless", "17.0.21.0.9-2.el9_6", Fixed, true},
		{"java-17-openjdk", "1:17.0.21.0.9-3.el9_6", Fixed, true},
		{"java-17-openjdk-devel", "1:17.0.21.0.9-2.el9_6", Fixed, true},
		// Another stream of RHEL 9 (el9, el9_4, el9_7): the row does not speak to it.
		{"java-17-openjdk-headless", "1:17.0.21.0.9-9.el9", "", false},
		{"java-17-openjdk-headless", "1:17.0.21.0.9-9.el9_7", "", false},
		{"java-17-openjdk-headless", "1:17.0.21.0.9-9.el8_10", "", false},
		// Rebuilds that are not Red Hat's: Oracle Linux, AlmaLinux.
		{"java-17-openjdk-headless", "1:17.0.21.0.9-2.0.1.el9_6", "", false},
		{"java-17-openjdk-headless", "1:17.0.21.0.9-2.el9_6.alma.1", "", false},
		// Another upstream update or build: the row does not speak to it.
		{"java-17-openjdk-headless", "1:17.0.21.1.1-1.el9_6", "", false},
		{"java-17-openjdk-headless", "1:17.0.21.0.10-1.el9_6", "", false},
		{"java-21-openjdk-headless", "1:21.0.13.0.9-1.el9_6", "", false},
		{"java-17-openjdk-headless", "17.0.21.0.9-1.fc41", "", false}, // not Red Hat
		{"java-17-amazon-corretto-headless", "17.0.21.0.9-2.el9_6", "", false},
	} {
		st, why, known := JudgeRedHat(c.name, c.evr)
		if known != c.known || known && (st != c.want || why == "") {
			t.Errorf("JudgeRedHat(%s, %s) = %s %v (%s), want %s %v", c.name, c.evr, st, known, why, c.want, c.known)
		}
	}
}

func TestRPMUpstream(t *testing.T) {
	for in, want := range map[string]string{
		"17.0.21.0.9-1.el9":   "17.0.21.0+9",
		"1:17.0.21.1.1-1.el9": "17.0.21.1+1",
		"21.0.13.1.2-1.el9":   "21.0.13.1+2",
		"17.0.21.0.3-1.el9":   "17.0.21.0+3",
		"17.0.21-1.el9":       "17.0.21",
		"17.0.21.1-1":         "17.0.21.1",
	} {
		if got := RPMUpstream(in); got != want {
			t.Errorf("RPMUpstream(%s) = %s, want %s", in, got, want)
		}
	}
}

func FuzzRPM(f *testing.F) {
	for _, s := range [][2]string{{"1:17.0.21.0.9-1.el9_6", "17.0.21.0.9-2.el9"}, {"1.0~rc1-1", "1.0a-1"}, {"22.3.1", "17"}} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 256 || len(b) > 256 {
			return
		}
		if c := CompareRPM(a, a); c != 0 {
			t.Fatalf("CompareRPM(%q, itself) = %d", a, c)
		}
		if x, y := CompareRPM(a, b), CompareRPM(b, a); x != -y {
			t.Fatalf("CompareRPM(%q, %q) = %d but reversed %d", a, b, x, y)
		}
		_ = RPMUpstream(a)
		if st, why, known := JudgeRedHat("java-17-openjdk-headless", a); known && (st == "" || why == "") {
			t.Fatalf("JudgeRedHat(%q) gave no verdict or reason", a)
		}
		if st, why := JudgeGraalVMRelease(a, len(b)%40); st == "" || why == "" {
			t.Fatalf("JudgeGraalVMRelease(%q) gave no verdict or reason", a)
		}
	})
}
