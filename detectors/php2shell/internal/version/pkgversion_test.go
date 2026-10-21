package version

import "testing"

// Orderings the verdicts depend on, spelled out (all also covered by the
// differential goldens).
func TestPackageVersionExamples(t *testing.T) {
	dpkg := []struct {
		a, b string
		want int
	}{
		{"8.2.35-1~deb12u1", "8.2.35-1", -1},
		{"8.2.29-1~deb12u1", "8.2.35-1~deb12u1", -1},
		{"8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1},
		{"7.4.3-4ubuntu2.29", "7.4.3-4ubuntu2.29+esm5", -1},
		{"5.5.9+dfsg-1ubuntu4.29+esm18", "5.5.9+dfsg-1ubuntu4.29+esm9", 1},
		{"1:8.2.35-1+0~20261021.1+debian12~1.gbp1234", "8.2.99-1", 1},
		{"8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "8.3.36-1", 1},
		{"1.0", "1.0-0", 0},
		{"01:1.0", "1:1.0", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1},
	}
	for _, c := range dpkg {
		if got, err := CompareDpkg(c.a, c.b); err != nil || got != c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"", " ", "1 0", ":1", "a:1", "-1:1", "1:", "1.0-", "-1", "a1", "1_0", "1.0-1:2", "2147483648:1", "1\x00"} {
		if _, err := CompareDpkg(bad, "1"); err == nil {
			t.Errorf("CompareDpkg(%q) accepted", bad)
		}
	}

	apk := []struct {
		a, b string
		want int
	}{
		{"8.3.29-r0", "8.3.36-r0", -1},
		{"8.4.27-r0", "8.4.27-r1", -1},
		{"1.0_rc1-r9", "1.0-r0", -1},
		{"1.0_p1-r0", "1.0-r9", 1},
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0-r0", -1}, // apk: a revision, even r0, sorts above none
	}
	for _, c := range apk {
		if got, err := CompareAPK(c.a, c.b); err != nil || got != c.want {
			t.Errorf("CompareAPK(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "a", "1.0-1", "1.0_foo", "1.", "1.0-r", "1.0~abc"} {
		if _, err := CompareAPK(bad, "1"); err == nil {
			t.Errorf("CompareAPK(%q) accepted", bad)
		}
	}

	rpm := []struct {
		a, b string
		want int
	}{
		{"8.2.35-150600.3.39.1", "8.2.35-150600.3.40.1", -1},
		{"8.2.13-1.module+el9.4.0+20xxx+abcd1234", "8.2.13-1.module+el9.5.0+22521+2f20a3e5", -1},
		{"8.0.30-1.el9_2", "8.0.30-3.el9_6", -1},
		{"1:8.0.30-1.el9_2", "8.9.0-1.el9", 1},
		{"0:8.0.30-1.el9_2", "8.0.30-1.el9_2", 0},
		{"1.0~rc1-1", "1.0-1", -1},
		{"1.0^git1-1", "1.0-1", 1},
		{"1.0", "1.0-1", -1},
		{"1.0_1", "1.0.1", 0},
	}
	for _, c := range rpm {
		if got := CompareRPM(c.a, c.b); got != c.want {
			t.Errorf("CompareRPM(%q, %q) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
	if e := ParseEVR("1:8.2.13-1.module+el9.4.0"); e.Epoch != "1" || e.Version != "8.2.13" || e.Release != "1.module+el9.4.0" {
		t.Errorf("ParseEVR = %+v", e)
	}
}
