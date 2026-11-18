package knowledge

import "testing"

func TestParseV(t *testing.T) {
	for _, bad := range []string{"", "1", "1.31.8-1", "1.31.8~", "1.31.8.1.2", "1..2", "a.b", "1.31.8 ", "+1.2", "1.2.3a", "1234567.1"} {
		if _, err := ParseV(bad); err == nil {
			t.Errorf("ParseV(%q) accepted", bad)
		}
	}
	if v, err := ParseV("37.0.7.1"); err != nil || v.String() != "37.0.7.1" {
		t.Errorf("ParseV 37.0.7.1 = %v %v", v, err)
	}
}

func TestNginxBoundaries(t *testing.T) {
	flow, _ := ByID(Flow)
	reuse, _ := ByID(Reuse)
	cases := []struct {
		v           string
		flow, reuse Status
	}{
		{"1.9.4", NotAffected, NotAffected},
		{"1.9.5", Vulnerable, NotAffected},
		{"1.18.0", Vulnerable, NotAffected},
		{"1.19.6", Vulnerable, NotAffected},
		{"1.19.7", Vulnerable, Vulnerable},
		{"1.22.1", Vulnerable, Vulnerable},
		{"1.29.8", Vulnerable, Vulnerable},
		{"1.30.0", Vulnerable, Vulnerable},
		{"1.30.6", Vulnerable, Vulnerable},
		{"1.30.7", Fixed, Fixed},
		{"1.30.10", Fixed, Fixed},
		{"1.31.0", Vulnerable, Vulnerable},
		{"1.31.8", Vulnerable, Vulnerable},
		{"1.31.9", Fixed, Fixed},
		{"1.31.10", Fixed, Fixed},
		{"1.32.0", Unknown, Unknown}, // R5: above the newest known line
		{"2.0.0", Unknown, Unknown},
		{"37.0.0", Unknown, Unknown},
		{"37.0.7", Unknown, Unknown},
		{"0.8.54", NotAffected, NotAffected},
	}
	for _, c := range cases {
		v := MustV(c.v)
		if got, why := Nginx(flow, v); got != c.flow {
			t.Errorf("%s flow = %s (%s), want %s", c.v, got, why, c.flow)
		}
		if got, why := Nginx(reuse, v); got != c.reuse {
			t.Errorf("%s reuse = %s (%s), want %s", c.v, got, why, c.reuse)
		}
	}
	if st, _ := Nginx(flow, MustV("1.31")); st != Unknown {
		t.Errorf("two-part nginx version judged %s", st)
	}
}

func TestOpenResty(t *testing.T) {
	flow, _ := ByID(Flow)
	reuse, _ := ByID(Reuse)
	for _, c := range []struct {
		v    string
		want Status
		cve  CVE
	}{
		{"1.31.8.1", Vulnerable, flow},
		{"1.31.8.2", Unknown, flow}, // newer than known: may carry a backport
		{"1.27.1.2", Vulnerable, flow},
		{"1.27.1.3", Unknown, flow},
		{"1.31.9.1", Fixed, flow},
		{"1.19.3.2", NotAffected, reuse}, // core 1.19.3 < 1.19.7
		{"1.19.3.2", Vulnerable, flow},
		{"1.19.9.1", Vulnerable, reuse},
		{"1.23.0.1", Unknown, flow}, // core with no known release
		{"1.31.8", Unknown, flow},
	} {
		if got, why := OpenResty(c.cve, MustV(c.v)); got != c.want {
			t.Errorf("OpenResty %s %s = %s (%s), want %s", c.v, c.cve.ID, got, why, c.want)
		}
	}
}

func TestForks(t *testing.T) {
	flow, _ := ByID(Flow)
	reuse, _ := ByID(Reuse)
	if st, _ := Tengine(reuse, MustV("3.2.0"), MustV("1.31.5")); st != Vulnerable {
		t.Errorf("Tengine 3.2.0 = %s", st)
	}
	if st, _ := Tengine(reuse, MustV("2.3.3"), MustV("1.18.0")); st != NotAffected {
		t.Errorf("Tengine 2.3.3 on 1.18.0 reuse = %s", st)
	}
	if st, _ := Tengine(flow, MustV("2.3.3"), MustV("1.18.0")); st != Vulnerable {
		t.Errorf("Tengine 2.3.3 on 1.18.0 flow = %s", st)
	}
	if st, _ := Tengine(flow, MustV("3.3.0"), MustV("1.31.9")); st != Unknown {
		t.Errorf("Tengine 3.3.0 = %s, want unknown (never cleared by its core)", st)
	}
	if st, _ := Tengine(flow, MustV("3.1.0"), nil); st != Unknown {
		t.Errorf("Tengine without core = %s", st)
	}
	if st, _ := Angie(flow, MustV("1.12.4")); st != Vulnerable {
		t.Errorf("Angie 1.12.4 = %s", st)
	}
	if st, _ := Angie(flow, MustV("1.13.0")); st != Unknown {
		t.Errorf("Angie 1.13.0 = %s", st)
	}
}

func TestPlus(t *testing.T) {
	flow, _ := ByID(Flow)
	reuse, _ := ByID(Reuse)
	cases := []struct {
		rel         string
		flow, reuse Status
	}{
		{"37.0.7.0", Vulnerable, Vulnerable},
		{"37.0.7.1", Vulnerable, Fixed},
		{"37.0.8.1", Fixed, Fixed},
		{"37.1.5.0", Vulnerable, Vulnerable},
		{"37.2.0.0", Vulnerable, Vulnerable},
		{"37.2.0.1", Vulnerable, Fixed},
		{"37.3.0.0", Vulnerable, Fixed},
		{"37.3.0.1", Fixed, Fixed},
		{"37.4.0.0", Unknown, Unknown},
		{"r33", Vulnerable, Vulnerable},
		{"r36-p1", Vulnerable, Vulnerable},
		{"r37", Unknown, Unknown},
		{"r37-p3", Unknown, Unknown},
		{"rx", Unknown, Unknown},
		{"36.0.1.0", Unknown, Unknown},
	}
	for _, c := range cases {
		if got, why := Plus(flow, c.rel, MustV("1.27.2")); got != c.flow {
			t.Errorf("Plus %s flow = %s (%s), want %s", c.rel, got, why, c.flow)
		}
		if got, why := Plus(reuse, c.rel, MustV("1.27.2")); got != c.reuse {
			t.Errorf("Plus %s reuse = %s (%s), want %s", c.rel, got, why, c.reuse)
		}
	}
	// Before R33 F5 lists nothing: the core decides.
	if st, _ := Plus(reuse, "r23", MustV("1.19.5")); st != NotAffected {
		t.Errorf("Plus r23 on 1.19.5 = %s", st)
	}
	if st, _ := Plus(reuse, "r30", nil); st != Unknown {
		t.Errorf("Plus r30 without core = %s", st)
	}
}

func TestUpstreamOf(t *testing.T) {
	for in, want := range map[string]string{
		"1:1.22.1-9+deb12u10": "1.22.1", "1.30.6-r0": "1.30.6", "1.31.8-1~trixie": "1.31.8",
		"1.24.0-4.module+el9.4.0+21950+8ebc21e1": "1.24.0", "1.24.0-2ubuntu7.19": "1.24.0",
	} {
		v, err := UpstreamOf(in)
		if err != nil || v.String() != want {
			t.Errorf("UpstreamOf(%q) = %v, %v", in, v, err)
		}
	}
	if _, err := UpstreamOf("1.22.1+dfsg-1"); err == nil {
		t.Error("UpstreamOf accepted a version with a suffix")
	}
}

func TestDistroOf(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"debian", ""}: "debian", {"ubuntu", "debian"}: "ubuntu", {"rocky", "rhel centos fedora"}: "rhel",
		{"linuxmint", "ubuntu debian"}: "ubuntu", {"wolfi", ""}: "", {"alpine", ""}: "alpine",
	} {
		if got := DistroOf(in[0], in[1]); got != want {
			t.Errorf("DistroOf%v = %q, want %q", in, got, want)
		}
	}
}
