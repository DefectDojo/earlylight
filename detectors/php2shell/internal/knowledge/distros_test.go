package knowledge

import (
	"strings"
	"testing"
)

// verdict applies an entry to an installed version the way the scanner does:
// fixed wins when present, otherwise vulnerable_through, otherwise not_affected.
func verdict(t *testing.T, e *Entry, cve, installed string) string {
	t.Helper()
	st, ok := e.CVEs[cve]
	if !ok {
		t.Fatalf("%s %s %s: no state for %s", e.Distro, e.Release, e.Source, cve)
	}
	cmp := Comparators[e.Format]
	switch {
	case st.NotAffected:
		return "fixed"
	case st.Fixed != "":
		n, err := cmp(installed, st.Fixed)
		if err != nil {
			t.Fatal(err)
		}
		if n >= 0 {
			return "fixed"
		}
		return "vulnerable"
	default:
		n, err := cmp(installed, st.VulnerableThrough)
		if err != nil {
			t.Fatal(err)
		}
		if n <= 0 {
			return "vulnerable"
		}
		return "unknown"
	}
}

func TestDistrosLoad(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Entries) < 40 {
		t.Fatalf("only %d entries", len(d.Entries))
	}
	for _, e := range d.Entries {
		for _, ev := range e.Evidence {
			if strings.TrimSpace(ev) == "" {
				t.Errorf("%s %s %s: empty evidence line", e.Distro, e.Release, e.Source)
			}
		}
	}
}

func TestDistrosKeyFacts(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	deb12 := OSRelease{ID: "debian", VersionID: "12", Codename: "bookworm"}
	deb13 := OSRelease{ID: "debian", VersionID: "13", Codename: "trixie"}
	sid := OSRelease{ID: "debian", Codename: "forky"}
	noble := OSRelease{ID: "ubuntu", VersionID: "24.04", Codename: "noble"}
	jammy := OSRelease{ID: "ubuntu", VersionID: "22.04", Codename: "jammy"}
	focal := OSRelease{ID: "ubuntu", VersionID: "20.04", Codename: "focal"}
	stonking := OSRelease{ID: "ubuntu", VersionID: "26.10", Codename: "stonking"}
	resolute := OSRelease{ID: "ubuntu", VersionID: "26.04", Codename: "resolute"}
	alpine322 := OSRelease{ID: "alpine", VersionID: "3.22.6"}
	alpine324 := OSRelease{ID: "alpine", VersionID: "3.24.2"}
	rhel9 := OSRelease{ID: "rhel", VersionID: "9.8"}
	rhel8 := OSRelease{ID: "rhel", VersionID: "8.10"}
	rhel10 := OSRelease{ID: "rhel", VersionID: "10.2"}
	al2023 := OSRelease{ID: "amzn", VersionID: "2023"}
	al2 := OSRelease{ID: "amzn", VersionID: "2"}
	sles157 := OSRelease{ID: "sles", VersionID: "15.7"}
	leap156 := OSRelease{ID: "opensuse-leap", VersionID: "15.6"}

	cases := []struct {
		name                     string
		os                       OSRelease
		format, source, ver, ven string
		want                     string // "vulnerable", "fixed", "unknown", or "nomatch"
	}{
		// Ubuntu: the backported fix keeps the 8.3.6 upstream version.
		{"noble .12", noble, "dpkg", "php8.3", "8.3.6-0ubuntu0.24.04.12", "", "vulnerable"},
		{"noble .13", noble, "dpkg", "php8.3", "8.3.6-0ubuntu0.24.04.13", "", "fixed"},
		{"noble GA", noble, "dpkg", "php8.3", "8.3.6-0maysync1", "", "vulnerable"},
		{"noble sury", noble, "dpkg", "php8.3", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "", "nomatch"},
		{"noble sury old", noble, "dpkg", "php8.3", "8.3.30-1+ubuntu24.04.1+deb.sury.org+1", "", "nomatch"},
		{"noble foreign upstream", noble, "dpkg", "php8.3", "8.3.30-1", "", "nomatch"},
		{"jammy .27", jammy, "dpkg", "php8.1", "8.1.2-1ubuntu2.27", "", "vulnerable"},
		{"jammy .28", jammy, "dpkg", "php8.1", "8.1.2-1ubuntu2.28", "", "fixed"},
		{"jammy sury 8.1", jammy, "dpkg", "php8.1", "8.1.34-1+ubuntu22.04.1+deb.sury.org+1", "", "nomatch"},
		{"focal non-ESM", focal, "dpkg", "php7.4", "7.4.3-4ubuntu2.29", "", "vulnerable"},
		{"focal ESM fixed", focal, "dpkg", "php7.4", "7.4.3-4ubuntu2.29+esm5", "", "fixed"},
		{"focal ESM older", focal, "dpkg", "php7.4", "7.4.3-4ubuntu2.29+esm4", "", "vulnerable"},
		{"stonking 2", stonking, "dpkg", "php8.5", "8.5.9-0ubuntu2", "", "vulnerable"},
		{"stonking 2.1", stonking, "dpkg", "php8.5", "8.5.9-0ubuntu2.1", "", "fixed"},
		{"resolute 1.4", resolute, "dpkg", "php8.5", "8.5.4-0ubuntu1.4", "", "vulnerable"},
		{"resolute 1.5", resolute, "dpkg", "php8.5", "8.5.4-0ubuntu1.5", "", "fixed"},
		{"ubuntu entry not for debian", deb12, "dpkg", "php8.3", "8.3.6-0ubuntu0.24.04.13", "", "nomatch"},

		// Debian.
		{"bookworm 8.2.34", deb12, "dpkg", "php8.2", "8.2.34-1~deb12u1", "", "vulnerable"},
		{"bookworm 8.2.32", deb12, "dpkg", "php8.2", "8.2.32-1~deb12u1", "", "vulnerable"},
		{"bookworm 8.2.35", deb12, "dpkg", "php8.2", "8.2.35-1~deb12u1", "", "fixed"},
		{"bookworm sury", deb12, "dpkg", "php8.2", "8.2.35-1+0~20261021.70+debian12~1.gbp1234ab", "", "nomatch"},
		{"trixie 8.4.26", deb13, "dpkg", "php8.4", "8.4.26-1~deb13u1", "", "vulnerable"},
		{"trixie 8.4.27", deb13, "dpkg", "php8.4", "8.4.27-1~deb13u1", "", "fixed"},
		{"forky 8.4.26-1", sid, "dpkg", "php8.4", "8.4.26-1", "", "vulnerable"},
		{"forky newer", sid, "dpkg", "php8.4", "8.4.27-1", "", "unknown"},

		// Alpine.
		{"alpine 3.22 php83", alpine322, "apk", "php83", "8.3.29-r0", "", "vulnerable"},
		{"alpine 3.22 php83 r1", alpine322, "apk", "php83", "8.3.29-r1", "", "unknown"},
		{"alpine 3.24 php84 old", alpine324, "apk", "php84", "8.4.26-r0", "", "vulnerable"},
		{"alpine 3.24 php84 fixed", alpine324, "apk", "php84", "8.4.27-r0", "", "fixed"},

		// Red Hat (UBI), vendor-gated.
		{"rhel9 php:8.2", rhel9, "rpm", "php", "8.2.33-1.module+el9.8.0+24630+45254c6a", "Red Hat, Inc.", "vulnerable"},
		{"rhel9 base", rhel9, "rpm", "php", "8.0.30-8.el9_8", "Red Hat, Inc.", "vulnerable"},
		{"rhel9 remi", rhel9, "rpm", "php", "8.2.33-1.el9.remi", "Remi's RPM repository <https://rpms.remirepo.net/>", "nomatch"},
		{"rhel9 module wrong vendor", rhel9, "rpm", "php", "8.2.33-1.module+el9.8.0+24630+45254c6a", "Rocky Enterprise Software Foundation", "nomatch"},
		{"rhel8 php:7.4", rhel8, "rpm", "php", "7.4.33-6.module+el8.10.0+24605+5caacdec", "Red Hat, Inc.", "vulnerable"},
		{"rhel10 php", rhel10, "rpm", "php", "8.3.33-1.el10_2", "Red Hat, Inc.", "vulnerable"},

		// Amazon Linux.
		{"al2023 php8.3", al2023, "rpm", "php8.3", "8.3.35-1.amzn2023.0.1", "Amazon Linux", "vulnerable"},
		{"al2023 php8.3 newer", al2023, "rpm", "php8.3", "8.3.36-1.amzn2023.0.1", "Amazon Linux", "unknown"},
		{"al2 extra php8.2", al2, "rpm", "php", "8.2.34-1.amzn2.0.1", "Amazon Linux", "vulnerable"},
		{"al2 core php", al2, "rpm", "php", "5.4.16-46.amzn2.0.7", "Amazon Linux", "vulnerable"},

		// SUSE.
		{"sles 15 sp7", sles157, "rpm", "php8", "8.3.35-150700.3.21.1", "SUSE LLC <https://www.suse.com/>", "vulnerable"},
		{"sles 15 sp7 QA build", sles157, "rpm", "php8", "8.3.36-150700.3.24.1", "SUSE LLC <https://www.suse.com/>", "unknown"},
		{"leap 15.6 php7", leap156, "rpm", "php7", "7.4.33-150400.4.55.1", "SUSE LLC <https://www.suse.com/>", "vulnerable"},
		{"leap 15.6 php8 has no entry", leap156, "rpm", "php8", "8.2.30-150600.3.25.1", "SUSE LLC <https://www.suse.com/>", "nomatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			es := d.Lookup(c.os, c.format, c.source, c.ver, c.ven)
			if c.want == "nomatch" {
				if len(es) != 0 {
					t.Fatalf("want no entry, got %s %s %s", es[0].Distro, es[0].Release, es[0].VersionPattern)
				}
				return
			}
			if len(es) != 1 {
				t.Fatalf("want exactly one entry, got %d", len(es))
			}
			for _, id := range CVEIDs() {
				if got := verdict(t, es[0], id, c.ver); got != c.want {
					t.Errorf("%s: got %s, want %s", id, got, c.want)
				}
			}
		})
	}
}

// Every version an entry names must match only that entry: overlapping
// patterns would make the scanner report a data error.
func TestDistrosNoOverlap(t *testing.T) {
	d, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := range d.Entries {
		e := &d.Entries[i]
		for _, st := range e.CVEs {
			for _, v := range []string{st.Fixed, st.VulnerableThrough} {
				if v == "" {
					continue
				}
				for _, id := range e.OSIDs {
					os := OSRelease{ID: id, VersionID: e.Release}
					if e.Codename != "" {
						os = OSRelease{ID: id, Codename: e.Codename}
					}
					if n := len(d.Lookup(os, e.Format, e.Source, v, e.Vendor+" vendor")); n != 1 {
						t.Errorf("%s %s %s %s: %d entries match", e.Distro, e.Release, e.Source, v, n)
					}
				}
			}
		}
	}
}
