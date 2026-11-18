package pkgdb

import "testing"

func TestCompareDpkg(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.22.1-9+deb12u10", "1.22.1-9+deb12u9", 1},
		{"1.22.1-9+deb12u9", "1.22.1-9+deb12u10", -1},
		{"1.22.1-9", "1.22.1-9+deb12u1", -1},
		{"1.30.6-3", "1.30.6-3", 0},
		{"1:1.0", "2.0", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.24.0-2ubuntu7.19", "1.24.0-2ubuntu7.9", 1},
		{"1.24.0-2ubuntu7", "1.24.0-2ubuntu7.1", -1},
		{"1.31.8-1~trixie", "1.31.9-1~trixie", -1},
		{"1.0a", "1.0", 1},
		{"1.0-0", "1.0", 0},
		{"1.00", "1.0", 0},
	}
	for _, c := range cases {
		if got := CompareDpkg(c.a, c.b); sign(got) != c.want {
			t.Errorf("CompareDpkg(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareAPK(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.30.6-r1", "1.30.6-r0", 1},
		{"1.30.6-r0", "1.30.7-r0", -1},
		{"1.28.3-r7", "1.28.3-r10", -1},
		{"1.0_rc1", "1.0", -1},
		{"1.0_p1", "1.0", 1},
		{"1.0a", "1.0", 1},
		{"1.0", "1.0.1", -1},
		{"1.30.6-r1", "1.30.6-r1", 0},
	}
	for _, c := range cases {
		got, ok := CompareAPK(c.a, c.b)
		if !ok || sign(got) != c.want {
			t.Errorf("CompareAPK(%q, %q) = %d %v, want %d", c.a, c.b, got, ok, c.want)
		}
	}
	for _, bad := range []string{"", "1..2", "x", "1.0-rx", "1.0_zz", "1.0ab"} {
		if _, ok := CompareAPK(bad, "1.0"); ok {
			t.Errorf("CompareAPK(%q) accepted", bad)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestDpkgStatus(t *testing.T) {
	st := DpkgStatus([]byte(`Package: nginx
Status: install ok installed
Maintainer: Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>
Version: 1.22.1-9+deb12u10
Description: x
 continued: line

Package: nginx-common
Status: deinstall ok config-files
Version: 1.22.1-9+deb12u9

Package: libnginx-mod-http-geoip
Status: install ok installed
Source: nginx (1.22.1-9+deb12u10)
Version: 1.22.1-9+deb12u10
`))
	if p := st["nginx"]; p.Version != "1.22.1-9+deb12u10" || p.Source != "nginx" || p.Manager != "dpkg" {
		t.Errorf("nginx %+v", p)
	}
	if _, ok := st["nginx-common"]; ok {
		t.Error("a removed package was read as installed")
	}
	if p := st["libnginx-mod-http-geoip"]; p.Source != "nginx" {
		t.Errorf("source %+v", p)
	}
	if DpkgListName("/var/lib/dpkg/info/nginx-core:amd64.list") != "nginx-core" {
		t.Error("list name")
	}
	if !ListHas([]byte("/.\n/usr\n/usr/sbin/nginx\n"), "/usr/sbin/nginx") || ListHas([]byte("/usr/sbin/nginx-debug\n"), "/usr/sbin/nginx") {
		t.Error("ListHas")
	}
}

func TestAPKOwners(t *testing.T) {
	own := APKOwners([]byte(`C:Q1abc
P:nginx
V:1.30.6-r0
o:nginx
m:Jakub Jirutka <jakub@jirutka.cz>
F:usr/sbin
R:nginx
F:etc/nginx
R:nginx.conf

P:musl
V:1.2.5-r0
F:lib
R:ld-musl-x86_64.so.1
`))
	p, ok := own["/usr/sbin/nginx"]
	if !ok || p.Name != "nginx" || p.Version != "1.30.6-r0" || p.Manager != "apk" {
		t.Errorf("%+v", p)
	}
	if own["/lib/ld-musl-x86_64.so.1"].Name != "musl" || own["/etc/nginx/nginx.conf"].Name != "nginx" {
		t.Error("owners")
	}
}
