package assess

import (
	"path"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/conf"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/pkgdb"
)

type mem map[string]string

func (m mem) Read(p string) ([]byte, bool, string) {
	s, ok := m[p]
	return []byte(s), ok, "missing"
}

func (m mem) Glob(pattern string) ([]string, bool) {
	var out []string
	for p := range m {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	return out, true
}

func bin(t *testing.T, b ngxtest.Build) *ngx.Binary {
	t.Helper()
	x, ok := ngx.Inspect("/usr/sbin/nginx", b.Bytes())
	if !ok {
		t.Fatal("not an nginx binary")
	}
	return x
}

func byCVE(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.CVE] = f
	}
	return out
}

const h2conf = "http { server { listen 443 ssl http2; location / { proxy_pass http://u; } } }"

func TestRunExposed(t *testing.T) {
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.8"))}, Source: mem{"/etc/nginx/nginx.conf": h2conf}}))
	for _, id := range []string{knowledge.Flow, knowledge.Reuse} {
		f := fs[id]
		if f.Status != knowledge.Vulnerable || f.State != conf.Exposed || f.Severity != "critical" || f.Facts["http2"] != "on" {
			t.Errorf("%s: %+v", id, f)
		}
		if !strings.Contains(f.Fix, "1.31.9") || !strings.Contains(f.Fix, "it is not a fix") {
			t.Errorf("%s fix: %s", id, f.Fix)
		}
	}
	if fs[knowledge.Flow].Kind != KindFlow || fs[knowledge.Reuse].Kind != KindReuse {
		t.Error("kinds")
	}
}

func TestRunNotExposedStaysVulnerable(t *testing.T) {
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.30.6"))}, Source: mem{"/etc/nginx/nginx.conf": "http { server { listen 80; } }"}}))
	f := fs[knowledge.Flow]
	if f.Status != knowledge.Vulnerable || f.State != conf.NotExposed || f.Severity != "medium" || !strings.Contains(f.Message, "still needs the update") {
		t.Errorf("%+v", f)
	}
	if strings.Contains(f.Fix, "it is not a fix") {
		t.Error("the interim mitigation was offered where HTTP/2 is already off")
	}
	// No configuration at all: unknown exposure, still vulnerable.
	fs = byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.30.6"))}, Source: mem{}}))
	if f := fs[knowledge.Flow]; f.Status != knowledge.Vulnerable || f.State != conf.Unknown || f.Severity != "high" {
		t.Errorf("no config: %+v", f)
	}
}

func TestRunSplitsCVEs(t *testing.T) {
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.18.0"))}, Source: mem{}}))
	if fs[knowledge.Flow].Status != knowledge.Vulnerable || fs[knowledge.Reuse].Status != knowledge.NotAffected {
		t.Errorf("1.18.0: flow %s reuse %s", fs[knowledge.Flow].Status, fs[knowledge.Reuse].Status)
	}
}

func TestRunNoHTTP2(t *testing.T) {
	b := ngxtest.Default("1.31.8")
	b.Configure, b.Modules = "--prefix=/etc/nginx --with-http_ssl_module", []string{"ngx_core_module"}
	fs := Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}})
	for _, f := range fs {
		if f.Status != knowledge.NotAffected || f.Fix != "" {
			t.Errorf("%+v", f)
		}
	}
	// A hidden version is never cleared, HTTP/2 or not.
	b.Line, b.Extra = "", nil
	for _, f := range Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}}) {
		if f.Status != knowledge.Unknown {
			t.Errorf("hidden: %+v", f)
		}
	}
}

func TestRunConflictUnknown(t *testing.T) {
	b := ngxtest.Default("1.31.9")
	b.Extra = []string{"Server: nginx/1.31.8\r\n"}
	for _, f := range Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}}) {
		if f.Status != knowledge.Unknown {
			t.Errorf("%+v", f)
		}
	}
}

func TestRunCommandConfig(t *testing.T) {
	src := mem{"/etc/nginx/nginx.conf": "http { server { listen 80; } }", "/app/nginx.conf": h2conf}
	in := Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.8"))}, Source: src,
		Command: []string{"/docker-entrypoint.sh", "nginx", "-c", "/app/nginx.conf", "-g", "daemon off;"}}
	f := byCVE(Run(in))[knowledge.Flow]
	if f.State != conf.Exposed || f.Facts["config"] != "/app/nginx.conf" || f.Facts["config_from"] != "the container command's -c" {
		t.Errorf("%+v", f.Facts)
	}
	in.Command = []string{"nginx", "-p", "/app/", "-cnginx.conf"}
	if f := byCVE(Run(in))[knowledge.Flow]; f.Facts["config"] != "/app/nginx.conf" {
		t.Errorf("-p/-c: %+v", f.Facts)
	}
}

func TestRunIngress(t *testing.T) {
	b := ngxtest.Default("1.27.1")
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{"/etc/nginx/nginx.conf": "# placeholder"}, Ingress: true}))
	if f := fs[knowledge.Reuse]; f.State != conf.Exposed || f.Status != knowledge.Vulnerable {
		t.Errorf("%+v", f)
	}
}

func TestBackport(t *testing.T) {
	saved := knowledge.Backports
	defer func() { knowledge.Backports = saved }()
	knowledge.Backports = []knowledge.Backport{{Distro: "debian", Release: "12", Package: "nginx", Fixed: "1.22.1-9+deb12u11", CVEs: []string{knowledge.Flow}, Advisory: "DSA-test"}}
	b := ngxtest.Default("1.22.1")
	owner := func(v, maint string) func(string) *pkgdb.Package {
		return func(string) *pkgdb.Package {
			return &pkgdb.Package{Manager: "dpkg", Name: "nginx", Source: "nginx", Version: v, Maintainer: maint}
		}
	}
	run := func(v, maint, distro, rel string) map[string]Finding {
		return byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}, Owner: owner(v, maint), Distro: distro, Release: rel}))
	}
	fs := run("1.22.1-9+deb12u11", "Debian Nginx Maintainers", "debian", "12")
	if fs[knowledge.Flow].Status != knowledge.Fixed || fs[knowledge.Reuse].Status != knowledge.Vulnerable {
		t.Errorf("backport: flow %s reuse %s", fs[knowledge.Flow].Status, fs[knowledge.Reuse].Status)
	}
	for _, c := range []struct{ v, maint, distro, rel, why string }{
		{"1.22.1-9+deb12u10", "Debian", "debian", "12", "older package"},
		{"1.22.1-9+deb12u11", "Debian", "debian", "13", "other release"},
		{"1.22.1-9+deb12u11", "Debian", "ubuntu", "12", "other distro"},
		{"1.22.1-9+deb12u11", "NGINX Packaging <nginx-packaging@f5.com>", "debian", "12", "nginx.org package"},
		{"1.24.0-9+deb12u11", "Debian", "debian", "12", "package not the binary's version"},
	} {
		if st := run(c.v, c.maint, c.distro, c.rel)[knowledge.Flow].Status; st != knowledge.Vulnerable {
			t.Errorf("%s: %s", c.why, st)
		}
	}
	// No owner: the table cannot apply.
	fs = byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}, Distro: "debian", Release: "12"}))
	if fs[knowledge.Flow].Status != knowledge.Vulnerable {
		t.Error("cleared without a package owner")
	}
}

func TestDistroFixText(t *testing.T) {
	b := ngxtest.Default("1.30.6")
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}, Distro: "alpine", Release: "3.24",
		Owner: func(string) *pkgdb.Package {
			return &pkgdb.Package{Manager: "apk", Name: "nginx", Version: "1.30.6-r0", Maintainer: "Jakub Jirutka"}
		}}))
	if f := fs[knowledge.Flow]; !strings.Contains(f.Fix, "apk upgrade nginx (1.30.7-r0 on Alpine 3.24") || f.Facts["package"] != "nginx 1.30.6-r0" {
		t.Errorf("%+v", f)
	}
	fs = byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.28.3"))}, Source: mem{}, Distro: "alpine", Release: "3.23",
		Owner: func(string) *pkgdb.Package {
			return &pkgdb.Package{Manager: "apk", Name: "nginx", Version: "1.28.3-r7", Maintainer: "Jakub Jirutka"}
		}}))
	if f := fs[knowledge.Flow]; !strings.Contains(f.Fix, "Alpine 3.23 had no fixed nginx package") {
		t.Errorf("3.23: %s", f.Fix)
	}
}

func TestConfigFor(t *testing.T) {
	b := &ngx.Binary{ConfPath: "", Prefix: ""}
	if m, _, how := configFor(b, nil); m != "/usr/local/nginx/conf/nginx.conf" || how != "nginx's default" {
		t.Errorf("%s %s", m, how)
	}
	if _, ok := nginxArgs([]string{"sh", "-c", "echo"}); ok {
		t.Error("a command without nginx")
	}
}
