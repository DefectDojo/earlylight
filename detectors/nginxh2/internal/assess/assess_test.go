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
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.30.6"))}, Source: mem{"/etc/nginx/nginx.conf": "http { server { listen 80; } }"},
		Command: []string{"nginx", "-g", "daemon off;"}, Starts: okStarts}))
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
		Command: []string{"/docker-entrypoint.sh", "nginx", "-c", "/app/nginx.conf", "-g", "daemon off;"}, CommandFrom: "the container command", Starts: okStarts,
		Launcher: func(w string) (bool, string) { return w == "/docker-entrypoint.sh", "" }}
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
	if m, _, how, _ := configFor(b, Input{}); m != "/usr/local/nginx/conf/nginx.conf" || how != "nginx's default" {
		t.Errorf("%s %s", m, how)
	}
	if _, _, unsure := startArgs([]string{"sh", "-c", "echo"}, nil); unsure == "" {
		t.Error("a command without nginx")
	}
}

func TestConfigForPrefixAndShell(t *testing.T) {
	or := ngxtest.Default("x")
	or.Line, or.ConfPath, or.Configure = "openresty/1.31.8.1", "conf/nginx.conf", "--prefix=/usr/local/openresty/nginx --with-http_v2_module"
	or.Extra = []string{"  -p prefix     : set prefix path (default: /usr/local/openresty/nginx/)"}
	b := bin(t, or)
	if m, _, _, _ := configFor(b, Input{}); m != "/usr/local/openresty/nginx/conf/nginx.conf" {
		t.Errorf("default: %s", m)
	}
	if m, _, how, _ := configFor(b, Input{Command: []string{"openresty", "-p", "/app/", "-g", "daemon off;"}}); m != "/app/conf/nginx.conf" || !strings.Contains(how, "-p") {
		t.Errorf("-p: %s %s", m, how)
	}
	// An absolute compiled-in path does not move with -p.
	if m, _, _, _ := configFor(bin(t, ngxtest.Default("1.31.8")), Input{Command: []string{"nginx", "-p", "/app/"}}); m != "/etc/nginx/nginx.conf" {
		t.Errorf("absolute: %s", m)
	}
	// A shell start is not read (round 5): unsure.
	if _, _, _, unsure := configFor(bin(t, ngxtest.Default("1.31.8")), Input{Command: []string{"/bin/sh", "-c", "exec nginx -c '/app/nginx.conf' -g 'daemon off;'"}, Starts: okStarts}); unsure == "" {
		t.Error("sh -c was read")
	}
	m, _, how, unsure := configFor(bin(t, ngxtest.Default("1.31.8")), Input{Command: []string{"nginx", "-c", "/app/nginx.conf", "-g", "daemon off;"}, Starts: okStarts})
	if m != "/app/nginx.conf" || unsure != "" || !strings.Contains(how, "-c") {
		t.Errorf("-c: %s %s %q", m, how, unsure)
	}
	// Something that writes the configuration first: unsure.
	if _, _, _, unsure := configFor(bin(t, ngxtest.Default("1.31.8")), Input{Command: []string{"/bin/sh", "-c", "envsubst < /t > /etc/nginx/x.conf && exec nginx"}}); unsure == "" {
		t.Error("envsubst before nginx was not noted")
	}
	if _, _, _, unsure := configFor(bin(t, ngxtest.Default("1.31.8")), Input{Command: []string{"sh", "-c", "nginx -c $CONF"}}); unsure == "" {
		t.Error("a variable in the shell text was not noted")
	}
	// Unsure: a weaker answer becomes unknown.
	fs := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.8"))}, Source: mem{"/etc/nginx/nginx.conf": "http { server { listen 80; } }"},
		Command: []string{"sh", "-c", "nginx -c $CONF"}}))
	if f := fs[knowledge.Flow]; f.State != conf.Unknown {
		t.Errorf("unsure: %+v", f.State)
	}
}

// Review 2, finding 2: exposure is "not exposed" only when the command
// that starts nginx, and everything it loads, were read.
func TestR2StartCommand(t *testing.T) {
	off := mem{"/etc/nginx/nginx.conf": "http { server { listen 80; } }", "/x.conf": "http { server { listen 80; } }",
		"/etc/nginx/h2.conf": "http { server { listen 443 ssl http2; } }"}
	// The launcher stands for the adapter's content check: only
	// /docker-entrypoint.sh is the official entrypoint here.
	trusted := func(w string) (bool, string) { return w == "/docker-entrypoint.sh", "not the official entrypoint" }
	run := func(cmd []string) conf.State {
		return byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.8"))}, Source: off, Command: cmd, Starts: okStarts, Launcher: trusted}))[knowledge.Flow].State
	}
	for _, c := range []struct {
		name string
		cmd  []string
		want conf.State
	}{
		{"official", []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}, conf.NotExposed},
		{"tini", []string{"/sbin/tini", "--", "nginx", "-g", "daemon off;"}, conf.Unknown},
		{"no command", nil, conf.Unknown},
		{"s6 init", []string{"/init"}, conf.Unknown},
		{"start script", []string{"/start.sh"}, conf.Unknown},
		{"forego", []string{"forego", "start", "-r"}, conf.Unknown},
		{"supervisord", []string{"supervisord", "-c", "/etc/supervisord.conf"}, conf.Unknown},
		{"wrapper then nginx", []string{"/usr/local/bin/wrap", "nginx"}, conf.Unknown},
		{"sed in sh -c", []string{"sh", "-c", "sed -i 's/listen 80;/listen 443 ssl http2;/' /etc/nginx/nginx.conf && nginx -g 'daemon off;'"}, conf.Unknown},
		{"exec in sh -c", []string{"sh", "-c", "exec nginx -g 'daemon off;'"}, conf.Unknown},
		{"continuation", []string{"sh", "-c", "exec nginx \\\n -c /etc/nginx/h2.conf"}, conf.Unknown},
		{"-qc", []string{"nginx", "-qc", "/etc/nginx/h2.conf"}, conf.Exposed},
		{"-g include", []string{"nginx", "-c", "/x.conf", "-g", "include /etc/nginx/h2.conf;"}, conf.Exposed},
	} {
		if got := run(c.cmd); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// No launcher check at all: any wrapper is unknown.
	if got := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.8"))}, Source: off, Command: []string{"/docker-entrypoint.sh", "nginx"}}))[knowledge.Flow].State; got != conf.Unknown {
		t.Errorf("an entrypoint with no launcher check: %s", got)
	}
}

// Review 2, finding 6: a build is cleared as built without HTTP/2 only
// when its configure arguments were read whole and it has a module list;
// HTTP/2 on a core older than 1.9.5 is judged by the code where known.
func TestR6NoHTTP2Evidence(t *testing.T) {
	statuses := func(b ngxtest.Build) map[string]knowledge.Status {
		out := map[string]knowledge.Status{}
		for _, f := range Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}}) {
			out[f.CVE] = f.Status
		}
		return out
	}
	// 1.9.7: no module list; 4,451 bytes of configure arguments with the
	// HTTP/2 flag last.
	long := ngxtest.Build{Line: "nginx/1.9.7", Configure: "--prefix=/x " + strings.Repeat("--with-cc-opt=-Dx ", 246) + "--with-http_v2_module"}
	if st := statuses(long)[knowledge.Flow]; st == knowledge.NotAffected {
		t.Errorf("truncated configure arguments cleared 1.9.7: %s", st)
	}
	or := long
	or.Line = "openresty/1.9.7.5"
	if st := statuses(or)[knowledge.Flow]; st == knowledge.NotAffected {
		t.Errorf("truncated configure arguments cleared OpenResty 1.9.7.5: %s", st)
	}
	// No module list, short configure arguments without the flag: not
	// cleared either (the module list is the second witness).
	if st := statuses(ngxtest.Build{Line: "nginx/1.9.7", Configure: "--prefix=/x"})[knowledge.Flow]; st == knowledge.NotAffected {
		t.Errorf("no module list cleared 1.9.7: %s", st)
	}
	// Both witnesses read, neither has HTTP/2: not affected.
	both := ngxtest.Default("1.31.8")
	both.Configure, both.Modules = "--prefix=/etc/nginx", []string{"ngx_core_module", "ngx_http_module"}
	if st := statuses(both)[knowledge.Flow]; st != knowledge.NotAffected {
		t.Errorf("no HTTP/2 with both witnesses: %s", st)
	}
	// HTTP/2 on a core before 1.9.5: a vendor backport, not cleared.
	plus := ngxtest.Default("1.9.4")
	plus.Line = "nginx/1.9.4 (nginx-plus-r7)"
	if st := statuses(plus); st[knowledge.Flow] != knowledge.Unknown || st[knowledge.Reuse] != knowledge.Unknown {
		t.Errorf("Plus r7 with HTTP/2 on 1.9.4: %v", st)
	}
	// Tengine 2.2.2 in its old one-line form, on core 1.8.1, with HTTP/2:
	// the unfixed flow-control code; not the 2021 reuse change.
	te := ngxtest.Default("1.8.1")
	te.Line, te.Tengine = "", "Tengine/2.2.2 (nginx/1.8.1)"
	if st := statuses(te); st[knowledge.Flow] != knowledge.Vulnerable || st[knowledge.Reuse] != knowledge.NotAffected {
		t.Errorf("Tengine 2.2.2: %v", st)
	}
	te.Tengine = "Tengine/2.0.3 (nginx/1.4.6)"
	if st := statuses(te); st[knowledge.Flow] != knowledge.Unknown {
		t.Errorf("Tengine 2.0.3 with HTTP/2: %v", st)
	}
}

// R16: a fixed verdict rests on the version; the message says so.
func TestR16FixedWording(t *testing.T) {
	f := byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.9"))}, Source: mem{}}))[knowledge.Flow]
	if strings.Contains(f.Message, "has the fix for") || !strings.Contains(f.Message, "version") {
		t.Errorf("%s", f.Message)
	}
}

// Verification 5: an older core whose HTTP/2 witness is cut or missing is
// unknown, never not affected.
func TestV5OldCoreWitness(t *testing.T) {
	statuses := func(b ngxtest.Build) map[string]knowledge.Status {
		out := map[string]knowledge.Status{}
		for _, f := range Run(Input{Binaries: []*ngx.Binary{bin(t, b)}, Source: mem{}}) {
			out[f.CVE] = f.Status
		}
		return out
	}
	cut := "--prefix=/x " + strings.Repeat("--with-cc-opt=-Dx ", 246) + "--with-http_v2_module"
	for name, b := range map[string]ngxtest.Build{
		"Tengine 2.2.2, cut arguments":  {Tengine: "Tengine/2.2.2 (nginx/1.8.1)", Configure: cut},
		"Tengine 2.2.2, no module list": {Tengine: "Tengine/2.2.2 (nginx/1.8.1)", Configure: "--prefix=/x"},
		"Plus R7, cut arguments":        {Line: "nginx/1.9.4 (nginx-plus-r7)", Configure: cut},
	} {
		for cve, st := range statuses(b) {
			if st == knowledge.NotAffected {
				t.Errorf("%s: %s not affected", name, cve)
			}
		}
	}
	// Plain nginx before 1.9.5 has no HTTP/2 in its source: not affected
	// by its version.
	if st := statuses(ngxtest.Build{Line: "nginx/1.8.1", Configure: cut}); st[knowledge.Flow] != knowledge.NotAffected {
		t.Errorf("nginx 1.8.1: %v", st)
	}
}

// Verification 6, and round 5: a shell start is never read (it is trusted
// by nothing the scan can check); a command that only tests nginx is not
// the start.
func TestV6ShellTestCall(t *testing.T) {
	off := mem{"/etc/nginx/nginx.conf": "http { server { listen 80; } }"}
	run := func(cmd ...string) conf.State {
		return byCVE(Run(Input{Binaries: []*ngx.Binary{bin(t, ngxtest.Default("1.31.8"))}, Source: off, Command: cmd, Starts: okStarts}))[knowledge.Flow].State
	}
	if got := run("sh", "-c", "nginx -t && exec nginx -g 'daemon off;'"); got != conf.Unknown {
		t.Errorf("a shell start: %s", got)
	}
	if got := run("nginx", "-T"); got != conf.Unknown {
		t.Errorf("a command that only tests: %s", got)
	}
	if got := run("nginx", "-g", "daemon off;"); got != conf.NotExposed {
		t.Errorf("nginx itself: %s", got)
	}
}

// okStarts stands for the adapter's check that the word starts the binary
// judged.
func okStarts(string, string) (bool, string) { return true, "" }
