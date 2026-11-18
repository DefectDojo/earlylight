package nginxh2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/internal/engine"
)

func write(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	for p, b := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func scanFS(t *testing.T, files map[string][]byte, opts engine.Options) *engine.Target {
	t.Helper()
	root := t.TempDir()
	write(t, root, files)
	opts.AsRoot = true
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, opts)
	if tg.Error != "" {
		t.Fatal(tg.Error)
	}
	return tg
}

func find(tg *engine.Target, kind, p string) *engine.Finding {
	for i := range tg.Findings {
		if tg.Findings[i].Kind == kind && tg.Findings[i].Path == p {
			return &tg.Findings[i]
		}
	}
	return nil
}

func TestScanDebianLayout(t *testing.T) {
	tg := scanFS(t, map[string][]byte{
		"/usr/sbin/nginx":                   ngxtest.Default("1.22.1").Bytes(),
		"/etc/nginx/nginx.conf":             []byte("events {} http { include /etc/nginx/sites-enabled/*; }"),
		"/etc/nginx/sites-enabled/default":  []byte("server { listen 443 ssl http2; location / { proxy_pass http://app; } }"),
		"/etc/os-release":                   []byte("ID=debian\nVERSION_ID=\"12\"\n"),
		"/var/lib/dpkg/status":              []byte("Package: nginx\nStatus: install ok installed\nMaintainer: Debian Nginx Maintainers\nVersion: 1.22.1-9+deb12u10\n"),
		"/var/lib/dpkg/info/nginx.list":     []byte("/usr/sbin/nginx\n"),
		"/usr/share/nginx/html/index.html":  []byte("<html>"),
		"/usr/lib/nginx/modules/ngx_x.so":   []byte("\x7fELF\x02\x01ngx_core_module\x00"),
		"/srv/app/static/big.conf.bak":      []byte("listen 443 ssl http2;"),
		"/etc/nginx/sites-available/unused": []byte("server { listen 8443 ssl http2; }"),
	}, engine.Options{})
	for _, k := range []string{KindFlow, KindReuse} {
		f := find(tg, k, "/usr/sbin/nginx")
		if f == nil {
			t.Fatalf("%s missing: %+v", k, tg.Findings)
		}
		if f.Verdict != engine.Vulnerable || f.Facts["exposure"] != "exposed" || f.Facts["package"] != "nginx 1.22.1-9+deb12u10" || f.Facts["distro"] != "debian 12" || f.Severity != "critical" {
			t.Errorf("%s: %+v", k, f)
		}
		if len(f.CVEs) != 1 || f.CVEs[0].Verdict != engine.Vulnerable {
			t.Errorf("%s CVEs: %+v", k, f.CVEs)
		}
	}
	if n := len(tg.Findings); n != 2 {
		t.Errorf("%d findings, want 2 (the dynamic module is not a server): %+v", n, tg.Findings)
	}
}

func TestScanFixedAndOff(t *testing.T) {
	tg := scanFS(t, map[string][]byte{
		"/usr/sbin/nginx":                       ngxtest.Default("1.31.9").Bytes(),
		"/opt/old/sbin/nginx":                   ngxtest.Default("1.30.6").Bytes(),
		"/etc/nginx/nginx.conf":                 []byte("http { include conf.d/*.conf; }"),
		"/etc/nginx/conf.d/a.conf":              []byte("server { listen 80; }"),
		"/etc/systemd/system/old-nginx.service": []byte("[Service]\nExecStart=/opt/old/sbin/nginx -g 'daemon on;'\n"),
	}, engine.Options{})
	if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Verdict != engine.Fixed || f.Reason == "" {
		t.Errorf("fixed: %+v", f)
	}
	f := find(tg, KindFlow, "/opt/old/sbin/nginx")
	if f == nil || f.Verdict != engine.Vulnerable || f.Facts["exposure"] != "not-exposed" || f.Facts["http2"] != "off" {
		t.Errorf("off: %+v", f)
	}
}

func TestScanUnreadInclude(t *testing.T) {
	tg := scanFS(t, map[string][]byte{
		"/usr/sbin/nginx":       ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf": []byte("http { include /srv/vhosts/*; server { listen 80; } }"),
		"/srv/vhosts/site":      []byte("server { listen 443 ssl http2; }"),
	}, engine.Options{})
	f := find(tg, KindFlow, "/usr/sbin/nginx")
	if f == nil || f.Verdict != engine.Vulnerable || f.Facts["exposure"] != "unknown" {
		t.Errorf("a glob the scan does not read whole must leave exposure unknown: %+v", f)
	}
}

func TestScanSymlinkedConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string][]byte{
		"/usr/sbin/nginx":                      ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf":                []byte("http { include /etc/nginx/sites-enabled/*; }"),
		"/etc/nginx/sites-available/site.conf": []byte("server { listen 443 ssl http2; }"),
	})
	if err := os.MkdirAll(filepath.Join(root, "etc/nginx/sites-enabled"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../sites-available/site.conf", filepath.Join(root, "etc/nginx/sites-enabled/site.conf")); err != nil {
		t.Fatal(err)
	}
	// A link loop must not hang or crash the scan.
	if err := os.Symlink("loop.conf", filepath.Join(root, "etc/nginx/loop.conf")); err != nil {
		t.Fatal(err)
	}
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
	f := find(tg, KindFlow, "/usr/sbin/nginx")
	if f == nil || f.Facts["exposure"] != "exposed" {
		t.Errorf("a site enabled through a symbolic link: %+v", f)
	}
}

func TestScanBelowRoot(t *testing.T) {
	// Scanning /usr/sbin of a system root still reads its configuration
	// and package database from disk.
	root := t.TempDir()
	write(t, root, map[string][]byte{
		"/usr/sbin/nginx":          ngxtest.Default("1.30.6").Bytes(),
		"/etc/nginx/nginx.conf":    []byte("http { include /etc/nginx/conf.d/*.conf; }"),
		"/etc/nginx/conf.d/s.conf": []byte("server { listen 443 ssl; http2 on; }"),
		"/etc/os-release":          []byte("ID=alpine\nVERSION_ID=3.24.4\n"),
		"/etc/alpine-release":      []byte("3.24.4\n"),
		"/lib/apk/db/installed":    []byte("P:nginx\nV:1.30.6-r0\nm:Jakub Jirutka\nF:usr/sbin\nR:nginx\n\n"),
	})
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, filepath.Join(root, "usr/sbin"), engine.Options{SystemRoot: root})
	if tg.Error != "" {
		t.Fatal(tg.Error)
	}
	f := find(tg, KindFlow, "/usr/sbin/nginx")
	if f == nil || f.Facts["exposure"] != "exposed" || f.Facts["package"] != "nginx 1.30.6-r0" || f.Facts["distro"] != "alpine 3.24" {
		t.Errorf("%+v", f)
	}
	if !strings.Contains(f.Fix, "apk upgrade nginx") {
		t.Errorf("fix: %s", f.Fix)
	}
}

func TestTemplates(t *testing.T) {
	s := &confSource{kept: map[string][]byte{
		"/etc/nginx/templates/default.conf.template": []byte("server { listen ${PORT} ssl http2; }"),
		"/srv/t/x.conf.tpl":                          []byte("server { listen 1 ssl http2; }"),
	}}
	s.templates(nil)
	if _, ok, _ := s.Read("/etc/nginx/conf.d/default.conf"); !ok {
		t.Error("default template not mapped")
	}
	s2 := &confSource{kept: s.kept}
	s2.templates([]string{"NGINX_ENVSUBST_TEMPLATE_DIR=/srv/t", "NGINX_ENVSUBST_TEMPLATE_SUFFIX=.tpl", "NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx/http.d"})
	if _, ok, _ := s2.Read("/etc/nginx/http.d/x.conf"); !ok {
		t.Error("template settings from the environment not used")
	}
	if ms, _ := s2.Glob("/etc/nginx/http.d/*.conf"); len(ms) != 1 {
		t.Errorf("glob over templates: %v", ms)
	}
}

func TestKeepConf(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/nginx/mime.types": true, "/etc/nginx/sites-enabled/default": true, "/app/site.conf": true,
		"/usr/local/openresty/lualib/resty/core.lua": false, "/usr/local/openresty/luajit/lib/libluajit-5.1.a": false,
		"/usr/local/openresty/nginx/conf/mime.types": true, "/opt/nginx/vhosts/example": true, "/usr/bin/python3": false,
		"/srv/nginx/html/index.html": false,
	} {
		if got := keepConf(p); got != want {
			t.Errorf("keepConf(%s) = %v", p, got)
		}
	}
	for p, want := range map[string]bool{
		"/etc/nginx/conf.d/*.conf": true, "/etc/nginx/sites-enabled/*": true, "/srv/vhosts/*": false, "/srv/vhosts/*.conf": true,
		"/opt/nginx/vhosts/*": false,
	} {
		if got := keptByAll(p); got != want {
			t.Errorf("keptByAll(%s) = %v", p, got)
		}
	}
}

func TestManifestLoads(t *testing.T) {
	d := &Detector{}
	if err := d.Load(); err != nil {
		t.Fatal(err)
	}
	m := d.Manifest()
	seen := map[string]bool{}
	for _, k := range m.Kinds {
		if seen[k.ID] {
			t.Errorf("duplicate kind %s", k.ID)
		}
		seen[k.ID] = true
		if strings.Contains(k.Description, "\u2014") || strings.Contains(k.Title, "\u2014") {
			t.Errorf("kind %s has an em dash", k.ID)
		}
	}
}
