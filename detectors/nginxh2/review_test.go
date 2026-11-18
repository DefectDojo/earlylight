package nginxh2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/conf"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Cases from the independent review: each read as "not exposed" before.

func TestTemplateVariables(t *testing.T) {
	kept := map[string][]byte{
		"/etc/nginx/nginx.conf":                      []byte("http { include /etc/nginx/conf.d/*.conf; }"),
		"/etc/nginx/templates/default.conf.template": []byte("server { listen 443 ssl ${NGINX_H2}; location / { proxy_pass http://$host; } }"),
	}
	for _, c := range []struct {
		env  []string
		want conf.State
	}{
		{[]string{"NGINX_H2=http2"}, conf.Exposed},
		{nil, conf.Unknown},
		{[]string{"NGINX_H2="}, conf.NotExposed},
	} {
		s := &confSource{kept: kept}
		s.templates(c.env)
		e := conf.Analyze(conf.Load(s, "/etc/nginx/nginx.conf", nil))
		if e.Flow != c.want {
			t.Errorf("env %v: %s (%v)", c.env, e.Flow, e.Unread)
		}
	}
}

func TestBelowRootSymlinkedSite(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string][]byte{
		"/usr/sbin/nginx":                    ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf":              []byte("http { include /etc/nginx/sites-enabled/*; }"),
		"/etc/nginx/sites-available/default": []byte("server { listen 443 ssl http2; }"),
	})
	os.MkdirAll(filepath.Join(root, "etc/nginx/sites-enabled"), 0o755)
	if err := os.Symlink("../sites-available/default", filepath.Join(root, "etc/nginx/sites-enabled/default")); err != nil {
		t.Fatal(err)
	}
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, filepath.Join(root, "usr/sbin"), engine.Options{SystemRoot: root})
	if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Facts["exposure"] != "exposed" {
		t.Errorf("%+v", f)
	}
}

func TestSymlinkedIncludeDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string][]byte{
		"/usr/sbin/nginx":       ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf": []byte("http { include /etc/nginx/vhosts/*; server { listen 80; } }"),
		"/data/vhosts/site":     []byte("server { listen 443 ssl http2; }"),
	})
	if err := os.Symlink("/data/vhosts", filepath.Join(root, "etc/nginx/vhosts")); err != nil {
		t.Fatal(err)
	}
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
	if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Facts["exposure"] != "unknown" {
		t.Errorf("a directory linked out of the kept ones: %+v", f)
	}
}

func TestGlobSemantics(t *testing.T) {
	tg := scanFS(t, map[string][]byte{
		"/usr/sbin/nginx":                ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf":          []byte("http { include /etc/nginx/conf.d/[!_]*.conf; }"),
		"/etc/nginx/conf.d/site.conf":    []byte("server { listen 443 ssl http2; }"),
		"/etc/nginx/conf.d/.hidden.conf": []byte("server { listen 8443 ssl http2; }"),
	}, engine.Options{})
	f := find(tg, KindFlow, "/usr/sbin/nginx")
	if f == nil || f.Facts["exposure"] != "exposed" || f.Facts["http2_where"] != "/etc/nginx/conf.d/site.conf:1" {
		t.Errorf("%+v", f)
	}
	for p, want := range map[[2]string]bool{
		{"/a/[!_]*.conf", "/a/x.conf"}: true, {"/a/[!_]*.conf", "/a/_x.conf"}: false, {"/a/*.conf", "/a/.x.conf"}: false,
		{"/a/.*.conf", "/a/.x.conf"}: true, {"/a/*", "/a/b/c"}: false,
	} {
		if got, _ := globMatch(p[0], p[1]); got != want {
			t.Errorf("globMatch(%s, %s) = %v", p[0], p[1], got)
		}
	}
	if _, err := globMatch("/a/[", "/a/x"); err == nil {
		t.Error("a bad pattern was accepted")
	}
}
