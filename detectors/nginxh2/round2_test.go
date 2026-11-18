package nginxh2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Findings of the second independent review (job 1118-111751-8721), each
// a case that read as "not exposed" or cleared where it should not.

// R1: an include the walk could not read (mode 000), scanned at a root,
// leaves exposure unknown: the engine's "not scanned" list says so.
func TestR1UnreadableIncludeAtRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode 000 files")
	}
	for _, unreadable := range []string{"etc/nginx/conf.d/a.conf", "etc/nginx/conf.d"} {
		root := t.TempDir()
		write(t, root, map[string][]byte{
			"/usr/sbin/nginx":          ngxtest.Default("1.31.8").Bytes(),
			"/etc/nginx/nginx.conf":    []byte("http { include /etc/nginx/conf.d/*.conf; server { listen 80; } }"),
			"/etc/nginx/conf.d/a.conf": []byte("server { listen 443 ssl http2; }"),
		})
		p := filepath.Join(root, unreadable)
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
		os.Chmod(p, 0o755)
		f := find(tg, KindFlow, "/usr/sbin/nginx")
		if f == nil || f.Facts["exposure"] != "unknown" {
			t.Errorf("%s unreadable: %+v", unreadable, f)
		}
	}
}

// R2: a host's nginx is judged with the command its service unit runs,
// drop-ins applied.
func TestR2SystemdUnit(t *testing.T) {
	base := map[string][]byte{
		"/usr/sbin/nginx":                   ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf":             []byte("http { server { listen 80; } }"),
		"/etc/nginx/h2.conf":                []byte("http { server { listen 443 ssl http2; } }"),
		"/lib/systemd/system/nginx.service": []byte("[Service]\nExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'\nExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'\n"),
	}
	tg := scanFS(t, base, engine.Options{})
	if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Facts["exposure"] != "not-exposed" || f.Facts["config_from"] != "the binary's default" {
		t.Errorf("unit: %+v", f)
	}
	base["/etc/systemd/system/nginx.service.d/override.conf"] = []byte("[Service]\nExecStart=\nExecStart=/usr/sbin/nginx -c /etc/nginx/h2.conf -g 'daemon on;'\n")
	tg = scanFS(t, base, engine.Options{})
	if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Facts["exposure"] != "exposed" {
		t.Errorf("drop-in: %+v", f)
	}
	delete(base, "/etc/systemd/system/nginx.service.d/override.conf")
	delete(base, "/lib/systemd/system/nginx.service")
	tg = scanFS(t, base, engine.Options{})
	if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Facts["exposure"] != "unknown" {
		t.Errorf("no unit: %+v", f)
	}
}

func TestR2EntrypointScripts(t *testing.T) {
	s := &scan{kind: engine.Image, db: map[string][]byte{"/docker-entrypoint.d/20-envsubst-on-templates.sh": nil, "/docker-entrypoint.d/40-h2.sh": nil},
		unread: map[string]string{"/docker-entrypoint.d/50-x.sh": "permission denied"}}
	got := s.entrypointScripts()
	if len(got) != 3 || got[1] != "40-h2.sh" || got[2] != "50-x.sh (not read)" {
		t.Errorf("%v", got)
	}
	if s.commandFor() != nil {
		t.Error("an image has its own command")
	}
}
