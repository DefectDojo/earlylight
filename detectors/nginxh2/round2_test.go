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
