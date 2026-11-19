package nginxh2

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Findings of the round-2 verification (job 1118-150713-c2aa).

func official(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "entrypoint", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// V1: an entrypoint is trusted by its content, never its name, and every
// /docker-entrypoint.d script it runs must be read and official.
func TestV1EntrypointContent(t *testing.T) {
	ep := official(t, "docker-entrypoint.sh")
	scripts := map[string][]byte{}
	for _, n := range []string{"10-listen-on-ipv6-by-default.sh", "15-local-resolvers.envsh", "20-envsubst-on-templates.sh", "30-tune-worker-processes.sh"} {
		scripts["/docker-entrypoint.d/"+n] = official(t, n)
	}
	mk := func() *scan {
		s := &scan{kind: engine.Image, db: map[string][]byte{}, scripts: map[string][]byte{"/docker-entrypoint.sh": ep}}
		for p, b := range scripts {
			s.scripts[p] = b
		}
		return s
	}
	cases := []struct {
		name  string
		edit  func(s *scan, links map[string]string)
		word  string
		trust bool
	}{
		{"official", func(*scan, map[string]string) {}, "/docker-entrypoint.sh", true},
		{"same name, other content", func(s *scan, _ map[string]string) {
			s.scripts["/docker-entrypoint.sh"] = []byte("#!/bin/sh\nsed -i 's/listen 80;/listen 443 ssl http2;/' /etc/nginx/conf.d/default.conf\nexec \"$@\"\n")
		}, "/docker-entrypoint.sh", false},
		{"other path, not read", func(*scan, map[string]string) {}, "/usr/local/bin/docker-entrypoint.sh", false},
		{"a custom script", func(s *scan, _ map[string]string) {
			s.scripts["/docker-entrypoint.d/40-h2.sh"] = []byte("#!/bin/sh\necho\n")
		}, "/docker-entrypoint.sh", false},
		{"an official name, other content", func(s *scan, _ map[string]string) {
			s.scripts["/docker-entrypoint.d/30-tune-worker-processes.sh"] = []byte("#!/bin/sh\nsed -i s/80/443/ /etc/nginx/conf.d/default.conf\n")
		}, "/docker-entrypoint.sh", false},
		{"a symbolic link to a script", func(_ *scan, l map[string]string) { l["/docker-entrypoint.d/40-h2.sh"] = "/opt/h2.sh" }, "/docker-entrypoint.sh", false},
		{"a script not read", func(s *scan, _ map[string]string) {
			s.unread = map[string]string{"/docker-entrypoint.d/50-x.sh": "permission denied"}
		}, "/docker-entrypoint.sh", false},
		{"a symbolic link to the official entrypoint", func(_ *scan, l map[string]string) { l["/usr/local/bin/docker-entrypoint.sh"] = "/docker-entrypoint.sh" }, "/usr/local/bin/docker-entrypoint.sh", true},
	}
	for _, c := range cases {
		s := mk()
		links := map[string]string{}
		c.edit(s, links)
		ok, why := s.commands(links, nil, "/", nil, nil).launcher(c.word)
		if ok != c.trust {
			t.Errorf("%s: trusted %v (%s), want %v", c.name, ok, why, c.trust)
		}
	}
}

// V2: a host's systemd unit is read with its drop-ins and overrides,
// wherever they are, and anything not read or run first is unknown.
func TestV2Systemd(t *testing.T) {
	base := func() map[string][]byte {
		return map[string][]byte{
			"/usr/sbin/nginx":                       ngxtest.Default("1.31.8").Bytes(),
			"/etc/nginx/nginx.conf":                 []byte("http { server { listen 80; } }"),
			"/etc/nginx/h2.conf":                    []byte("http { server { listen 443 ssl http2; } }"),
			"/usr/lib/systemd/system/nginx.service": []byte("[Service]\nExecStart=/usr/sbin/nginx -g 'daemon on;'\n"),
		}
	}
	exposure := func(tg *engine.Target) string {
		if f := find(tg, KindFlow, "/usr/sbin/nginx"); f != nil {
			return f.Facts["exposure"]
		}
		return "no finding"
	}
	// A drop-in outside the walk (a scan of /usr below the root).
	root := t.TempDir()
	files := base()
	files["/etc/systemd/system/nginx.service.d/override.conf"] = []byte("[Service]\nExecStart=\nExecStart=/usr/sbin/nginx -c /etc/nginx/h2.conf\n")
	write(t, root, files)
	if got := exposure(engine.ScanFS([]engine.Detector{&Detector{}}, filepath.Join(root, "usr"), engine.Options{SystemRoot: root})); got != "exposed" {
		t.Errorf("drop-in outside the walk: %s", got)
	}
	// /etc/systemd/system/nginx.service links to a unit elsewhere.
	root = t.TempDir()
	files = base()
	files["/opt/units/nginx.service"] = []byte("[Service]\nExecStart=/usr/sbin/nginx -c /etc/nginx/h2.conf\n")
	write(t, root, files)
	os.MkdirAll(filepath.Join(root, "etc/systemd/system"), 0o755)
	if err := os.Symlink("/opt/units/nginx.service", filepath.Join(root, "etc/systemd/system/nginx.service")); err != nil {
		t.Fatal(err)
	}
	if got := exposure(engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})); got != "exposed" {
		t.Errorf("linked override: %s", got)
	}
	// A script run first.
	files = base()
	files["/usr/lib/systemd/system/nginx.service"] = []byte("[Service]\nExecStartPre=/usr/local/bin/gen-conf.sh\nExecStartPre=/usr/sbin/nginx -t -q\nExecStart=/usr/sbin/nginx\n")
	if got := exposure(scanFS(t, files, engine.Options{})); got != "unknown" {
		t.Errorf("ExecStartPre script: %s", got)
	}
	// nginx -t first is fine.
	files["/usr/lib/systemd/system/nginx.service"] = []byte("[Service]\nExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on;'\nExecStart=/usr/sbin/nginx\n")
	if got := exposure(scanFS(t, files, engine.Options{})); got != "not-exposed" {
		t.Errorf("nginx -t first: %s", got)
	}
}

// V2: an override that cannot be read leaves exposure unknown.
func TestV2SystemdUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode 000 files")
	}
	for _, p := range []string{"etc/systemd/system/nginx.service.d", "etc/systemd/system/nginx.service.d/override.conf", "etc/systemd/system/nginx.service"} {
		root := t.TempDir()
		write(t, root, map[string][]byte{
			"/usr/sbin/nginx":                                   ngxtest.Default("1.31.8").Bytes(),
			"/etc/nginx/nginx.conf":                             []byte("http { server { listen 80; } }"),
			"/usr/lib/systemd/system/nginx.service":             []byte("[Service]\nExecStart=/usr/sbin/nginx\n"),
			"/etc/systemd/system/nginx.service":                 []byte("[Service]\nExecStart=/usr/sbin/nginx\n"),
			"/etc/systemd/system/nginx.service.d/override.conf": []byte("[Service]\nExecStart=\nExecStart=/usr/sbin/nginx -c /x\n"),
		})
		full := filepath.Join(root, p)
		os.Chmod(full, 0)
		tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
		os.Chmod(full, 0o755)
		if f := find(tg, KindFlow, "/usr/sbin/nginx"); f == nil || f.Facts["exposure"] != "unknown" {
			t.Errorf("%s unreadable: %+v", p, f)
		}
	}
}

// V7: glob includes do not each walk every link of the target.
func TestV7GlobWork(t *testing.T) {
	links := map[string]string{}
	for i := 0; i < 30000; i++ {
		links["/usr/share/x/l"+strconv.Itoa(i)] = "/elsewhere"
	}
	s := &confSource{kept: map[string][]byte{"/etc/nginx/conf.d/a.conf": []byte("x")}, links: links}
	start := time.Now()
	for i := 0; i < 2000; i++ {
		s.Glob("/etc/nginx/conf.d/*.conf")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("2,000 globs over 30,000 links took %s", d)
	}
}
