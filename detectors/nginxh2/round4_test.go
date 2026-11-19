package nginxh2

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Findings of the round-3 verification (job 1118-150713-c2aa).

// W1: a relative command word is resolved as the runtime resolves it:
// "./x" against the image's working directory, "x" through its PATH.
func TestW1RelativeEntrypoint(t *testing.T) {
	ep := official(t, "docker-entrypoint.sh")
	custom := []byte("#!/bin/sh\nsed -i 's/listen 80;/listen 443 ssl http2;/' /etc/nginx/conf.d/default.conf\nexec \"$@\"\n")
	s := &scan{kind: engine.Image, db: map[string][]byte{}, scripts: map[string][]byte{
		"/docker-entrypoint.sh": ep, "/app/docker-entrypoint.sh": custom, "/usr/local/bin/docker-entrypoint.sh": custom, "/opt/bin/ok.sh": ep,
	}}
	exists := func(p string) bool { _, ok := s.scripts[p]; return ok }
	for _, c := range []struct {
		word, dir string
		env       []string
		trust     bool
	}{
		{"/docker-entrypoint.sh", "/app", nil, true},
		{"./docker-entrypoint.sh", "/app", nil, false},
		{"./docker-entrypoint.sh", "/", nil, true},
		{"docker-entrypoint.sh", "/", nil, false}, // the default PATH finds /usr/local/bin first
		{"docker-entrypoint.sh", "/", []string{"PATH=/opt/none:/"}, true},
		{"ok.sh", "/", []string{"PATH=/opt/bin"}, true},
		{"missing.sh", "/", nil, false},
		{"bin/ok.sh", "/opt", nil, true},
	} {
		ok, why := s.launcher(nil, nil, c.dir, c.env, exists)(c.word)
		if ok != c.trust {
			t.Errorf("%s in %s with %v: trusted %v (%s), want %v", c.word, c.dir, c.env, ok, why, c.trust)
		}
	}
}

// W2: a symbolic link to a directory inside /docker-entrypoint.d is
// descended into, as find -follow does: what it holds is run.
func TestW2LinkedDirectory(t *testing.T) {
	ep := official(t, "docker-entrypoint.sh")
	for _, c := range []struct {
		name    string
		scripts map[string][]byte
		unread  map[string]string
		trust   bool
	}{
		{"a script in the linked directory", map[string][]byte{"/opt/scripts/40-h2.sh": []byte("#!/bin/sh\nsed -i x\n")}, nil, false},
		{"an envsh in it", map[string][]byte{"/opt/scripts/sub/a.envsh": []byte("#!/bin/sh\nexport X=1\n")}, nil, false},
		{"an official script in it", map[string][]byte{"/opt/scripts/30-tune-worker-processes.sh": official(t, "30-tune-worker-processes.sh")}, nil, true},
		{"something there not read", nil, map[string]string{"/opt/scripts/50.sh": "permission denied"}, false},
		{"a link to nothing read", nil, nil, false},
	} {
		s := &scan{kind: engine.Image, db: map[string][]byte{}, scripts: map[string][]byte{"/docker-entrypoint.sh": ep}, unread: c.unread}
		for p, b := range c.scripts {
			s.scripts[p] = b
		}
		links := map[string]string{"/docker-entrypoint.d/extra": "/opt/scripts"}
		ok, why := s.launcher(links, nil, "/", nil, nil)("/docker-entrypoint.sh")
		if ok != c.trust {
			t.Errorf("%s: trusted %v (%s), want %v", c.name, ok, why, c.trust)
		}
	}
}

// W3 and W4: a unit's Environment= and EnvironmentFile= are applied to
// ExecStart (nginx.org's pkg-oss unit), and commands run around the start
// that cannot change the configuration (rm -f of a pid file, nginx -t) do
// not void "not exposed".
func TestW3W4UnitEnvironment(t *testing.T) {
	pkgOSS := "[Service]\nType=forking\nPIDFile=/run/nginx.pid\nEnvironment=\"cmdopts=\"\nEnvironment=\"conffile=/etc/nginx/nginx.conf\"\nEnvironmentFile=-/etc/sysconfig/nginx\nExecStart=/usr/sbin/nginx -c ${conffile} $cmdopts\n"
	files := func(unit string) map[string][]byte {
		return map[string][]byte{
			"/usr/sbin/nginx":                       ngxtest.Default("1.31.8").Bytes(),
			"/etc/nginx/nginx.conf":                 []byte("http { include /etc/nginx/conf.d/*.conf; }"),
			"/etc/nginx/conf.d/a.conf":              []byte("server { listen 443 ssl http2; location / { proxy_pass http://u; } }"),
			"/etc/nginx/off.conf":                   []byte("http { server { listen 80; } }"),
			"/usr/lib/systemd/system/nginx.service": []byte(unit),
		}
	}
	exposure := func(fs map[string][]byte) string {
		if f := find(scanFS(t, fs, engine.Options{}), KindFlow, "/usr/sbin/nginx"); f != nil {
			return f.Facts["exposure"] + " " + f.Facts["config"]
		}
		return "no finding"
	}
	if got := exposure(files(pkgOSS)); got != "exposed /etc/nginx/nginx.conf" {
		t.Errorf("pkg-oss unit: %s", got)
	}
	// The EnvironmentFile overrides the unit's value.
	fs := files(pkgOSS)
	fs["/etc/sysconfig/nginx"] = []byte("# nginx options\nconffile=/etc/nginx/off.conf\n")
	if got := exposure(fs); got != "not-exposed /etc/nginx/off.conf" {
		t.Errorf("EnvironmentFile: %s", got)
	}
	// A required EnvironmentFile that is not there: unknown (with the
	// default configuration off, so nothing shows HTTP/2 on).
	fs = files(strings.Replace(pkgOSS, "EnvironmentFile=-", "EnvironmentFile=", 1))
	fs["/etc/nginx/conf.d/a.conf"] = []byte("server { listen 80; }")
	if got := exposure(fs); !strings.HasPrefix(got, "unknown") {
		t.Errorf("missing EnvironmentFile: %s", got)
	}
	// A harmless ExecStartPre on a not-exposed host.
	fs = files("[Service]\nPIDFile=/run/nginx.pid\nExecStartPre=/usr/bin/rm -f /run/nginx.pid\nExecStartPre=/usr/sbin/nginx -t\nExecStart=/usr/sbin/nginx -c /etc/nginx/off.conf\n")
	if got := exposure(fs); got != "not-exposed /etc/nginx/off.conf" {
		t.Errorf("rm -f pid then nginx -t: %s", got)
	}
	// rm of anything else still voids it.
	fs = files("[Service]\nExecStartPre=/usr/bin/rm -f /etc/nginx/conf.d/a.conf\nExecStart=/usr/sbin/nginx -c /etc/nginx/off.conf\n")
	fs["/etc/nginx/conf.d/a.conf"] = []byte("server { listen 80; }")
	if got := exposure(fs); !strings.HasPrefix(got, "unknown") {
		t.Errorf("rm of a configuration file: %s", got)
	}
	// An optional EnvironmentFile outside what the scan reads whole.
	fs = files(strings.Replace(pkgOSS, "/etc/sysconfig/nginx", "/opt/env/nginx-env", 1))
	fs["/etc/nginx/conf.d/a.conf"] = []byte("server { listen 80; }")
	if got := exposure(fs); !strings.HasPrefix(got, "unknown") {
		t.Errorf("an optional file the scan does not read: %s", got)
	}
}

// W6: reading many units does not walk every link of the target per
// unit directory.
func TestW6UnitIndex(t *testing.T) {
	db := map[string][]byte{}
	for i := 0; i < 3000; i++ {
		db["/usr/lib/systemd/system/u"+strconv.Itoa(i)+".service"] = []byte("[Service]\nExecStart=/bin/true\n")
	}
	links := map[string]string{}
	for i := 0; i < 150000; i++ {
		links["/usr/share/x/l"+strconv.Itoa(i)] = "/y"
	}
	s := &scan{kind: engine.Filesystem, db: db}
	start := time.Now()
	s.systemdStarts(&confSource{links: links})
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("3,000 units with 150,000 links took %s", d)
	}
}

// W7: below a system root, a glob with a wildcard in its directory part
// reads the directories from disk, as --as-root does.
func TestW7WildcardBelowRoot(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string][]byte{
		"/opt/sbin/nginx":                   ngxtest.Default("1.31.8").Bytes(),
		"/opt/app/conf/nginx.conf":          []byte("http { include /opt/app/conf/vhosts/*/site.conf; }"),
		"/opt/app/conf/vhosts/a/site.conf":  []byte("server { listen 80; }"),
		"/opt/app/conf/vhosts/b/site.conf":  []byte("server { listen 443 ssl http2; }"),
		"/etc/systemd/system/nginx.service": []byte("[Service]\nExecStart=/opt/sbin/nginx -c /opt/app/conf/nginx.conf\n"),
	})
	for name, tg := range map[string]*engine.Target{
		"--as-root": engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true}),
		"--root":    engine.ScanFS([]engine.Detector{&Detector{}}, root+"/opt", engine.Options{SystemRoot: root}),
	} {
		if f := find(tg, KindFlow, "/opt/sbin/nginx"); f == nil || f.Facts["exposure"] != "exposed" {
			t.Errorf("%s: %+v", name, f)
		}
	}
}
