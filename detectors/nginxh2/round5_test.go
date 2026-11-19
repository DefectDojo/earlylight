package nginxh2

import (
	"path"
	"sort"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/internal/archive"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Findings of the round-4 verification (job 1118-184956-3834), and the
// rule that closes them: "not exposed" only when the start command
// resolves to the binary judged, the entrypoint and everything it runs
// were read and are official, and every configuration file was read.

// fakeImage is an image target for Visit and Finish.
type fakeImage struct {
	files    map[string][]byte
	links    map[string]string
	unread   map[string]string
	cmd, env []string
	workdir  string
	seen     map[string]bool
}

func (f *fakeImage) Kind() engine.TargetKind { return engine.Image }
func (f *fakeImage) Exists(p string) bool    { return f.seen[p] }
func (f *fakeImage) Env() []string           { return f.env }
func (f *fakeImage) Command() []string       { return f.cmd }
func (f *fakeImage) Aliases(p string) []string {
	return []string{p}
}
func (f *fakeImage) Links() (map[string]string, map[string]string) { return f.links, nil }
func (f *fakeImage) SystemRoot() string                            { return "" }
func (f *fakeImage) Problem(string)                                {}
func (f *fakeImage) Annotate(string, any)                          {}
func (f *fakeImage) WorkingDir() string                            { return f.workdir }

// run scans the image as the engine would: files the detector wants are
// read, the not-scanned records are handed over, then Finish.
func (f *fakeImage) run(t *testing.T) []engine.Finding {
	t.Helper()
	d := &Detector{}
	s := d.NewScan(engine.Image)
	f.seen = map[string]bool{}
	var ps []string
	for p := range f.files {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	for _, p := range ps {
		b := f.files[p]
		head := b
		if len(head) > 4096 {
			head = head[:4096]
		}
		exe := archive.IsExecutable(head)
		if !d.Wants(p, head, exe) {
			continue
		}
		f.seen[p] = true
		s.Visit(engine.File{Path: p, Data: b, Executable: exe})
	}
	var sk []engine.Skip
	for p, why := range f.unread {
		sk = append(sk, engine.Skip{Path: p, Reason: why})
	}
	s.(engine.SkipVisitor).VisitSkips(sk)
	return s.Finish(f)
}

func (f *fakeImage) exposure(t *testing.T) string {
	for _, x := range f.run(t) {
		if x.Kind == KindFlow && x.Path == "/usr/sbin/nginx" {
			return x.Facts["exposure"]
		}
	}
	return "no finding"
}

// officialImage is nginx:1.31.8's layout: the official entrypoint and its
// four scripts, a default site on port 80.
func officialImage(t *testing.T) *fakeImage {
	files := map[string][]byte{
		"/usr/sbin/nginx":                ngxtest.Default("1.31.8").Bytes(),
		"/etc/nginx/nginx.conf":          []byte("events {} http { include /etc/nginx/conf.d/*.conf; }"),
		"/etc/nginx/conf.d/default.conf": []byte("server { listen 80; location / { root /usr/share/nginx/html; } }"),
		"/docker-entrypoint.sh":          official(t, "docker-entrypoint.sh"),
	}
	for _, n := range []string{"10-listen-on-ipv6-by-default.sh", "15-local-resolvers.envsh", "20-envsubst-on-templates.sh", "30-tune-worker-processes.sh"} {
		files["/docker-entrypoint.d/"+n] = official(t, n)
	}
	return &fakeImage{files: files, links: map[string]string{}, unread: map[string]string{},
		cmd: []string{"/docker-entrypoint.sh", "nginx", "-g", "daemon off;"}, env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}}
}

var elf = []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00binary")

func TestX0OfficialLayout(t *testing.T) {
	if got := officialImage(t).exposure(t); got != "not-exposed" {
		t.Fatalf("the official layout: %s", got)
	}
}

// X1: everything reachable from /docker-entrypoint.d must be read and
// official; a directory link out of it is unknown.
func TestX1EntrypointCompleteness(t *testing.T) {
	for name, edit := range map[string]func(*fakeImage){
		"a directory link out, a script without #!": func(f *fakeImage) {
			f.links["/docker-entrypoint.d/extra"] = "/opt/scripts"
			f.files["/opt/scripts/30-tune-worker-processes.sh"] = official(t, "30-tune-worker-processes.sh")
			f.files["/opt/scripts/40-h2.envsh"] = []byte("sed -i 's/listen 80;/listen 80 http2;/' /etc/nginx/conf.d/default.conf\n")
		},
		"an envsh without #!": func(f *fakeImage) { f.files["/docker-entrypoint.d/40-h2.envsh"] = []byte("sed -i x\n") },
		"an ELF file":         func(f *fakeImage) { f.files["/docker-entrypoint.d/40-h2.sh"] = elf },
		"any other file":      func(f *fakeImage) { f.files["/docker-entrypoint.d/README"] = []byte("notes\n") },
		"a large script": func(f *fakeImage) {
			f.files["/docker-entrypoint.d/40.sh"] = append([]byte("#!/bin/sh\n"), make([]byte, 300<<10)...)
		},
	} {
		f := officialImage(t)
		edit(f)
		if got := f.exposure(t); got != "unknown" {
			t.Errorf("%s: %s", name, got)
		}
	}
}

// X2, X3: the word that starts nginx must resolve to the binary judged,
// with no env indirection.
func TestX2X3StartWord(t *testing.T) {
	for name, edit := range map[string]func(*fakeImage){
		"a wrapper named nginx on PATH": func(f *fakeImage) {
			f.files["/usr/local/bin/nginx"] = []byte("#!/bin/sh\nsed -i x /etc/nginx/nginx.conf\nexec /usr/sbin/nginx \"$@\"\n")
		},
		"./nginx in the working directory": func(f *fakeImage) {
			f.workdir = "/app"
			f.files["/app/nginx"] = []byte("#!/bin/sh\nexec /usr/sbin/nginx \"$@\"\n")
			f.cmd = []string{"/docker-entrypoint.sh", "./nginx", "-g", "daemon off;"}
		},
		"env PATH=": func(f *fakeImage) {
			f.cmd = []string{"env", "PATH=/app:/usr/sbin:/usr/bin:/bin", "/docker-entrypoint.sh", "nginx"}
		},
		"env --chdir": func(f *fakeImage) {
			f.cmd = []string{"env", "--chdir=/", "./docker-entrypoint.sh", "nginx"}
		},
		"a linked PATH entry first": func(f *fakeImage) {
			f.env = []string{"PATH=/custom:/usr/sbin:/"}
			f.links["/custom/docker-entrypoint.sh"] = "/opt/bin/wrapper"
			f.files["/opt/bin/wrapper"] = elf
			f.cmd = []string{"docker-entrypoint.sh", "nginx"}
		},
		"a nginx word that resolves to nothing read": func(f *fakeImage) {
			f.env = []string{"PATH=/nowhere"}
		},
	} {
		f := officialImage(t)
		edit(f)
		if got := f.exposure(t); got != "unknown" {
			t.Errorf("%s: %s", name, got)
		}
	}
	// The binary itself, by absolute path or through PATH, is fine.
	f := officialImage(t)
	f.cmd = []string{"/usr/sbin/nginx", "-g", "daemon off;"}
	if got := f.exposure(t); got != "not-exposed" {
		t.Errorf("the binary by path: %s", got)
	}
}

// X4: templates are written only when the official entrypoint runs and
// is given nginx or nginx-debug.
func TestX4Templates(t *testing.T) {
	setup := func() *fakeImage {
		f := officialImage(t)
		f.files["/etc/nginx/conf.d/default.conf"] = []byte("server { listen 443 ssl http2; location / { proxy_pass http://u; } }")
		f.files["/etc/nginx/templates/default.conf.template"] = []byte("server { listen 80; }")
		return f
	}
	if got := setup().exposure(t); got != "not-exposed" {
		t.Errorf("the entrypoint writes the template over default.conf: %s", got)
	}
	for name, cmd := range map[string][]string{
		"nginx directly":     {"/usr/sbin/nginx", "-g", "daemon off;"},
		"through tini":       {"tini", "--", "nginx", "-g", "daemon off;"},
		"sh -c exec nginx":   {"sh", "-c", "exec nginx -g 'daemon off;'"},
		"entrypoint, not $1": {"/docker-entrypoint.sh", "/usr/sbin/nginx", "-g", "daemon off;"},
	} {
		f := setup()
		f.cmd = cmd
		if got := f.exposure(t); got != "exposed" {
			t.Errorf("%s: %s (the template is not written)", name, got)
		}
	}
	_ = path.Base
}
