package nginxh2

import (
	"testing"

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
