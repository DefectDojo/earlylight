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
