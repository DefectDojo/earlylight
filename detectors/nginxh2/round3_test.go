package nginxh2

import (
	"os"
	"path/filepath"
	"testing"

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
		ok, why := s.launcher(links, nil)(c.word)
		if ok != c.trust {
			t.Errorf("%s: trusted %v (%s), want %v", c.name, ok, why, c.trust)
		}
	}
}
