package nginxh2

import (
	"path"
	"strings"
	"testing"
)

// FuzzSource: the glob matcher, the symbolic link resolver, template
// substitution and the systemd unit reader take any input without a panic
// or an unbounded loop.
func FuzzSource(f *testing.F) {
	f.Add("/etc/nginx/conf.d/[[:digit:]]*.conf", "/etc/nginx/conf.d/10-a.conf", "/etc/nginx/conf.d=../x;/x=/etc", "listen ${A} $B;", "A=1", "ExecStart=-/usr/sbin/nginx -g 'daemon on;'")
	f.Add("/a/[!_]*", "/a/.b", "/a=/a", "${", "=", "ExecStart=\nExecStart=nginx \\")
	f.Fuzz(func(t *testing.T, pattern, p, links, tmpl, env, unit string) {
		globMatch(pattern, p)
		posixClasses(pattern)
		lm := map[string]string{}
		for _, kv := range strings.Split(links, ";") {
			if k, v, ok := strings.Cut(kv, "="); ok && len(lm) < 32 {
				lm[path.Clean("/"+k)] = v
			}
		}
		s := &confSource{kept: map[string][]byte{p: []byte(tmpl)}, links: lm, hardlinks: map[string]string{p: pattern}}
		s.resolve(p)
		s.Read(p)
		s.Glob(pattern)
		envsubst([]byte(tmpl), strings.Split(env, ","))
		unitWords(unit)
		us := &scan{db: map[string][]byte{"/lib/systemd/system/nginx.service": []byte(unit), "/etc/systemd/system/nginx.service.d/a.conf": []byte(tmpl)}}
		us.systemdStarts(&confSource{links: lm})
		nginxTest(unitWords(unit))
	})
}
