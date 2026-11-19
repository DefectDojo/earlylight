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
	f.Add("/usr/sbin/nginx", "/docker-entrypoint.d/40-x.sh", "/docker-entrypoint.d/sub=/etc;/usr/bin/nginx=../sbin/nginx", "", "PATH=/usr/bin", "#!/bin/sh\n")
	// The launcher is the official entrypoint, so the fuzzed file in
	// /docker-entrypoint.d and the links reach the directory walk.
	ep := official(f, "docker-entrypoint.sh")
	tpl := official(f, "20-envsubst-on-templates.sh")
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
		vars, _ := envFile([]byte(tmpl))
		expandUnit(unit, vars)
		unsetVar(unit, vars)
		execPrefix(unit)
		harmless(unitWords(unit), "/run/nginx.pid", "/usr/sbin/nginx")
		resolveCommand(p, pattern, strings.Split(env, ","), func(q string) bool { return q == pattern })
		fuzzed := "/docker-entrypoint.d/" + path.Base(p)
		ls := &scan{db: map[string][]byte{"/docker-entrypoint.d/20-envsubst-on-templates.sh": tpl},
			scripts: map[string][]byte{"/docker-entrypoint.sh": ep, fuzzed: []byte(unit)},
			epSeen:  map[string]bool{fuzzed: true, "/docker-entrypoint.d/" + path.Base(pattern): true}}
		cmds := ls.commands(lm, nil, pattern, strings.Split(env, ","), nil)
		ok, _ := cmds.launcher("/docker-entrypoint.sh")
		cmds.launcher(p)
		cmds.starts(p, pattern)
		if b := path.Base(p); ok && b != "." && b != "/" && !strings.Contains(b, "/") && !officialScripts[b][sha([]byte(unit))] && len(lm) == 0 {
			t.Fatalf("the entrypoint passed with %s not official", fuzzed)
		}
	})
}
