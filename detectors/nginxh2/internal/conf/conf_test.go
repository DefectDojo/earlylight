package conf

import (
	"path"
	"sort"
	"strings"
	"testing"
)

// mem is a Source over a map. incomplete lists glob patterns whose
// matches are not all known.
type mem struct {
	files      map[string]string
	incomplete map[string]bool
}

func (m mem) Read(p string) ([]byte, bool, string) {
	s, ok := m.files[p]
	if !ok {
		return nil, false, "missing"
	}
	return []byte(s), true, ""
}

func (m mem) Glob(pattern string) ([]string, bool) {
	var out []string
	for p := range m.files {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, !m.incomplete[pattern]
}

func analyze(t *testing.T, files map[string]string) Exposure {
	t.Helper()
	return Analyze(Load(mem{files: files}, "/etc/nginx/nginx.conf", nil))
}

func TestParse(t *testing.T) {
	ds, err := Parse("f", `# comment
user nginx;
http {
    log_format main '$remote_addr "$request"' ;
    server { listen 443 ssl http2; server_name "a b" x\;y;
        location / { return 200 "}{;"; } # trailing
        set $x ${host}z;
    }
}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 2 || ds[1].Name != "http" || len(ds[1].Block) != 2 {
		t.Fatalf("got %+v", ds)
	}
	srv := ds[1].Block[1]
	if srv.Name != "server" || srv.Block[0].Name != "listen" || strings.Join(srv.Block[0].Args, " ") != "443 ssl http2" {
		t.Errorf("server %+v", srv)
	}
	if got := srv.Block[1].Args; len(got) != 2 || got[0] != "a b" || got[1] != `x\;y` {
		t.Errorf("server_name args %q", got)
	}
	if got := srv.Block[3].Args; len(got) != 2 || got[1] != "${host}z" {
		t.Errorf("set args %q", got)
	}
	if srv.Block[0].Line != 5 {
		t.Errorf("line %d", srv.Block[0].Line)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"http {", "}", "server ;;", "a \"b", "a 'b'c;", "a { b }", "{", "a ${b", strings.Repeat("a {", 100) + strings.Repeat("}", 100),
	} {
		if _, err := Parse("f", bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestLuaBlocks(t *testing.T) {
	ds, err := Parse("f", `http { server { listen 443 ssl http2;
  content_by_lua_block {
    -- don't { count "this"
    local s = "}" .. '{' .. [[ } ]]
    --[==[ a } comment ]==]
    if x then y() end
  }
  location / { proxy_pass http://u; }
} }`)
	if err != nil {
		t.Fatal(err)
	}
	srv := ds[0].Block[0]
	if len(srv.Block) != 3 || srv.Block[2].Name != "location" {
		t.Fatalf("lua block not skipped: %+v", srv.Block)
	}
}

func TestExposure(t *testing.T) {
	cases := []struct {
		name        string
		conf        string
		flow, reuse State
	}{
		{"off", `http { server { listen 80; location / { proxy_pass http://u; } } }`, NotExposed, NotExposed},
		{"tls h2 proxy", `http { server { listen 443 ssl http2; location / { proxy_pass http://u; } } }`, Exposed, Exposed},
		{"tls h2 static", `http { server { listen 443 ssl http2; root /srv; } }`, Exposed, NoProxy},
		{"http2 on", `http { http2 on; server { listen 443 ssl; location / { grpc_pass grpc://u; } } }`, Exposed, Exposed},
		{"http2 on, server off", `http { http2 on; server { listen 443 ssl; http2 off; proxy_pass http://u; } }`, NotExposed, NotExposed},
		{"cleartext", `http { server { listen 80 http2; location / { proxy_pass http://u; } } }`, Cleartext, Exposed},
		{"old ssl on", `http { server { listen 443 http2; ssl on; } }`, Exposed, NoProxy},
		{"port shared", `http { server { listen 443 ssl http2; server_name a; } server { listen 443 ssl; server_name b; location / { proxy_pass http://u; } } }`, Exposed, Exposed},
		{"no http", `events {} stream { server { listen 443; proxy_pass x; } }`, NotExposed, NotExposed},
		{"quic only", `http { server { listen 443 quic; listen 443 ssl; location / { proxy_pass http://u; } } }`, NotExposed, NotExposed},
		{"ssl on another listen of the port", `http { server { listen 443 ssl default_server; return 444; } server { listen 443; http2 on; location / { proxy_pass http://u; } } }`, Exposed, Exposed},
		{"default server http2", `http { server { listen 80 default_server; http2 on; return 444; } server { listen 80; server_name a; location / { proxy_pass http://u; } } }`, Cleartext, Exposed},
		{"template variable in listen", `http { server { listen 443 ssl ${H2}; location / { proxy_pass http://u; } } }`, Unknown, Unknown},
		{"template variable in http2", `http { server { listen 443 ssl; http2 ${H2}; } }`, Unknown, Unknown},
		{"no listen, not root", `http { server { http2 on; location / { proxy_pass http://u; } } }`, Cleartext, Exposed},
		{"nested if", `http { server { listen 443 ssl http2; location / { if ($x) { fastcgi_pass unix:/s; } } } }`, Exposed, Exposed},
	}
	for _, c := range cases {
		e := analyze(t, map[string]string{"/etc/nginx/nginx.conf": c.conf})
		if e.Flow != c.flow || e.Reuse != c.reuse {
			t.Errorf("%s: flow %s reuse %s, want %s %s (%+v)", c.name, e.Flow, e.Reuse, c.flow, c.reuse, e)
		}
	}
}

func TestIncludes(t *testing.T) {
	files := map[string]string{
		"/etc/nginx/nginx.conf":         "events { worker_connections 128; } http { include mime.types; include /etc/nginx/conf.d/*.conf; include sites-enabled/*; }",
		"/etc/nginx/mime.types":         "types { text/html html; }",
		"/etc/nginx/conf.d/a.conf":      "server { listen 80; }",
		"/etc/nginx/sites-enabled/site": "server { listen 443 ssl; include snippets/h2.conf; location / { proxy_pass http://b; } }",
		"/etc/nginx/snippets/h2.conf":   "http2 on;",
	}
	e := analyze(t, files)
	if e.Flow != Exposed || e.Reuse != Exposed || e.WorkerConnections != "128" {
		t.Fatalf("%+v", e)
	}
	if len(e.Where) != 1 || e.Where[0] != "/etc/nginx/snippets/h2.conf:1" {
		t.Errorf("where %v", e.Where)
	}
	// The include that turned it on cannot be read: unknown, not off.
	delete(files, "/etc/nginx/snippets/h2.conf")
	e = analyze(t, files)
	if e.Flow != Unknown || e.Reuse != Unknown || e.HTTP2 != "unknown" || len(e.Unread) == 0 {
		t.Errorf("unread include: %+v", e)
	}
	// A glob whose matches are not all known: unknown.
	files["/etc/nginx/snippets/h2.conf"] = "http2 off;"
	m := mem{files: files, incomplete: map[string]bool{"/etc/nginx/conf.d/*.conf": true}}
	e = Analyze(Load(m, "/etc/nginx/nginx.conf", nil))
	if e.Flow != Unknown {
		t.Errorf("incomplete glob: %+v", e)
	}
	// Everything read and off.
	e = analyze(t, files)
	if e.Flow != NotExposed || e.HTTP2 != "off" {
		t.Errorf("off: %+v", e)
	}
	// Positive evidence wins over an unread file.
	files["/etc/nginx/conf.d/a.conf"] = "server { listen 443 ssl http2; } include /missing.conf;"
	e = analyze(t, files)
	if e.Flow != Exposed || len(e.Unread) == 0 {
		t.Errorf("exposed with unread: %+v", e)
	}
}

func TestIncludeHostile(t *testing.T) {
	loop := map[string]string{
		"/etc/nginx/nginx.conf": "include a.conf;",
		"/etc/nginx/a.conf":     "include b.conf;",
		"/etc/nginx/b.conf":     "include a.conf;",
	}
	e := analyze(t, loop)
	if e.Flow != Unknown || !strings.Contains(strings.Join(e.Unread, " "), "includes itself") {
		t.Errorf("loop: %+v", e)
	}
	self := map[string]string{"/etc/nginx/nginx.conf": "http { include /etc/nginx/*.conf; }"}
	if e := analyze(t, self); e.Flow != Unknown {
		t.Errorf("self glob: %+v", e)
	}
	// A fan-out: each file includes the next level twice.
	fan := map[string]string{"/etc/nginx/nginx.conf": "include l0.conf; include l0.conf;"}
	for i := 0; i < 20; i++ {
		fan["/etc/nginx/l"+string(rune('a'+i))+".conf"] = ""
	}
	for i := 0; i < 19; i++ {
		fan["/etc/nginx/l"+itoa(i)+".conf"] = "include l" + itoa(i+1) + ".conf; include l" + itoa(i+1) + ".conf;"
	}
	fan["/etc/nginx/l19.conf"] = "http { server { listen 443 ssl http2; } }"
	c := Load(mem{files: fan}, "/etc/nginx/nginx.conf", nil)
	if len(c.Files) > MaxFiles || len(c.Unread) == 0 {
		t.Errorf("fan-out read %d files, unread %v", len(c.Files), c.Unread)
	}
	vars := map[string]string{"/etc/nginx/nginx.conf": "include $x.conf;"}
	if e := analyze(t, vars); e.Flow != Unknown {
		t.Errorf("variable include: %+v", e)
	}
	if e := analyze(t, map[string]string{}); e.Flow != Unknown || e.Reuse != Unknown {
		t.Errorf("no file: %+v", e)
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

func TestCommandLineDirectives(t *testing.T) {
	extra, err := Parse("-g", "daemon off; include /etc/nginx/h2.conf;")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"/etc/nginx/nginx.conf": "http { server { listen 443 ssl; } }", "/etc/nginx/h2.conf": "http { http2 on; }"}
	c := Load(mem{files: files}, "/etc/nginx/nginx.conf", extra)
	if len(c.Root) != 3 {
		t.Errorf("extra not added: %+v", c.Root)
	}
}

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{"443": "443", "*:443": "443", "[::]:443": "443", "10.0.0.1:8443": "8443", "localhost": "80", "unix:/run/x": "unix:/run/x", "[::1]": "80"} {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %q, want %q", in, got, want)
		}
	}
}
