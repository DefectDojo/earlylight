package conf

import (
	"strings"
	"testing"
)

// FuzzParse: any input parses or fails with an error, within the limits,
// and the loader and analysis never panic on what it gives.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"http { server { listen 443 ssl http2; location / { proxy_pass http://u; } } }",
		"events { worker_connections 1; } http { http2 on; include a/*.conf; }",
		"a 'b\\'c' \"d\\\"\" ${x} e\\;f;",
		"content_by_lua_block { -- } \n local s = [[ } ]] }",
		"http { server { listen [::]:443 ssl; ssl on; } }",
		"include include.conf;",
		"#",
		"}{;",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ds, err := Parse("f", s)
		if err != nil {
			return
		}
		files := map[string]string{"/etc/nginx/nginx.conf": s, "/etc/nginx/include.conf": s}
		c := Load(mem{files: files}, "/etc/nginx/nginx.conf", nil)
		e := Analyze(c)
		if e.Flow == "" || e.Reuse == "" || e.HTTP2 == "" {
			t.Fatalf("empty state: %+v", e)
		}
		if e.HTTP2 == "off" && (e.Flow != NotExposed || e.Reuse != NotExposed) {
			t.Fatalf("HTTP/2 off but %+v", e)
		}
		if e.HTTP2 == "off" && len(e.Unread) > 0 {
			t.Fatalf("off with unread files: %+v", e)
		}
		_ = ds
		if strings.Count(s, "{") > 10000 {
			t.Skip()
		}
	})
}
