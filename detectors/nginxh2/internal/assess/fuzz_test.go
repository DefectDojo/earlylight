package assess

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
)

// FuzzStart: any start command reads without a panic, and the
// configuration path it gives is absolute.
func FuzzStart(f *testing.F) {
	f.Add("sh -c", "exec nginx \\\n -qc /x.conf -g 'include /y;'", "40-x.sh")
	f.Add("/docker-entrypoint.sh nginx", "-g daemon\\ off;", "")
	f.Add("", "'unterminated", "10-listen-on-ipv6-by-default.sh")
	f.Fuzz(func(t *testing.T, lead, rest, script string) {
		cmd := append(strings.Fields(lead), rest)
		nginxOptions(strings.Fields(rest))
		b := &ngx.Binary{ConfPath: "/etc/nginx/nginx.conf", ConfRaw: "/etc/nginx/nginx.conf"}
		main, _, _, _ := configFor(b, Input{Command: cmd, Launcher: func(w string) (bool, string) { return w == script, "" }})
		if !strings.HasPrefix(main, "/") {
			t.Fatalf("relative configuration path %q", main)
		}
	})
}
