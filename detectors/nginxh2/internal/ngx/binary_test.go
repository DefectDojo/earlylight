package ngx_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
)

func TestInspectOfficial(t *testing.T) {
	b, ok := ngx.Inspect("/usr/sbin/nginx", ngxtest.Default("1.31.8").Bytes())
	if !ok {
		t.Fatal("not recognised")
	}
	if b.Product != ngx.Nginx || b.Version != "1.31.8" || b.HTTP2 != ngx.Yes || b.TLS != ngx.Yes || b.ConfPath != "/etc/nginx/nginx.conf" || b.Bits != 64 || b.Arch != "x86_64" || b.Conflict != "" {
		t.Errorf("got %+v", b)
	}
}

func TestInspectProducts(t *testing.T) {
	ubuntu := ngxtest.Default("1.24.0")
	ubuntu.Line = "nginx/1.24.0 (Ubuntu)"
	or := ngxtest.Default("x")
	or.Line, or.Extra = "openresty/1.31.8.1", []string{"openresty/1.31.8.1", "1.31.8"}
	plus := ngxtest.Default("1.27.2")
	plus.Line = "nginx/1.27.2 (nginx-plus-r33-p2)"
	te := ngxtest.Default("1.31.5")
	te.Tengine = "Tengine/3.2.0"
	an := ngxtest.Default("1.31.3")
	an.Angie, an.Extra = "Angie/1.12.4", []string{"Angie/1.12.4", "nginx/1.31.3"}
	other := ngxtest.Default("1.0")
	other.Line, other.Extra = "WAF/2.1", nil
	cases := []struct {
		name    string
		b       ngxtest.Build
		product ngx.Product
		version string
		core    string
		extra   func(*ngx.Binary) bool
	}{
		{"ubuntu", ubuntu, ngx.Nginx, "1.24.0", "1.24.0", func(b *ngx.Binary) bool { return b.Build == "Ubuntu" }},
		{"openresty", or, ngx.OpenResty, "1.31.8.1", "1.31.8", nil},
		{"plus", plus, ngx.Plus, "1.27.2", "1.27.2", func(b *ngx.Binary) bool { return b.PlusRelease == "r33-p2" }},
		{"tengine", te, ngx.Tengine, "3.2.0", "1.31.5", nil},
		{"angie", an, ngx.Angie, "1.12.4", "", nil},
		{"other", other, ngx.Other, "2.1", "", nil},
	}
	for _, c := range cases {
		b, ok := ngx.Inspect("/x", c.b.Bytes())
		if !ok {
			t.Errorf("%s: not recognised", c.name)
			continue
		}
		if b.Product != c.product || b.Version != c.version || b.Core != c.core || b.Conflict != "" || c.extra != nil && !c.extra(b) {
			t.Errorf("%s: got %+v", c.name, b)
		}
	}
}

func TestInspectHiddenAndConflicts(t *testing.T) {
	hidden := ngxtest.Default("1.31.8")
	hidden.Line, hidden.Extra = "", nil
	b, ok := ngx.Inspect("/x", hidden.Bytes())
	if !ok || b.Product != ngx.Hidden {
		t.Fatalf("hidden: %v %+v", ok, b)
	}
	// A version line that disagrees with the Server header string.
	edited := ngxtest.Default("1.31.9")
	edited.Extra = []string{"Server: nginx/1.31.8\r\n"}
	if b, _ := ngx.Inspect("/x", edited.Bytes()); b.Conflict == "" {
		t.Error("an edited version line was not noticed")
	}
	two := ngxtest.Default("1.31.9")
	two.Extra = append(two.Extra, "nginx version: nginx/1.31.8\n")
	if b, _ := ngx.Inspect("/x", two.Bytes()); b.Conflict == "" {
		t.Error("two version lines were not noticed")
	}
	// Paths with nginx/ are not versions.
	paths := ngxtest.Default("1.31.9")
	paths.Extra = append(paths.Extra, "/etc/nginx/nginx.conf", "/usr/lib/nginx/1modules", "<center>nginx/1.31.9</center>")
	if b, _ := ngx.Inspect("/x", paths.Bytes()); b.Conflict != "" {
		t.Errorf("paths read as versions: %s", b.Conflict)
	}
}

func TestInspectRejects(t *testing.T) {
	// A dynamic module imports ngx_core_module but has no configure line.
	mod := []byte("\x7fELF\x02\x01\x00ngx_core_module\x00ngx_http_v2_module\x00")
	if _, ok := ngx.Inspect("/m.so", mod); ok {
		t.Error("a dynamic module was taken for nginx")
	}
	if _, ok := ngx.Inspect("/x", []byte("\x7fELF\x00configure arguments: --prefix=/x\n\x00")); ok {
		t.Error("configure arguments alone made an nginx binary")
	}
}

func TestFeatures(t *testing.T) {
	noV2 := ngxtest.Default("1.31.8")
	noV2.Configure = "--prefix=/etc/nginx --with-http_ssl_module"
	noV2.Modules = []string{"ngx_core_module", "ngx_http_ssl_module"}
	b, _ := ngx.Inspect("/x", noV2.Bytes())
	if b.HTTP2 != ngx.No || b.TLS != ngx.Yes {
		t.Errorf("no v2: %+v", b)
	}
	// Before 1.9.11 there is no module list: the configure flag shows
	// what is in, and nothing shows what is out.
	old := ngxtest.Build{Line: "nginx/1.9.6", Configure: "--with-http_v2_module"}
	b, _ = ngx.Inspect("/x", old.Bytes())
	if b.HTTP2 != ngx.Yes || b.TLS != ngx.Unknown {
		t.Errorf("old: %+v", b)
	}
	// Empty configure arguments and no module list: not known.
	bare := ngxtest.Build{Line: "nginx/1.9.6"}
	b, _ = ngx.Inspect("/x", bare.Bytes())
	if b.HTTP2 != ngx.Unknown {
		t.Errorf("bare: %+v", b)
	}
	// --with-http_v2_module_x is not the flag.
	near := ngxtest.Build{Line: "nginx/1.9.6", Configure: "--with-http_v2_modulex --prefix=/usr/local/nginx", Modules: []string{"ngx_core_module"}}
	b, _ = ngx.Inspect("/x", near.Bytes())
	if b.HTTP2 != ngx.No || b.ConfPath != "/usr/local/nginx/conf/nginx.conf" {
		t.Errorf("near: %+v", b)
	}
}

func TestBits(t *testing.T) {
	b32 := ngxtest.Default("1.31.8")
	b32.Bits, b32.Machine = 32, 3
	b, _ := ngx.Inspect("/x", b32.Bytes())
	if b.Bits != 32 || b.Arch != "i386" {
		t.Errorf("32-bit: %+v", b)
	}
	arm := ngxtest.Default("1.31.8")
	arm.Machine = 183
	b, _ = ngx.Inspect("/x", arm.Bytes())
	if b.Arch != "aarch64" {
		t.Errorf("arm64: %+v", b)
	}
}

// TestRealBinaries reads the binaries in testdata/real when they are
// there (they are not committed: NGINXH2_REAL points at a directory of
// binaries copied out of images, named <expected product>_<version>).
func TestRealBinaries(t *testing.T) {
	dir := os.Getenv("NGINXH2_REAL")
	if dir == "" {
		t.Skip("NGINXH2_REAL not set")
	}
	ms, _ := filepath.Glob(filepath.Join(dir, "*.bin"))
	for _, m := range ms {
		data, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		b, ok := ngx.Inspect(m, data)
		if !ok || b.Conflict != "" || b.Version == "" || b.HTTP2 != ngx.Yes {
			t.Errorf("%s: %v %+v", m, ok, b)
			continue
		}
		t.Logf("%s: %s %s core %s build %q conf %s", filepath.Base(m), b.Product, b.Version, b.Core, b.Build, b.ConfPath)
	}
}
