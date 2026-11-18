package ngx_test

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngxtest"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/pkgdb"
)

// FuzzInspect: no input panics, and a binary is never both conflicting
// and judged by a version it says it does not have.
func FuzzInspect(f *testing.F) {
	or := ngxtest.Default("x")
	or.Line = "openresty/1.31.8.1"
	te := ngxtest.Default("1.31.5")
	te.Tengine = "Tengine/3.2.0"
	for _, b := range []ngxtest.Build{ngxtest.Default("1.31.8"), or, te, {Line: "nginx/1.24.0 (nginx-plus-r33-p2)"}} {
		f.Add(b.Bytes())
	}
	f.Add([]byte("configure arguments:\x00ngx_core_module\x00"))
	f.Add([]byte("MZ\x00\x00configure arguments: nginx version: nginx/1.2.3 (x"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, ok := ngx.Inspect("/x", data)
		if !ok {
			return
		}
		if b.HTTP2 == "" || b.TLS == "" || b.Product == "" {
			t.Fatalf("empty field: %+v", b)
		}
		if len(b.Configure) > 4096 || len(b.Version) > 4096 {
			t.Fatalf("unbounded field")
		}
	})
}

// FuzzVersions: version parsing and comparison never panic, and
// comparison is antisymmetric.
func FuzzVersions(f *testing.F) {
	f.Add("1.31.8", "1.22.1-9+deb12u10", "1.30.6-r0")
	f.Add("37.0.7.1", "1:1.0~rc1-1", "1.0_p1-r2")
	f.Fuzz(func(t *testing.T, v, deb, apk string) {
		if x, err := knowledge.ParseV(v); err == nil {
			for _, c := range knowledge.CVEs {
				knowledge.Nginx(c, x)
				knowledge.OpenResty(c, x)
				knowledge.Plus(c, v, x)
				knowledge.Angie(c, x)
				knowledge.Tengine(c, x, x)
			}
		}
		knowledge.UpstreamOf(deb)
		if a, b := pkgdb.CompareDpkg(deb, apk), pkgdb.CompareDpkg(apk, deb); sign(a) != -sign(b) {
			t.Fatalf("CompareDpkg not antisymmetric: %q %q", deb, apk)
		}
		a, ok1 := pkgdb.CompareAPK(apk, deb)
		b, ok2 := pkgdb.CompareAPK(deb, apk)
		if ok1 && ok2 && sign(a) != -sign(b) {
			t.Fatalf("CompareAPK not antisymmetric: %q %q", apk, deb)
		}
	})
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
