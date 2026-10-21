package report

import "testing"

func TestSafe(t *testing.T) {
	for _, s := range []string{"\x1b[31mred", "a\nfake line", "\x9b31m", "bad\xffutf8", "tab\there"} {
		if got := safe(s); got == s {
			t.Errorf("%q passed through unescaped", s)
		}
	}
	for _, s := range []string{"/etc/ssl/certs/ca-certificates.crt", "app.jar!/BOOT-INF/lib/x.jar!/cacerts", "émSign ✓"} {
		if got := safe(s); got != s {
			t.Errorf("%q changed to %q", s, got)
		}
	}
}
