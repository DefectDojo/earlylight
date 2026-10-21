package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/detect"
)

func ctx(files map[string]string) Context {
	return Context{
		Read: func(p string) []byte {
			if s, ok := files[p]; ok {
				return []byte(s)
			}
			return nil
		},
		Exists: func(p string) bool { _, ok := files[p]; return ok },
	}
}

func one(t *testing.T, f detect.Finding, c Context) Result {
	t.Helper()
	r := Assess([]detect.Finding{f}, c)
	if len(r) != 1 {
		t.Fatalf("got %d results", len(r))
	}
	return r[0]
}

func root(path string) detect.Finding {
	return detect.Finding{Kind: detect.TrustsPathRoot, Path: path, SPKI: "AA"}
}

func TestDebianConf(t *testing.T) {
	src := "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt"
	cases := []struct {
		conf   *string
		status Status
	}{
		{ptr("mozilla/emSign_ECC_Root_CA_-_G3.crt\n"), Active},
		{ptr("!mozilla/emSign_ECC_Root_CA_-_G3.crt\n"), Inactive},
		{ptr("# comment\nmozilla/Other.crt\n"), Inactive},
		{nil, Active},
	}
	for i, c := range cases {
		files := map[string]string{}
		if c.conf != nil {
			files["/etc/ca-certificates.conf"] = *c.conf
		}
		if r := one(t, root(src), ctx(files)); r.Status != c.status {
			t.Errorf("case %d: got %v (%s)", i, r.Status, r.Reason)
		}
	}
}

func ptr(s string) *string { return &s }

func TestCompiledBundleAlwaysActive(t *testing.T) {
	// The compiled bundle is what clients read: a "!" in the conf does not matter
	// until update-ca-certificates has rebuilt it.
	files := map[string]string{"/etc/ca-certificates.conf": "!mozilla/emSign_ECC_Root_CA_-_G3.crt\n"}
	if r := one(t, root("/etc/ssl/certs/ca-certificates.crt"), ctx(files)); r.Status != Active {
		t.Fatalf("got %v", r.Status)
	}
}

func TestBlocklistDirAndSource(t *testing.T) {
	fs := []detect.Finding{
		root("/etc/pki/ca-trust/source/blocklist/emsign.pem"),
		root("/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit"),
		root("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"),
	}
	r := Assess(fs, ctx(nil))
	want := []Status{Inactive, Inactive, Active} // the extracted bundle is what clients use
	for i := range r {
		if r[i].Status != want[i] {
			t.Errorf("%s: got %v (%s)", r[i].Path, r[i].Status, r[i].Reason)
		}
	}
	// Without a blocklist entry the source bundle stays active.
	if r := one(t, root("/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit"), ctx(nil)); r.Status != Active {
		t.Fatalf("got %v", r.Status)
	}
}

func TestBotocore(t *testing.T) {
	p := "/usr/local/lib/python3.14/site-packages/botocore/cacert.pem"
	if r := one(t, root(p), ctx(map[string]string{"/usr/local/lib/python3.14/site-packages/certifi/cacert.pem": ""})); r.Status != Inactive {
		t.Fatalf("with certifi: got %v", r.Status)
	}
	if r := one(t, root(p), ctx(nil)); r.Status != Active {
		t.Fatalf("without certifi: got %v", r.Status)
	}
	av := "/opt/venv/lib/python3.12/site-packages/awscli/botocore/cacert.pem"
	if r := one(t, root(av), ctx(nil)); r.Status != Active {
		t.Fatalf("awscli without certifi: got %v", r.Status)
	}
}

func TestFileLevelFlags(t *testing.T) {
	f := root("/usr/bin/node")
	f.Blocklisted = true
	if r := one(t, f, ctx(nil)); r.Status != Inactive {
		t.Fatal("blocklisted binary should be inactive")
	}
	f = root("/x.p11-kit")
	f.Trust = "distrusted"
	if r := one(t, f, ctx(nil)); r.Status != Inactive {
		t.Fatal("distrusted should be inactive")
	}
	if r := one(t, root("/usr/local/go/src/crypto/x509/testdata/emudhra.pem"), ctx(nil)); r.Status != Inactive {
		t.Fatal("testdata should be inactive")
	}
	g := detect.Finding{Kind: detect.UnpatchedGo, Path: "/usr/local/bin/app"}
	if r := one(t, g, ctx(nil)); r.Status != Active {
		t.Fatal("unpatched Go is always active")
	}
}

func TestImageEnvRules(t *testing.T) {
	node := root("/usr/local/bin/node")
	c := ctx(nil)
	if r := one(t, node, c); r.Status != Active {
		t.Fatal("node without env must be active")
	}
	c.Env = []string{"PATH=/usr/bin", "NODE_OPTIONS=--max-old-space-size=4096 --use-openssl-ca"}
	if r := one(t, node, c); r.Status != Inactive {
		t.Fatalf("node with --use-openssl-ca: got %v", r.Status)
	}
	c.Env = []string{"NODE_OPTIONS=--use-system-ca"} // adds system roots, keeps bundled ones
	if r := one(t, node, c); r.Status != Active {
		t.Fatal("--use-system-ca must stay active")
	}
	boto := root("/opt/venv/lib/python3.12/site-packages/awscli/botocore/cacert.pem")
	c.Env = []string{"AWS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"}
	if r := one(t, boto, c); r.Status != Inactive {
		t.Fatalf("botocore with AWS_CA_BUNDLE: got %v", r.Status)
	}
	c.Env = []string{"AWS_CA_BUNDLE="}
	if r := one(t, boto, c); r.Status != Active {
		t.Fatal("empty AWS_CA_BUNDLE must stay active")
	}
}

// Archive member names are attacker-controlled: they must not trigger location rules.
func TestArchiveMembersIgnoreLocationRules(t *testing.T) {
	fs := []detect.Finding{
		root("/app.jar!/../../etc/pki/ca-trust/source/blocklist/x.pem"),
		root("/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit"),
		root("/app.jar!/testdata/cacerts"),
		root("/app.jar!/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt"),
	}
	for _, r := range Assess(fs, ctx(map[string]string{"/etc/ca-certificates.conf": "!mozilla/emSign_ECC_Root_CA_-_G3.crt\n"})) {
		if r.Status != Active {
			t.Errorf("%s: got %v (%s)", r.Path, r.Status, r.Reason)
		}
	}
}

func TestDebianPatchedCertifi(t *testing.T) {
	p := "/usr/lib/python3/dist-packages/certifi/cacert.pem"
	debianCore := "DEBIAN_CA_CERTS_PATH = '/etc/ssl/certs/ca-certificates.crt'\n\n\ndef where() -> str:\n    return DEBIAN_CA_CERTS_PATH\n"
	upstreamCore := "if sys.version_info >= (3, 11):\n    def where() -> str:\n        return _CACERT_PATH\n"
	// pip's vendored copy on Debian: upstream defs first, Debian's top-level def last.
	pipCore := upstreamCore + "\nDEBIAN_CA_CERTS_PATH = '/etc/ssl/certs/ca-certificates.crt'\n\n# Debian: Use system CA certs:\ndef where() -> str:\n    return DEBIAN_CA_CERTS_PATH\n"
	literal := "def where():\n    return \"/etc/pki/tls/certs/ca-bundle.crt\"\n"
	selfRef := "def where():\n    return \"/opt/app/certifi/cacert.pem\"\n"
	for name, c := range map[string]struct {
		core string
		want Status
	}{"pip": {pipCore, Inactive}, "literal": {literal, Inactive}, "self": {selfRef, Active}} {
		if r := one(t, root(p), ctx(map[string]string{"/usr/lib/python3/dist-packages/certifi/core.py": c.core})); r.Status != c.want {
			t.Errorf("%s: got %v", name, r.Status)
		}
	}
	if r := one(t, root(p), ctx(map[string]string{"/usr/lib/python3/dist-packages/certifi/core.py": debianCore})); r.Status != Inactive {
		t.Fatalf("debian certifi: %v", r.Status)
	}
	if r := one(t, root(p), ctx(map[string]string{"/usr/lib/python3/dist-packages/certifi/core.py": upstreamCore})); r.Status != Active {
		t.Fatalf("upstream certifi: %v", r.Status)
	}
	// Inside a wheel, the sibling core.py in the same wheel counts.
	w := "/usr/share/python-wheels/pip-23.0.1-py3-none-any.whl!/pip/_vendor/certifi/cacert.pem"
	if r := one(t, root(w), ctx(map[string]string{"/usr/share/python-wheels/pip-23.0.1-py3-none-any.whl!/pip/_vendor/certifi/core.py": debianCore})); r.Status != Inactive {
		t.Fatalf("debian pip wheel: %v", r.Status)
	}
}

func TestSUSEAndBSDBlocklists(t *testing.T) {
	fs := []detect.Finding{
		root("/etc/pki/trust/blacklist/emSign ECC Root CA - G3.pem"),
		root("/usr/share/pki/trust/ca-certificates-mozilla.trust.p11-kit"),
		root("/usr/share/certs/untrusted/emsign.pem"),
		root("/var/lib/ca-certificates/ca-bundle.pem"),
	}
	r := Assess(fs, ctx(nil))
	want := []Status{Inactive, Inactive, Inactive, Active}
	for i := range r {
		if r[i].Status != want[i] {
			t.Errorf("%s: got %v (%s)", r[i].Path, r[i].Status, r[i].Reason)
		}
	}
}

func TestPlatformStores(t *testing.T) {
	for _, p := range []string{
		"/System/Library/Keychains/SystemRootCertificates.keychain",
		"/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Google Chrome Framework",
		"/usr/lib/firefox/libnssckbi.so",
	} {
		if r := one(t, root(p), ctx(nil)); r.Status != Platform {
			t.Errorf("%s: got %v", p, r.Status)
		}
	}
	// System NSS used by non-browser software has no OneCRL: stays active.
	if r := one(t, root("/usr/lib64/libnssckbi.so"), ctx(nil)); r.Status != Active {
		t.Error("system libnssckbi must stay active")
	}
	g := detect.Finding{Kind: detect.UnpatchedGo, Path: "/usr/local/bin/app", Binary: "macho"}
	if r := one(t, g, ctx(nil)); r.Status != Platform {
		t.Error("macOS Go binary should be platform-managed")
	}
	g.Binary = "pe"
	if r := one(t, g, ctx(nil)); r.Status != Active {
		t.Error("Windows Go binary stays active (Microsoft trusts the emSign G3 CAs)")
	}
}

func TestConfDuplicateLines(t *testing.T) {
	src := "/usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt"
	for _, conf := range []string{
		"mozilla/emSign_ECC_Root_CA_-_G3.crt\n!mozilla/emSign_ECC_Root_CA_-_G3.crt\n",
		"!mozilla/emSign_ECC_Root_CA_-_G3.crt\nmozilla/emSign_ECC_Root_CA_-_G3.crt\n",
	} {
		if r := one(t, root(src), ctx(map[string]string{"/etc/ca-certificates.conf": conf})); r.Status != Active {
			t.Errorf("conf %q: got %v", conf, r.Status)
		}
	}
}
