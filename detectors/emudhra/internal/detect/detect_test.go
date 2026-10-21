package detect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/knowledge"
)

func mustDetector(t testing.TB) *Detector {
	t.Helper()
	d, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func keyByName(t testing.TB, name string) *knowledge.Key {
	t.Helper()
	kb, err := knowledge.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kb.Keys {
		if k.Name == name {
			return k
		}
	}
	t.Fatalf("no key %q", name)
	return nil
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// selfSigned makes an ordinary certificate with a random (strong) key.
func selfSigned(t testing.TB, cn string) *x509.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return certWithKey(t, cn, k)
}

func certWithKey(t testing.TB, cn string, k *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(0, 0).Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func kinds(fs []Finding) map[Kind]int {
	m := map[Kind]int{}
	for _, f := range fs {
		m[f.Kind]++
	}
	return m
}

func TestPEMBundle(t *testing.T) {
	d := mustDetector(t)
	g3 := keyByName(t, "emSign ECC Root CA - G3").Certs[0]
	bundle := append(pemOf(selfSigned(t, "Some Other Root")), pemOf(g3)...)
	fs := d.Scan("/etc/ssl/certs/ca-certificates.crt", bundle)
	if len(fs) != 1 || fs[0].Kind != TrustsPathRoot || fs[0].Method != "pem" {
		t.Fatalf("got %+v", fs)
	}
}

func TestCompromisedIntermediateInBundle(t *testing.T) {
	d := mustDetector(t)
	k := keyByName(t, "EM OV TLS CA - G3C")
	fs := d.Scan("/x.pem", pemOf(k.Certs[1]))
	if len(fs) != 1 || fs[0].Kind != TrustsCompromisedKey || fs[0].Scalar != 4 {
		t.Fatalf("got %+v", fs)
	}
}

// Node.js compiles roots in as NUL-terminated C strings; encoding/pem rejects that.
func TestPEMWithNULTerminators(t *testing.T) {
	d := mustDetector(t)
	g3 := pemOf(keyByName(t, "emSign ECC Root CA - G3").Certs[0])
	g3 = bytes.TrimSuffix(g3, []byte("\n"))
	bin := bytes.Join([][]byte{[]byte("\x7fELF..."), g3, make([]byte, 8), []byte("trailing")}, nil)
	if k := kinds(d.Scan("/usr/local/bin/node", bin)); k[TrustsPathRoot] != 1 {
		t.Fatalf("got %v", k)
	}
}

// PEM inside source-code string literals: quotes and literal \n escapes per line.
func TestPEMInSourceLiteral(t *testing.T) {
	d := mustDetector(t)
	lines := strings.Split(strings.TrimSpace(string(pemOf(keyByName(t, "emSign ECC Root CA - G3").Certs[0]))), "\n")
	var src strings.Builder
	for _, l := range lines {
		src.WriteString("\"" + l + "\\n\"\n")
	}
	if k := kinds(d.Scan("/src/node_root_certs.h", []byte(src.String()))); k[TrustsPathRoot] != 1 {
		t.Fatalf("got %v", k)
	}
}

func TestDERFile(t *testing.T) {
	d := mustDetector(t)
	c := keyByName(t, "AAA Certificate Services").Certs[0]
	fs := d.Scan("/aaa.der", c.Raw)
	if len(fs) != 1 || fs[0].Kind != TrustsPathRoot {
		t.Fatalf("got %+v", fs)
	}
}

// JKS keystores, webpki-roots and similar keep keys outside PEM.
func TestRawKeyBytes(t *testing.T) {
	d := mustDetector(t)
	k := keyByName(t, "EM EV TLS CA - G3C")
	blob := append(append(bytes.Repeat([]byte{0xAB}, 1000), k.RawKey...), bytes.Repeat([]byte{0xCD}, 1000)...)
	fs := d.Scan("/bin/app", blob)
	if len(fs) != 1 || fs[0].Kind != TrustsCompromisedKey || fs[0].Method != "raw-key" || fs[0].Scalar != 56 {
		t.Fatalf("got %+v", fs)
	}
}

func TestWeakKeyGeneric(t *testing.T) {
	d := mustDetector(t)
	// A brand-new certificate with private key 12345: not on any list, still caught.
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = big.NewInt(12345)
	priv.X, priv.Y = elliptic.P256().ScalarBaseMult(priv.D.Bytes())
	c := certWithKey(t, "Weak Test CA", priv)
	fs := d.Scan("/weak.pem", pemOf(c))
	if len(fs) != 1 || fs[0].Kind != WeakKey || fs[0].Scalar != 12345 {
		t.Fatalf("got %+v", fs)
	}
}

func TestNoFalsePositives(t *testing.T) {
	d := mustDetector(t)
	var bundle []byte
	for i := 0; i < 50; i++ {
		bundle = append(bundle, pemOf(selfSigned(t, "Root"))...)
	}
	noise := make([]byte, 1<<20)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"bundle": bundle, "noise": noise} {
		if fs := d.Scan("/"+name, data); len(fs) != 0 {
			t.Fatalf("%s: unexpected findings %+v", name, fs)
		}
	}
}

func TestP11KitDistrusted(t *testing.T) {
	d := mustDetector(t)
	g3 := pemOf(keyByName(t, "emSign ECC Root CA - G3").Certs[0])
	other := pemOf(selfSigned(t, "Other"))
	file := "[p11-kit-object-v1]\nlabel: \"Other\"\ntrusted: true\n" + string(other) +
		"\n[p11-kit-object-v1]\nlabel: \"emSign ECC Root CA - G3\"\nx-distrusted: true\n" + string(g3)
	fs := d.Scan("/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit", []byte(file))
	if len(fs) != 1 || fs[0].Trust != "distrusted" {
		t.Fatalf("got %+v", fs)
	}
	// Same object without the flag is plain trust.
	file2 := "[p11-kit-object-v1]\ntrusted: true\n" + string(g3)
	if fs := d.Scan("/x.p11-kit", []byte(file2)); len(fs) != 1 || fs[0].Trust != "" {
		t.Fatalf("got %+v", fs)
	}
}

func trustedBlock(t *testing.T, c *x509.Certificate, trust, reject []asn1.ObjectIdentifier) []byte {
	t.Helper()
	type aux struct {
		Trust  []asn1.ObjectIdentifier `asn1:"optional"`
		Reject []asn1.ObjectIdentifier `asn1:"optional,tag:0"`
	}
	a, err := asn1.Marshal(aux{Trust: trust, Reject: reject})
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: append(append([]byte{}, c.Raw...), a...)})
}

func TestOpenSSLTrustSettings(t *testing.T) {
	d := mustDetector(t)
	aaa := keyByName(t, "AAA Certificate Services").Certs[0]
	email := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	cases := []struct {
		name          string
		trust, reject []asn1.ObjectIdentifier
		wantTrust     string
		wantPurposes  []string
	}{
		// RHEL's real entry for AAA: e-mail and code signing only.
		{"rhel-aaa", []asn1.ObjectIdentifier{email, oidCodeSigning}, nil, "", []string{"code-signing"}},
		{"email-only", []asn1.ObjectIdentifier{email}, nil, "no-usable-purpose", []string{}},
		{"reject-all", nil, []asn1.ObjectIdentifier{oidAnyEKU}, "no-usable-purpose", []string{}},
		{"reject-server", nil, []asn1.ObjectIdentifier{oidServerAuth}, "", []string{"tls-client", "code-signing"}},
		{"tls", []asn1.ObjectIdentifier{oidServerAuth}, nil, "", []string{"tls-server"}},
	}
	for _, c := range cases {
		fs := d.Scan("/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", trustedBlock(t, aaa, c.trust, c.reject))
		if len(fs) != 1 || fs[0].Trust != c.wantTrust || strings.Join(fs[0].Purposes, ",") != strings.Join(c.wantPurposes, ",") {
			t.Errorf("%s: got %+v", c.name, fs)
		}
	}
	// No trust settings at all: trusted for everything, no restriction recorded.
	blk := pem.EncodeToMemory(&pem.Block{Type: "TRUSTED CERTIFICATE", Bytes: aaa.Raw})
	if fs := d.Scan("/t.crt", blk); len(fs) != 1 || fs[0].Trust != "" || fs[0].Purposes != nil {
		t.Fatalf("got %+v", fs)
	}
}

func TestHasBlocklistRawOnly(t *testing.T) {
	d := mustDetector(t)
	hashes := d.compromisedSPKIs()
	var raw, seven, hexes, b64 []byte
	for i, h := range hashes {
		raw = append(append(raw, h...), 0)
		if i < 7 {
			seven = append(append(seven, h...), 0)
		}
		hexes = append(hexes, strings.ToUpper(hex.EncodeToString(h))...)
		b64 = append(b64, base64.StdEncoding.EncodeToString(h)...)
	}
	if !d.HasBlocklist(raw) {
		t.Error("raw Node.js-style blocklist not recognised")
	}
	if d.HasBlocklist(seven) {
		t.Error("seven of eight must not count")
	}
	// A data file that merely lists the hashes as text is not a blocklist.
	if d.HasBlocklist(hexes) || d.HasBlocklist(b64) {
		t.Error("text hashes must not count as a compiled blocklist")
	}
}

func TestBlocklistMarksRootsInSameFile(t *testing.T) {
	d := mustDetector(t)
	g3 := pemOf(keyByName(t, "emSign ECC Root CA - G3").Certs[0])
	var raw []byte
	for _, h := range d.compromisedSPKIs() {
		raw = append(raw, h...)
	}
	fs := d.Scan("/bin/x", append(g3, raw...))
	if len(fs) != 1 || !fs[0].Blocklisted {
		t.Fatalf("got %+v", fs)
	}
}

func TestGoHasBlocklist(t *testing.T) {
	cases := map[string][2]bool{ // fixed, known
		"go1.27.3": {true, true}, "go1.27.10": {true, true}, "go1.27.2": {false, true}, "go1.27": {false, true},
		"go1.26.10": {true, true}, "go1.26.9": {false, true}, "go1.25.12": {false, true}, "go1.21.0": {false, true},
		"go1.28": {true, true}, "go1.27.3 X:boringcrypto": {true, true}, "go1.27.2 X:boringcrypto": {false, true},
		"go1.28rc1": {false, false}, "devel go1.28-abc": {false, false}, "": {false, false}, "go2": {false, false},
		"go1.27.3.1": {false, false},
	}
	for v, want := range cases {
		fixed, known := GoHasBlocklist(v)
		if fixed != want[0] || known != want[1] {
			t.Errorf("%q: got fixed=%v known=%v, want %v", v, fixed, known, want)
		}
	}
}

func TestChainIssuedByCompromised(t *testing.T) {
	d := mustDetector(t)
	// Forge a leaf with the compromised key EM OV TLS CA - G3C (k = 4): exactly what
	// an attacker can do.
	ca := keyByName(t, "EM OV TLS CA - G3C").Certs[0]
	priv := &ecdsa.PrivateKey{D: big.NewInt(4)}
	priv.PublicKey = *ca.PublicKey.(*ecdsa.PublicKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "victim.example"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(0, 0).Add(time.Hour), DNSNames: []string{"victim.example"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	fs := d.Chain("victim.example:443", []*x509.Certificate{leaf, ca})
	k := kinds(fs)
	if k[IssuedByCompromised] != 1 || k[TrustsCompromisedKey] != 1 {
		t.Fatalf("got %v", k)
	}
	// A normal server chain, including a path root, reports nothing.
	g3 := keyByName(t, "AAA Certificate Services").Certs[0]
	if fs := d.Chain("ok:443", []*x509.Certificate{selfSigned(t, "ok"), g3}); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func FuzzScan(f *testing.F) {
	d := mustDetector(f)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"))
	f.Add([]byte("[p11-kit-object-v1]\nx-distrusted: true\n-----BEGIN TRUSTED CERTIFICATE-----\n-----END TRUSTED CERTIFICATE-----"))
	f.Add([]byte{0x30, 0x82, 0xff, 0xff, 0x02})
	f.Add([]byte("\xff Go buildinf:\x08\x02"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = d.Scan("/fuzz", data)
	})
}

func FuzzLooseBase64(f *testing.F) {
	f.Add([]byte("\"MII\\nAB\\r\""))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = decodeLooseBase64(b)
		_ = extractPEM(b)
		_ = leadingSequence(b)
		_, _ = exposedPurposes(b)
	})
}

func FuzzGoHasBlocklist(f *testing.F) {
	f.Add("go1.27.3")
	f.Fuzz(func(t *testing.T, v string) {
		fixed, known := GoHasBlocklist(v)
		if fixed && !known {
			t.Fatalf("fixed but unknown for %q", v)
		}
	})
}

// Many BEGIN markers and no END must stay linear (it was 64 KB of searching each).
func TestManyBeginsNoEndIsFast(t *testing.T) {
	d := mustDetector(t)
	data := bytes.Repeat([]byte("-----BEGIN CERTIFICATE-----\n"), 200000) // ~5.6 MB
	start := time.Now()
	d.Scan("/evil", data)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("took %v", el)
	}
	// A real block after the noise is still found.
	g3 := pemOf(keyByName(t, "emSign ECC Root CA - G3").Certs[0])
	if k := kinds(d.Scan("/evil2", append(data, g3...))); k[TrustsPathRoot] != 1 {
		t.Fatalf("got %v", k)
	}
}

func TestPEMVariants(t *testing.T) {
	d := mustDetector(t)
	g3 := keyByName(t, "emSign ECC Root CA - G3").Certs[0]
	body := base64.StdEncoding.EncodeToString(g3.Raw)
	var lines []string
	for i := 0; i < len(body); i += 64 {
		j := i + 64
		if j > len(body) {
			j = len(body)
		}
		lines = append(lines, body[i:j])
	}
	cases := map[string]string{
		"headers": "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: none\n\n" + strings.Join(lines, "\n") + "\n-----END CERTIFICATE-----\n",
		"json":    `{"ca":"-----BEGIN CERTIFICATE-----\n` + strings.NewReplacer("+", `+`, "/", `\/`).Replace(strings.Join(lines, `\n`)) + `\n-----END CERTIFICATE-----"}`,
		"crlf":    "-----BEGIN CERTIFICATE-----\r\n" + strings.Join(lines, "\r\n") + "\r\n-----END CERTIFICATE-----\r\n",
	}
	for name, text := range cases {
		if k := kinds(d.Scan("/"+name, []byte(text))); k[TrustsPathRoot] != 1 {
			t.Errorf("%s: got %v", name, k)
		}
	}
}

func TestPKCS7PEM(t *testing.T) {
	d := mustDetector(t)
	g3 := keyByName(t, "emSign ECC Root CA - G3").Certs[0]
	// A degenerate signedData carrying the certificate, as `openssl crl2pkcs7` writes.
	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      struct{ Type asn1.ObjectIdentifier }
		Certificates     asn1.RawValue `asn1:"tag:0,optional"`
	}
	sd := signedData{Version: 1, DigestAlgorithms: asn1.RawValue{Tag: asn1.TagSet, IsCompound: true, Class: asn1.ClassUniversal}}
	sd.ContentInfo.Type = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	sd.Certificates = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: g3.Raw}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}, asn1.RawValue{FullBytes: inner}})
	if err != nil {
		t.Fatal(err)
	}
	p7 := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: outer})
	if k := kinds(d.Scan("/bundle.p7b", p7)); k[TrustsPathRoot] != 1 {
		t.Fatalf("got %v", k)
	}
}

func TestBase64OfPEM(t *testing.T) {
	d := mustDetector(t)
	g3 := pemOf(keyByName(t, "emSign ECC Root CA - G3").Certs[0])
	secret := "apiVersion: v1\nkind: Secret\ndata:\n  ca.crt: " + base64.StdEncoding.EncodeToString(g3) + "\n"
	if k := kinds(d.Scan("/k8s/secret.yaml", []byte(secret))); k[TrustsPathRoot] != 1 {
		t.Fatalf("got %v", k)
	}
}

// RHEL/SUSE p11-kit: an x-certificate-extension object limits a root's EKU.
func TestP11KitEKUExtension(t *testing.T) {
	d := mustDetector(t)
	aaa := keyByName(t, "AAA Certificate Services").Certs[0]
	spki := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: aaa.RawSubjectPublicKeyInfo})
	extFor := func(oids ...asn1.ObjectIdentifier) string {
		v, _ := asn1.Marshal(oids)
		e, _ := asn1.Marshal(struct {
			ID       asn1.ObjectIdentifier
			Critical bool
			Value    []byte
		}{asn1.ObjectIdentifier{2, 5, 29, 37}, true, v})
		var b strings.Builder
		for _, c := range e {
			fmt.Fprintf(&b, "%%%02x", c)
		}
		return b.String()
	}
	email := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	file := func(ext string) []byte {
		return []byte("[p11-kit-object-v1]\nlabel: \"Comodo AAA Services root\"\nclass: x-certificate-extension\nobject-id: 2.5.29.37\nvalue: \"" + ext + "\"\nmodifiable: false\n" + string(spki) +
			"\n[p11-kit-object-v1]\nlabel: \"Comodo AAA Services root\"\ntrusted: true\n" + string(pemOf(aaa)))
	}
	// SUSE's real case: e-mail only.
	fs := d.Scan("/usr/share/pki/trust/ca-certificates-mozilla.trust.p11-kit", file(extFor(email)))
	if len(fs) != 1 || fs[0].Trust != "no-usable-purpose" {
		t.Fatalf("email-only: got %+v", fs)
	}
	// RHEL's real case: e-mail and code signing.
	fs = d.Scan("/x.p11-kit", file(extFor(email, oidCodeSigning)))
	if len(fs) != 1 || fs[0].Trust != "" || strings.Join(fs[0].Purposes, ",") != "code-signing" {
		t.Fatalf("email+codesign: got %+v", fs)
	}
}

func TestPKCS12Limits(t *testing.T) {
	d := mustDetector(t)
	// Minimal PFX shape with a MAC demanding 2^31-1 iterations.
	mac, _ := asn1.Marshal(struct {
		Mac        asn1.RawValue
		Salt       []byte
		Iterations int
	}{asn1.RawValue{FullBytes: []byte{0x30, 0x00}}, []byte("salt"), 1<<31 - 1})
	authSafe, _ := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}{oidPKCS7Data, asn1.RawValue{FullBytes: []byte{0x04, 0x02, 0x30, 0x00}}})
	pfx, _ := asn1.Marshal(struct {
		Version  int
		AuthSafe asn1.RawValue
		MacData  asn1.RawValue
	}{3, asn1.RawValue{FullBytes: authSafe}, asn1.RawValue{FullBytes: mac}})
	start := time.Now()
	_, skips := d.ScanAll("/evil.p12", pfx)
	if time.Since(start) > 2*time.Second {
		t.Fatal("iteration cap not applied")
	}
	if len(skips) != 1 || !strings.Contains(skips[0].Reason, "iterations") {
		t.Fatalf("got skips %+v", skips)
	}
}

func TestLeafIssuedByCompromisedInFile(t *testing.T) {
	d := mustDetector(t)
	ca := keyByName(t, "EM OV TLS CA - G3C").Certs[0]
	priv := &ecdsa.PrivateKey{D: big.NewInt(4)}
	priv.PublicKey = *ca.PublicKey.(*ecdsa.PublicKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "server.example"},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(0, 0).Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	if k := kinds(d.Scan("/etc/nginx/server.crt", pemOf(leaf))); k[IssuedByCompromised] != 1 {
		t.Fatalf("got %v", k)
	}
}

// The Go probes built with real toolchains, when present (validation/probes).
func TestGoBlocklistEvidenceOnRealBinaries(t *testing.T) {
	d := mustDetector(t)
	for v, wantFlag := range map[string]bool{"1.27.2": true, "1.26.9": true, "1.27.3": false, "1.26.10": false} {
		b, err := os.ReadFile("../../validation/probes/probe-go-" + v)
		if err != nil {
			t.Skip("probe binaries not built")
		}
		if got := kinds(d.Scan("/probe", b))[UnpatchedGo] == 1; got != wantFlag {
			t.Errorf("go%s: unpatched-go reported %v, want %v", v, got, wantFlag)
		}
		// Appending the eight hashes as text must not make an unpatched binary look fixed.
		var text []byte
		for _, h := range d.compromisedSPKIs() {
			text = append(text, hex.EncodeToString(h)...)
		}
		if wantFlag && kinds(d.Scan("/probe", append(b, text...)))[UnpatchedGo] != 1 {
			t.Errorf("go%s: text hashes hid the finding", v)
		}
	}
}
