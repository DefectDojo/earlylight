// Package detect inspects one file's bytes and reports facts about it.
//
// Every finding is a fact the user can re-check by hand:
//   - a certificate in the file carries a tracked key (exact public-key match), or
//     an elliptic-curve key whose private scalar is tiny (proved by k·G);
//   - the raw bytes of a tracked public key appear in the file (exact match), which
//     catches stores that keep keys outside PEM, such as JKS keystores, Rust's
//     webpki-roots and DER files;
//   - the file is a Go binary that links crypto/x509 certificate verification and
//     was built with a Go release that predates the blocklist for these keys.
//
// Nothing is reported from a certificate's name alone.
package detect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/weakkey"
	"software.sslmate.com/src/go-pkcs12"
)

// Kind of finding.
type Kind string

const (
	// TrustsCompromisedKey: the file contains a certificate (or the raw key) of one of
	// the eight compromised intermediates. Any software that treats the file as a
	// trust store trusts a key anyone can forge with.
	TrustsCompromisedKey Kind = "compromised-key"
	// TrustsPathRoot: the file contains a CA that issued or cross-signed the
	// compromised intermediates. Software that trusts it and does not block the
	// intermediates accepts certificates forged with the compromised keys.
	TrustsPathRoot Kind = "path-root"
	// WeakKey: a certificate in the file has an elliptic-curve key whose private
	// scalar is below 2^16 (or its negation is). Its private key is public knowledge.
	WeakKey Kind = "weak-key"
	// UnpatchedGo: a Go binary that links crypto/x509 chain verification and was
	// built with a Go release without the CVE-2026-111943 blocklist.
	UnpatchedGo Kind = "unpatched-go"
)

// Finding is one fact about one file.
type Finding struct {
	Kind     Kind   `json:"kind"`
	Path     string `json:"path"`
	Subject  string `json:"subject,omitempty"`     // certificate CN, or the tracked key's name
	SPKI     string `json:"spki_sha256,omitempty"` // key that matched
	CertHash string `json:"cert_sha256,omitempty"` // certificate that matched, when one was parsed
	Method   string `json:"method"`                // how it was found: pem, der, pkcs12, raw-key, go-buildinfo
	Detail   string `json:"detail"`                // the exact fact, in words
	Scalar   uint32 `json:"private_scalar,omitempty"`
	// Trust is what the file itself says about the certificate: "" (plain entry),
	// "distrusted" (p11-kit x-distrusted), or "no-usable-purpose" (OpenSSL trust
	// settings allow none of the purposes the compromised intermediates can issue for).
	Trust string `json:"file_trust,omitempty"`
	// Blocklisted is true when the same file also contains all eight compromised
	// SPKI hashes, the form Go (go1.26.10, go1.27.3) and Node.js use for their
	// compiled-in blocklists. Software built that way rejects the compromised
	// chains even though it carries the roots.
	Blocklisted bool `json:"file_has_blocklist,omitempty"`
	// Purposes, when the file's own trust settings restrict the certificate, lists
	// the purposes it is trusted for that a compromised intermediate can also issue
	// for (TLS server, TLS client, code signing). Empty with Trust "no-usable-purpose"
	// means none overlap.
	Purposes []string `json:"exposed_purposes,omitempty"`
	// Binary is the executable format for unpatched-go findings: "elf", "macho" or "pe".
	Binary string `json:"binary,omitempty"`
}

// Detector holds the loaded knowledge base.
type Detector struct {
	kb *knowledge.Set
}

// New loads and verifies the knowledge base.
func New() (*Detector, error) {
	kb, err := knowledge.Load()
	if err != nil {
		return nil, err
	}
	return &Detector{kb: kb}, nil
}

var (
	pemBegin    = []byte("-----BEGIN ")
	goVerifySym = []byte("crypto/x509.(*Certificate).Verify")
	// goBlocklistSym is the function go1.26.10 and go1.27.3 added to filter chains
	// through the compromised keys. Its name is in the binary's function table
	// (pclntab) whenever Verify is linked, including stripped and -trimpath builds.
	goBlocklistSym = []byte("crypto/x509.containsDistrustedSPKIHash")
	goBuildInfo    = []byte("\xff Go buildinf:")
	pkcs12Passwds  = []string{"changeit", ""}
)

// Skip records content that was recognised but could not be checked.
type Skip struct {
	Path   string
	Reason string
}

// Scan reports every finding in data, which is the full content of the file at path.
func (d *Detector) Scan(path string, data []byte) []Finding {
	f, _ := d.ScanAll(path, data)
	return f
}

// ScanAll is Scan plus the parts of the file that were recognised but could not be
// checked (for example a keystore whose password is unknown). A scan must report
// those, so a file is never counted as clean when it was not really read.
func (d *Detector) ScanAll(path string, data []byte) ([]Finding, []Skip) {
	var out []Finding
	var skips []Skip
	seen := map[string]bool{} // SPKI already reported for this file via a parsed certificate
	add := func(f Finding) {
		f.Path = path
		out = append(out, f)
	}
	skip := func(reason string) { skips = append(skips, Skip{Path: path, Reason: reason}) }
	d.scanPEM(data, seen, add)
	d.scanBase64PEM(data, seen, add)
	d.scanDER(data, seen, add)
	d.scanPKCS12(data, seen, add, skip)
	d.scanRawKeys(data, seen, add)
	hasGo := bytes.Contains(data, goBuildInfo)
	if len(out) == 0 && !hasGo {
		return nil, skips
	}
	blocklist := d.HasBlocklist(data)
	if hasGo {
		linksVerify, hasCheck := goLinks(data)
		blocklist = blocklist || hasCheck
		d.scanGo(data, linksVerify, blocklist, add)
	}
	for i := range out {
		if out[i].Kind == TrustsCompromisedKey || out[i].Kind == TrustsPathRoot {
			out[i].Blocklisted = blocklist
		}
	}
	return out, skips
}

// HasBlocklist reports whether data contains the raw SHA-256 SPKI hash of all eight
// compromised keys, the form Node.js compiles in (kBlockedSPKIs). Go binaries are
// checked by the symbol of Go's blocklist check instead (see goBlocklistSym), so a
// data file that merely lists the hashes in text does not count.
func (d *Detector) HasBlocklist(data []byte) bool {
	for _, h := range d.compromisedSPKIs() {
		if !bytes.Contains(data, h) {
			return false
		}
	}
	return true
}

func (d *Detector) compromisedSPKIs() [][]byte {
	var out [][]byte
	for _, k := range d.kb.Keys {
		if k.Kind != knowledge.Compromised {
			continue
		}
		h, err := hex.DecodeString(k.SPKISHA256)
		if err == nil {
			out = append(out, h)
		}
	}
	return out
}

// checkCert reports a parsed certificate if it carries a tracked or weak key.
func (d *Detector) checkCert(c *x509.Certificate, method, trust string, seen map[string]bool, add func(Finding)) {
	d.checkCertPurposes(c, method, trust, nil, seen, add)
}

func (d *Detector) checkCertPurposes(c *x509.Certificate, method, trust string, purposes []string, seen map[string]bool, add func(Finding)) {
	spki := knowledge.SPKIHash(c)
	if seen[spki] {
		return
	}
	if k := d.kb.ByCert(c); k != nil {
		seen[spki] = true
		f := Finding{Subject: c.Subject.CommonName, SPKI: spki, CertHash: knowledge.CertHash(c), Method: method, Trust: trust, Purposes: purposes}
		switch k.Kind {
		case knowledge.Compromised:
			f.Kind = TrustsCompromisedKey
			f.Scalar = k.Scalar
			f.Detail = fmt.Sprintf("contains a certificate for compromised %s key %q (private key = %d·G)", k.Usage, k.Name, k.Scalar)
		case knowledge.PathRoot:
			f.Kind = TrustsPathRoot
			f.Detail = fmt.Sprintf("contains CA %q, which issued or cross-signed the compromised eMudhra intermediates", k.Name)
		}
		add(f)
		return
	}
	if k := d.signedByCompromised(c); k != nil {
		seen[spki] = true
		add(Finding{
			Kind: IssuedByCompromised, Subject: c.Subject.CommonName, CertHash: knowledge.CertHash(c),
			SPKI: k.SPKISHA256, Method: method, Trust: trust,
			Detail: fmt.Sprintf("contains certificate %q, signed by compromised CA %q: replace it with one from a different CA", c.Subject.CommonName, k.Name),
		})
		return
	}
	if pub, ok := c.PublicKey.(*ecdsa.PublicKey); ok {
		if k, neg, small := weakkey.SmallScalar(pub); small {
			seen[spki] = true
			sign := ""
			if neg {
				sign = "-"
			}
			add(Finding{
				Kind: WeakKey, Subject: c.Subject.CommonName, SPKI: spki, CertHash: knowledge.CertHash(c),
				Method: method, Scalar: k, Trust: trust,
				Detail: fmt.Sprintf("contains a certificate whose %s key is %s%d·G: its private key is public", pub.Curve.Params().Name, sign, k),
			})
		}
	}
}

// scanPEM decodes every PEM CERTIFICATE / TRUSTED CERTIFICATE block anywhere in the
// file, including PEM text compiled into binaries (Node.js, Electron, Go fallback
// roots). p11-kit trust files are split into objects first, so a certificate marked
// x-distrusted is reported as distrusted, and one whose extended key usage is
// restricted by an x-certificate-extension object gets that restriction.
func (d *Detector) scanPEM(data []byte, seen map[string]bool, add func(Finding)) {
	if bytes.Contains(data, p11kitHeader) {
		objs := bytes.Split(data, p11kitHeader)
		eku := p11kitEKUs(objs)
		for _, obj := range objs {
			if p11kitField(obj, "class") == "x-certificate-extension" {
				continue // its PUBLIC KEY block is not a certificate
			}
			trust := ""
			if p11kitDistrusted(obj) {
				trust = "distrusted"
			}
			d.scanPEMBlocksEKU(obj, trust, eku, seen, add)
		}
		return
	}
	d.scanPEMBlocks(data, "", seen, add)
}

var p11kitHeader = []byte("[p11-kit-object-v1]")

func p11kitDistrusted(obj []byte) bool {
	return p11kitField(obj, "x-distrusted") == "true"
}

// p11kitField returns the value of "name: value" in a p11-kit object, unquoted.
func p11kitField(obj []byte, name string) string {
	prefix := []byte(name + ":")
	for _, line := range bytes.Split(obj, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if v, ok := bytes.CutPrefix(line, prefix); ok {
			return strings.Trim(string(bytes.TrimSpace(v)), "\"")
		}
	}
	return ""
}

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// p11kitEKUs maps a public key (SPKI SHA-256, upper-case hex) to the purposes a
// compromised intermediate could also be used for, from p11-kit
// x-certificate-extension objects that restrict extended key usage (RHEL, SUSE).
func p11kitEKUs(objs [][]byte) map[string][]string {
	out := map[string][]string{}
	for _, obj := range objs {
		if p11kitField(obj, "class") != "x-certificate-extension" || p11kitField(obj, "object-id") != "2.5.29.37" {
			continue
		}
		ext := percentDecode(p11kitField(obj, "value"))
		var e struct {
			ID       asn1.ObjectIdentifier
			Critical bool `asn1:"optional"`
			Value    []byte
		}
		if _, err := asn1.Unmarshal(ext, &e); err != nil || !e.ID.Equal(oidExtKeyUsage) {
			continue
		}
		var oids []asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(e.Value, &oids); err != nil {
			continue
		}
		var spki []byte
		for _, b := range extractPEMTypes(obj, []string{"PUBLIC KEY"}) {
			spki = b.der
		}
		if spki == nil {
			continue
		}
		h := sha256.Sum256(spki)
		out[strings.ToUpper(hex.EncodeToString(h[:]))] = purposesFromEKU(oids)
	}
	return out
}

func purposesFromEKU(oids []asn1.ObjectIdentifier) []string {
	p := []string{}
	for _, c := range compromisedPurposes {
		for _, o := range oids {
			if o.Equal(c.oid) || o.Equal(oidAnyEKU) {
				p = append(p, c.name)
				break
			}
		}
	}
	return p
}

// percentDecode decodes p11-kit's value encoding: literal bytes with %XX escapes.
func percentDecode(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				out = append(out, b[0])
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

func (d *Detector) scanPEMBlocksEKU(data []byte, trust string, eku map[string][]string, seen map[string]bool, add func(Finding)) {
	d.scanPEMBlocksWith(data, trust, func(c *x509.Certificate) ([]string, bool) {
		p, ok := eku[knowledge.SPKIHash(c)]
		return p, ok
	}, seen, add)
}

func (d *Detector) scanPEMBlocks(data []byte, trust string, seen map[string]bool, add func(Finding)) {
	d.scanPEMBlocksWith(data, trust, nil, seen, add)
}

// scanPEMBlocksWith checks every certificate block. restrict, when set, can supply
// an extended-key-usage restriction for a certificate (from a p11-kit extension).
func (d *Detector) scanPEMBlocksWith(data []byte, trust string, restrict func(*x509.Certificate) ([]string, bool), seen map[string]bool, add func(Finding)) {
	for _, b := range extractPEM(data) {
		blockTrust := trust
		der := b.der
		var purposes []string
		switch b.typ {
		case "TRUSTED CERTIFICATE":
			// OpenSSL's certificate followed by trust settings (X509_CERT_AUX).
			der = leadingSequence(b.der)
			if der != nil && blockTrust == "" {
				if p, restricted := exposedPurposes(b.der[len(der):]); restricted {
					purposes = p
					if len(p) == 0 {
						blockTrust = "no-usable-purpose"
					}
				}
			}
		case "CERTIFICATE", "X509 CERTIFICATE":
		default:
			// PKCS#7 / CMS bundles (.p7b): certificates inside are DER, so the exact
			// key bytes are there to find.
			d.scanRawKeys(b.der, seen, add)
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		if restrict != nil && blockTrust == "" {
			if p, ok := restrict(c); ok {
				purposes = p
				if len(p) == 0 {
					blockTrust = "no-usable-purpose"
				}
			}
		}
		d.checkCertPurposes(c, "pem", blockTrust, purposes, seen, add)
	}
}

// scanBase64PEM finds PEM that has itself been base64-encoded, as in Kubernetes
// Secrets and ConfigMaps, webhook caBundle fields and Helm values. Any base64 run
// that starts with the encoding of "-----BEGIN" is decoded and scanned as PEM.
func (d *Detector) scanBase64PEM(data []byte, seen map[string]bool, add func(Finding)) {
	marker := []byte("LS0tLS1CRUdJTi")
	pos := 0
	for {
		i := bytes.Index(data[pos:], marker)
		if i < 0 {
			return
		}
		start := pos + i
		end := start
		for end < len(data) && isB64(data[end]) {
			end++
		}
		pos = end
		run := bytes.TrimRight(data[start:end], "=")
		dec, err := base64.RawStdEncoding.DecodeString(string(run))
		if err != nil {
			// a run may end mid-quantum if it was line-wrapped; drop the tail
			if n := len(run) / 4 * 4; n > 0 {
				dec, err = base64.RawStdEncoding.DecodeString(string(run[:n]))
			}
			if err != nil {
				continue
			}
		}
		d.scanPEMBlocks(dec, "", seen, add)
	}
}

func isB64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

type pemBlock struct {
	typ string
	der []byte
}

var certTypes = []string{"CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE", "PKCS7", "PKCS #7 SIGNED DATA", "CMS"}

// maxPEMBody bounds how far an END marker is searched for. The largest real
// certificates are a few kilobytes of base64.
const maxPEMBody = 64 << 10

// extractPEM finds certificate PEM blocks anywhere in data. Unlike encoding/pem it
// does not require clean line endings, so it also reads PEM compiled into binaries
// as C strings (terminated by NUL bytes, as in Node.js) and PEM written inside
// source-code string literals (quotes and \n escapes between lines). The body is
// reduced to the base64 alphabet before decoding; anything that does not then parse
// as a certificate is ignored.
func extractPEM(data []byte) []pemBlock {
	return extractPEMTypes(data, certTypes)
}

func extractPEMTypes(data []byte, types []string) []pemBlock {
	var out []pemBlock
	// nextEnd caches, per type, the absolute offset of the next END marker at or
	// after the last search point (-1: none left). Each byte is searched for each
	// marker type at most once, so many BEGIN markers without an END cost linear
	// time, not 64 KB each.
	// owner is the offset of the last BEGIN of the same type before that END: the
	// only BEGIN the END can close. Earlier BEGINs in between are unterminated noise.
	type endCache struct{ from, at, owner int }
	cache := map[string]*endCache{}
	pos := 0
	for {
		i := bytes.Index(data[pos:], pemBegin)
		if i < 0 {
			return out
		}
		begin := pos + i
		pos = begin + len(pemBegin)
		var typ string
		for _, t := range types {
			if bytes.HasPrefix(data[pos:], []byte(t+"-----")) {
				typ = t
				break
			}
		}
		if typ == "" {
			continue
		}
		bodyStart := pos + len(typ) + 5
		endMarker := []byte("-----END " + typ + "-----")
		c := cache[typ]
		if c == nil || (c.at >= 0 && c.at < bodyStart) {
			from := bodyStart
			if c != nil && c.from > from {
				from = c.from
			}
			at, owner := -1, -1
			if j := bytes.Index(data[from:], endMarker); j >= 0 {
				at = from + j
				owner = bytes.LastIndex(data[:at], []byte("-----BEGIN "+typ+"-----"))
			}
			c = &endCache{from: from, at: at, owner: owner}
			cache[typ] = c
		}
		if c.at < 0 {
			continue // no END marker for this type anywhere after here
		}
		if begin != c.owner || c.at-bodyStart > maxPEMBody {
			continue // not this block's END, or too far away
		}
		if der := decodeLooseBase64(data[bodyStart:c.at]); der != nil {
			out = append(out, pemBlock{typ: typ, der: der})
		}
		pos = c.at + len(endMarker)
	}
}

// decodeLooseBase64 decodes a PEM body written any way real software writes it:
// RFC 1421 header lines ("Proc-Type: ...") are dropped, literal "\n" / "\r"
// escapes and JSON "\u002b" / "\u002f" / "\/" escapes are undone, and every other
// byte outside the base64 alphabet is ignored. It returns nil if that fails.
func decodeLooseBase64(b []byte) []byte {
	if bytes.IndexByte(b, ':') >= 0 {
		var kept [][]byte
		for _, line := range bytes.Split(b, []byte("\n")) {
			if bytes.IndexByte(line, ':') < 0 {
				kept = append(kept, line)
			}
		}
		b = bytes.Join(kept, []byte("\n"))
	}
	clean := make([]byte, 0, len(b))
	for k := 0; k < len(b); k++ {
		c := b[k]
		if c == '\\' && k+1 < len(b) {
			switch b[k+1] {
			case 'n', 'r':
				k++
				continue
			case 'u':
				if k+5 < len(b) {
					if v, err := strconv.ParseUint(string(b[k+2:k+6]), 16, 16); err == nil {
						k += 5
						if v == '+' || v == '/' {
							clean = append(clean, byte(v))
						}
						continue
					}
				}
			}
		}
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
			clean = append(clean, c)
		}
	}
	der, err := base64.RawStdEncoding.DecodeString(string(clean))
	if err != nil {
		return nil
	}
	return der
}

var (
	oidServerAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidAnyEKU      = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

// compromisedPurposes are the extended key usages the 16 compromised certificates
// allow between them (TLS server and client for the six TLS CAs, code signing for
// the two code-signing CAs). None allows e-mail protection.
var compromisedPurposes = []struct {
	oid  asn1.ObjectIdentifier
	name string
}{
	{oidServerAuth, "tls-server"},
	{oidClientAuth, "tls-client"},
	{oidCodeSigning, "code-signing"},
}

// x509CertAux mirrors OpenSSL's X509_CERT_AUX: trust and reject lists, then
// optional alias, key id and other fields this scanner does not need.
type x509CertAux struct {
	Trust  []asn1.ObjectIdentifier `asn1:"optional"`
	Reject []asn1.ObjectIdentifier `asn1:"optional,tag:0"`
	Rest   asn1.RawValue           `asn1:"optional"`
	Rest2  asn1.RawValue           `asn1:"optional"`
	Rest3  asn1.RawValue           `asn1:"optional"`
}

// exposedPurposes reads OpenSSL trust settings. restricted is false when there are
// none (the certificate is trusted for everything). Otherwise purposes lists the
// purposes it is trusted for, and not rejected for, that a compromised
// intermediate can issue for.
func exposedPurposes(aux []byte) (purposes []string, restricted bool) {
	if len(aux) == 0 {
		return nil, false
	}
	var a x509CertAux
	if _, err := asn1.Unmarshal(aux, &a); err != nil {
		return nil, false
	}
	if len(a.Trust) == 0 && len(a.Reject) == 0 {
		return nil, false
	}
	has := func(list []asn1.ObjectIdentifier, o asn1.ObjectIdentifier) bool {
		for _, x := range list {
			if x.Equal(o) || x.Equal(oidAnyEKU) {
				return true
			}
		}
		return false
	}
	purposes = []string{}
	for _, p := range compromisedPurposes {
		trusted := len(a.Trust) == 0 || has(a.Trust, p.oid)
		if trusted && !has(a.Reject, p.oid) {
			purposes = append(purposes, p.name)
		}
	}
	return purposes, true
}

// scanDER handles a file that is a single DER certificate.
func (d *Detector) scanDER(data []byte, seen map[string]bool, add func(Finding)) {
	if len(data) < 4 || data[0] != 0x30 {
		return
	}
	der := leadingSequence(data)
	if der == nil || len(der) != len(data) {
		return
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}
	d.checkCert(c, "der", "", seen, add)
}

// maxPKCS12Iterations bounds the key-derivation work a PKCS#12 file can demand.
// Real stores use 2,048 to 600,000; a hostile file can ask for billions.
const maxPKCS12Iterations = 1_000_000

// scanPKCS12 decodes Java-style PKCS#12 trust stores (cacerts) with the default
// passwords. Raw-key search already covers certificates stored unencrypted; this
// covers encrypted certificate bags. A file that is PKCS#12 but cannot be opened
// is reported as a skip, never as clean.
func (d *Detector) scanPKCS12(data []byte, seen map[string]bool, add func(Finding), skip func(string)) {
	isPFX, iters := pkcs12Shape(data)
	if !isPFX {
		return
	}
	if iters > maxPKCS12Iterations {
		skip(fmt.Sprintf("PKCS#12 store asks for %d key-derivation iterations (limit %d); encrypted certificates in it were not checked", iters, maxPKCS12Iterations))
		return
	}
	for _, pw := range pkcs12Passwds {
		certs, err := pkcs12.DecodeTrustStore(data, pw)
		if err != nil {
			continue
		}
		for _, c := range certs {
			d.checkCert(c, "pkcs12", "", seen, add)
		}
		return
	}
	skip("PKCS#12 store could not be opened (password is not changeit or empty, or it is not a Java trust store); certificates encrypted in it were not checked")
}

var oidPKCS7Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

// saltThenCount returns the largest INTEGER that directly follows an OCTET STRING
// among the elements of a SEQUENCE body. Counts too large for an int are reported
// as the maximum, so they are always over the limit.
func saltThenCount(body []byte) int {
	max := 0
	prevOctet := false
	for len(body) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(body, &v)
		if err != nil {
			return max
		}
		body = rest
		if v.Class == asn1.ClassUniversal && v.Tag == asn1.TagInteger && prevOctet {
			n := new(big.Int).SetBytes(v.Bytes)
			if len(v.Bytes) > 0 && v.Bytes[0]&0x80 == 0 {
				if n.IsInt64() && n.Int64() <= int64(^uint32(0)>>1) {
					if int(n.Int64()) > max {
						max = int(n.Int64())
					}
				} else {
					max = int(^uint32(0) >> 1)
				}
			}
		}
		prevOctet = v.Class == asn1.ClassUniversal && v.Tag == asn1.TagOctetString
	}
	return max
}

// pkcs12Shape reports whether data is a PKCS#12 PFX (version 3 with a data
// ContentInfo) and the largest iteration count anywhere in it: in the MAC data and
// in every PBE or PBKDF2 parameter set, which all have the shape
// SEQUENCE { OCTET STRING salt, INTEGER iterations, ... }.
func pkcs12Shape(data []byte) (bool, int) {
	var pfx struct {
		Version  int
		AuthSafe struct {
			Type    asn1.ObjectIdentifier
			Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
		}
		Rest asn1.RawValue `asn1:"optional"`
	}
	if len(data) < 4 || data[0] != 0x30 {
		return false, 0
	}
	if _, err := asn1.Unmarshal(data, &pfx); err != nil || pfx.Version != 3 || !pfx.AuthSafe.Type.Equal(oidPKCS7Data) {
		return false, 0
	}
	max := 0
	var walk func(b []byte, depth int)
	walk = func(b []byte, depth int) {
		if depth > 32 {
			return
		}
		for len(b) > 0 {
			var v asn1.RawValue
			rest, err := asn1.Unmarshal(b, &v)
			if err != nil {
				return
			}
			b = rest
			switch {
			case v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence:
				// An OCTET STRING (salt) directly followed by an INTEGER (iteration
				// count), at any position: PBE and PBKDF2 parameters start with it,
				// MacData has it after the digest.
				if it := saltThenCount(v.Bytes); it > max {
					max = it
				}
				walk(v.Bytes, depth+1)
			case v.IsCompound:
				walk(v.Bytes, depth+1)
			case v.Class == asn1.ClassUniversal && v.Tag == asn1.TagOctetString:
				walk(v.Bytes, depth+1) // authSafe and SafeContents are DER inside octet strings
			}
		}
	}
	walk(data, 0)
	return true, max
}

// scanRawKeys searches for the exact public-key bytes of every tracked key. A
// 97-byte P-384 point or a 256-byte RSA modulus cannot match by accident.
func (d *Detector) scanRawKeys(data []byte, seen map[string]bool, add func(Finding)) {
	for _, k := range d.kb.Keys {
		if seen[k.SPKISHA256] || !bytes.Contains(data, k.RawKey) {
			continue
		}
		seen[k.SPKISHA256] = true
		f := Finding{Subject: k.Name, SPKI: k.SPKISHA256, Method: "raw-key"}
		switch k.Kind {
		case knowledge.Compromised:
			f.Kind = TrustsCompromisedKey
			f.Scalar = k.Scalar
			f.Detail = fmt.Sprintf("contains the public key of compromised %s CA %q (private key = %d·G)", k.Usage, k.Name, k.Scalar)
		case knowledge.PathRoot:
			f.Kind = TrustsPathRoot
			f.Detail = fmt.Sprintf("contains the public key of CA %q, which issued or cross-signed the compromised eMudhra intermediates", k.Name)
		}
		add(f)
	}
}

// scanGo reports Go binaries that verify certificate chains without the blocklist.
// The blocklist check itself is the evidence: go1.26.10 and go1.27.3 link
// crypto/x509.containsDistrustedSPKIHash into any binary that links Verify, and
// distributions that backport the fix carry it too. A binary is reported only if
// it links Verify, lacks that function, and does not name a release known to
// include the fix.
func (d *Detector) scanGo(data []byte, linksVerify, blocklist bool, add func(Finding)) {
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return
	}
	if !linksVerify {
		return // does not link certificate chain verification
	}
	if blocklist {
		return
	}
	if fixed, known := GoHasBlocklist(bi.GoVersion); known && fixed {
		return
	}
	add(Finding{
		Kind: UnpatchedGo, Subject: bi.Path, Method: "go-buildinfo", Binary: binaryFormat(data),
		Detail: fmt.Sprintf("Go binary built with %s links crypto/x509 chain verification without the CVE-2026-111943 blocklist (fixed in go1.26.10 and go1.27.3); rebuild it", bi.GoVersion),
	})
}

func binaryFormat(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x7fELF")):
		return "elf"
	case bytes.HasPrefix(b, []byte{0xcf, 0xfa, 0xed, 0xfe}), bytes.HasPrefix(b, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(b, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "macho"
	case bytes.HasPrefix(b, []byte("MZ")):
		return "pe"
	}
	return ""
}

// goLinks reports whether a Go binary contains crypto/x509's Verify and Go's
// blocklist check, read from its function table when possible. Only PE files and
// unusual layouts fall back to searching for the function names.
func goLinks(data []byte) (verify, blocklistCheck bool) {
	if has, ok := goFuncTable(data); ok {
		return has(string(goVerifySym)), has(string(goBlocklistSym))
	}
	return bytes.Contains(data, goVerifySym), bytes.Contains(data, goBlocklistSym)
}

// GoHasBlocklist reports whether a Go release string such as "go1.27.2" or
// "go1.26.10 X:boringcrypto" includes the blocklist. known is false for
// development builds, release candidates and anything it cannot parse.
func GoHasBlocklist(v string) (fixed bool, known bool) {
	fields := strings.Fields(v)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "go1.") {
		return false, false
	}
	parts := strings.Split(strings.TrimPrefix(fields[0], "go1."), ".")
	if len(parts) > 2 {
		return false, false
	}
	minor, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, false // e.g. "28rc1"
	}
	patch := 0
	if len(parts) == 2 {
		if patch, err = strconv.Atoi(parts[1]); err != nil {
			return false, false
		}
	}
	switch {
	case minor >= 28:
		return true, true
	case minor == 27:
		return patch >= 3, true
	case minor == 26:
		return patch >= 10, true
	default:
		return false, true // 1.25 and older are out of support and never got the fix
	}
}

// leadingSequence returns the first complete DER SEQUENCE at the start of b, or nil.
func leadingSequence(b []byte) []byte {
	if len(b) < 2 || b[0] != 0x30 {
		return nil
	}
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return nil
		}
		l = 0
		for _, x := range b[2 : 2+n] {
			l = l<<8 | int(x)
		}
		hdr += n
	}
	if l < 0 || hdr+l > len(b) {
		return nil
	}
	return b[:hdr+l]
}

// IssuedByCompromised is the finding kind for a certificate a server presents that
// was signed by one of the compromised keys.
const IssuedByCompromised Kind = "issued-by-compromised-ca"

// Chain checks the certificates a TLS server presented. It reports any certificate
// that carries a tracked or weak key, and any certificate whose signature verifies
// under a compromised key, which means it was issued by a compromised CA and must
// be replaced. where names the server, for example "example.com:443".
func (d *Detector) Chain(where string, certs []*x509.Certificate) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(f Finding) {
		// A server presenting a path root (for example the widely used AAA
		// Certificate Services cross-sign) is normal and not a problem in itself.
		if f.Kind == TrustsPathRoot {
			return
		}
		f.Path = where
		out = append(out, f)
	}
	for _, c := range certs {
		d.checkCert(c, "tls-handshake", "", seen, func(f Finding) {
			f.Detail = strings.Replace(f.Detail, "contains", "presents", 1)
			add(f)
		})
	}
	return out
}

// signedByCompromised returns the compromised key whose signature c carries.
func (d *Detector) signedByCompromised(c *x509.Certificate) *knowledge.Key {
	for _, k := range d.kb.Keys {
		if k.Kind != knowledge.Compromised {
			continue
		}
		for _, issuer := range k.Certs {
			// Cheap name check first; the signature check is what proves it.
			if !bytes.Equal(c.RawIssuer, issuer.RawSubject) {
				continue
			}
			if c.CheckSignatureFrom(issuer) == nil {
				return k
			}
		}
	}
	return nil
}
