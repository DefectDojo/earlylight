// Package knowledge holds the certificates involved in the October 2026 eMudhra
// intermediate CA key compromise (Mozilla bug 2083449) and the facts the scanner
// matches on.
//
// Every match is by public key, never by name: names can be copied, keys cannot.
// The data proves itself at start-up. Each "compromised" key must be k·G for a tiny
// k, which is exactly what makes it compromised; if the embedded data ever stopped
// satisfying that, Load fails instead of scanning with bad data.
package knowledge

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"crypto/x509"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/weakkey"
)

// The data is stored gzip-compressed so this program's own binary never contains
// the certificates or keys it searches for, and cannot report itself.
//
//go:embed data/certs.pem.gz
var certsGZ []byte

// Kind says why a key matters.
type Kind int

const (
	// Compromised: one of the eight intermediate keys anyone can recover.
	Compromised Kind = iota + 1
	// PathRoot: a CA that issued or cross-signed the compromised intermediates.
	// Trusting it lets a client build a chain to them.
	PathRoot
)

func (k Kind) String() string {
	switch k {
	case Compromised:
		return "compromised-key"
	case PathRoot:
		return "path-root"
	}
	return "unknown"
}

// Key is one public key the scanner looks for, with every certificate that
// carries it (the same key can appear under several issuers).
type Key struct {
	Name       string   // subject common name
	Kind       Kind     // Compromised or PathRoot
	Usage      string   // "tls", "code-signing", or "" for roots
	SPKISHA256 string   // hex, upper case
	Scalar     uint32   // private scalar, Compromised keys only
	RawKey     []byte   // EC point (uncompressed) or RSA modulus, for byte search
	CertSHA256 []string // every known certificate with this key
	Certs      []*x509.Certificate
}

// Set is the loaded, verified knowledge base.
type Set struct {
	Keys   []*Key
	bySPKI map[string]*Key
}

var (
	loadOnce sync.Once
	loaded   *Set
	loadErr  error
)

// Load parses and verifies the embedded data. It is safe to call repeatedly.
func Load() (*Set, error) {
	loadOnce.Do(func() {
		zr, err := gzip.NewReader(bytes.NewReader(certsGZ))
		if err != nil {
			loadErr = err
			return
		}
		data, err := io.ReadAll(zr)
		if err != nil {
			loadErr = err
			return
		}
		loaded, loadErr = parse(data)
	})
	return loaded, loadErr
}

// SPKIHash returns the upper-case hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIHash(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// CertHash returns the upper-case hex SHA-256 of a certificate's DER encoding.
func CertHash(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// ByCert returns the key this certificate carries, if it is one we track.
func (s *Set) ByCert(c *x509.Certificate) *Key {
	return s.bySPKI[SPKIHash(c)]
}

func rawKey(c *x509.Certificate) ([]byte, error) {
	switch pub := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		b, err := pub.Bytes()
		if err != nil {
			return nil, err
		}
		return b, nil
	case *rsa.PublicKey:
		return pub.N.Bytes(), nil
	}
	return nil, fmt.Errorf("unsupported key type %T", c.PublicKey)
}

func parse(data []byte) (*Set, error) {
	s := &Set{bySPKI: map[string]*Key{}}
	rest := data
	var comment string
	for len(rest) > 0 {
		// The line before each PEM block says what it is.
		if i := bytes.Index(rest, []byte("-----BEGIN CERTIFICATE-----")); i >= 0 {
			pre := string(rest[:i])
			if j := strings.LastIndex(pre, "# "); j >= 0 {
				comment = strings.TrimSpace(pre[j+2:])
			}
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("embedded certificate: %w", err)
		}
		kind := PathRoot
		usage := ""
		if strings.HasPrefix(comment, "compromised-intermediate") {
			kind = Compromised
			switch {
			case strings.Contains(comment, "usage tls"):
				usage = "tls"
			case strings.Contains(comment, "usage code_signing"), strings.Contains(comment, "usage cs"), strings.Contains(comment, "usage codesigning"):
				usage = "code-signing"
			}
		} else if !strings.HasPrefix(comment, "path-root") {
			return nil, fmt.Errorf("embedded certificate %q has no role comment", c.Subject.CommonName)
		}
		spki := SPKIHash(c)
		k := s.bySPKI[spki]
		if k == nil {
			rk, err := rawKey(c)
			if err != nil {
				return nil, err
			}
			k = &Key{Name: c.Subject.CommonName, Kind: kind, Usage: usage, SPKISHA256: spki, RawKey: rk}
			s.bySPKI[spki] = k
			s.Keys = append(s.Keys, k)
		} else if k.Kind != kind {
			return nil, fmt.Errorf("key %s listed as both %v and %v", spki, k.Kind, kind)
		}
		if usage == "" && kind == Compromised {
			usage = usageFromEKU(c)
			k.Usage = usage
		}
		k.CertSHA256 = append(k.CertSHA256, CertHash(c))
		k.Certs = append(k.Certs, c)
	}
	return s, s.verify()
}

func usageFromEKU(c *x509.Certificate) string {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			return "code-signing"
		}
	}
	return "tls"
}

// verify enforces the invariants the scanner's accuracy rests on.
func (s *Set) verify() error {
	var compromised, roots int
	for _, k := range s.Keys {
		switch k.Kind {
		case Compromised:
			compromised++
			pub, ok := k.Certs[0].PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return fmt.Errorf("compromised key %s is not EC", k.Name)
			}
			scalar, _, small := weakkey.SmallScalar(pub)
			if !small {
				return fmt.Errorf("compromised key %s is not a small-scalar key: refusing to run on unverified data", k.Name)
			}
			k.Scalar = scalar
		case PathRoot:
			roots++
		}
	}
	if compromised != 8 {
		return fmt.Errorf("expected 8 compromised keys, found %d", compromised)
	}
	if roots != 4 {
		return fmt.Errorf("expected 4 path roots, found %d", roots)
	}
	// Every compromised certificate must be signed by a path root we track, so the
	// "path-root" list is complete for the certificates we know.
	for _, k := range s.Keys {
		if k.Kind != Compromised {
			continue
		}
		for _, c := range k.Certs {
			if !s.signedByPathRoot(c) {
				return fmt.Errorf("compromised certificate %s (%s) is not signed by any tracked path root", k.Name, CertHash(c))
			}
		}
	}
	return nil
}

func (s *Set) signedByPathRoot(c *x509.Certificate) bool {
	for _, r := range s.Keys {
		if r.Kind != PathRoot {
			continue
		}
		for _, rc := range r.Certs {
			if err := c.CheckSignatureFrom(rc); err == nil {
				return true
			}
		}
	}
	return false
}

// ErrNotLoaded is returned by helpers used before Load succeeded.
var ErrNotLoaded = errors.New("knowledge base not loaded")
