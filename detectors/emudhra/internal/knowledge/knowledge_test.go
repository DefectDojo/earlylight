package knowledge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestLoadVerifiesItself(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var compromised int
	for _, k := range s.Keys {
		t.Logf("%-16v %-28s usage=%-12s k=%-4d certs=%d spki=%s", k.Kind, k.Name, k.Usage, k.Scalar, len(k.Certs), k.SPKISHA256[:16])
		if k.Kind != Compromised {
			continue
		}
		compromised++
		// Independent confirmation: k·G must equal the key.
		pub := k.Certs[0].PublicKey.(*ecdsa.PublicKey)
		x, y := elliptic.P384().ScalarBaseMult(big.NewInt(int64(k.Scalar)).Bytes())
		negY := new(big.Int).Sub(elliptic.P384().Params().P, y)
		if x.Cmp(pub.X) != 0 || (y.Cmp(pub.Y) != 0 && negY.Cmp(pub.Y) != 0) {
			t.Errorf("%s: k=%d does not reproduce the key", k.Name, k.Scalar)
		}
		if len(k.Certs) != 2 {
			t.Errorf("%s: expected the key under 2 issuers, got %d", k.Name, len(k.Certs))
		}
	}
	if compromised != 8 {
		t.Fatalf("compromised = %d", compromised)
	}
}
