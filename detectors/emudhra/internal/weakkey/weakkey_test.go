package weakkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func keyFor(c elliptic.Curve, k *big.Int) *ecdsa.PublicKey {
	x, y := c.ScalarBaseMult(k.Bytes())
	return &ecdsa.PublicKey{Curve: c, X: x, Y: y}
}

func TestSmallScalars(t *testing.T) {
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		for _, k := range []int64{1, 2, 4, 237, 255, 12345, Limit - 1} {
			got, neg, ok := SmallScalar(keyFor(c, big.NewInt(k)))
			if !ok || neg || int64(got) != k {
				t.Errorf("%s k=%d: got %d neg=%v ok=%v", c.Params().Name, k, got, neg, ok)
			}
			// n-k is the negated point: same x, other y.
			nk := new(big.Int).Sub(c.Params().N, big.NewInt(k))
			got, neg, ok = SmallScalar(keyFor(c, nk))
			if !ok || !neg || int64(got) != k {
				t.Errorf("%s n-%d: got %d neg=%v ok=%v", c.Params().Name, k, got, neg, ok)
			}
		}
		// Just outside the range is not reported.
		if _, _, ok := SmallScalar(keyFor(c, big.NewInt(Limit))); ok {
			t.Errorf("%s: k=Limit reported", c.Params().Name)
		}
	}
}

func TestRandomKeysAreNotWeak(t *testing.T) {
	for i := 0; i < 200; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, ok := SmallScalar(&k.PublicKey); ok {
			t.Fatal("random key reported weak")
		}
	}
}

func TestBadInput(t *testing.T) {
	if _, _, ok := SmallScalar(nil); ok {
		t.Fatal("nil")
	}
	if _, _, ok := SmallScalar(&ecdsa.PublicKey{Curve: elliptic.P256()}); ok {
		t.Fatal("nil coordinates")
	}
	// x of a real small point with a y that is not on the curve: not reported.
	pub := keyFor(elliptic.P256(), big.NewInt(9))
	pub.Y = new(big.Int).Add(pub.Y, big.NewInt(1))
	if _, _, ok := SmallScalar(pub); ok {
		t.Fatal("off-curve y reported")
	}
}
