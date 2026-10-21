// Package weakkey finds elliptic-curve public keys whose private scalar is tiny.
//
// A public key Q on a curve with generator G is Q = k·G. If k is small, anyone can
// recover it by stepping through G, 2G, 3G, ... until they reach Q. The eMudhra
// intermediates compromised in October 2026 had k below 256. This package checks
// every k up to Limit, and also n-k (the same point negated), so the answer is a
// proof, not a heuristic: when it reports k, then k·G (or (n-k)·G) equals the key.
package weakkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"sync"
)

// Limit is the largest scalar checked. Recovering any k below it takes a laptop
// well under a second, so a key in this range is as good as public.
const Limit = 1 << 16

type table struct {
	once sync.Once
	byX  map[string]uint32 // affine x-coordinate (fixed width) -> k
}

var tables = map[string]*table{
	"P-256": {},
	"P-384": {},
	"P-521": {},
}

func curveByName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	}
	return nil
}

func (t *table) build(c elliptic.Curve) {
	size := (c.Params().BitSize + 7) / 8
	t.byX = make(map[string]uint32, Limit)
	gx, gy := c.Params().Gx, c.Params().Gy
	x, y := new(big.Int).Set(gx), new(big.Int).Set(gy)
	for k := uint32(1); k < Limit; k++ {
		t.byX[string(x.FillBytes(make([]byte, size)))] = k
		//nolint:staticcheck // the generic Add is fine for a one-off precomputation
		x, y = c.Add(x, y, gx, gy)
	}
}

// SmallScalar reports the private scalar of pub when it is below Limit, or its
// negation n-k is. ok is false for any other key or an unsupported curve.
// The result is exact: the caller can confirm it with ScalarBaseMult.
func SmallScalar(pub *ecdsa.PublicKey) (k uint32, negated bool, ok bool) {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return 0, false, false
	}
	name := pub.Curve.Params().Name
	t, known := tables[name]
	if !known {
		return 0, false, false
	}
	c := curveByName(name)
	t.once.Do(func() { t.build(c) })
	size := (c.Params().BitSize + 7) / 8
	if pub.X.Sign() < 0 || pub.X.BitLen() > size*8 {
		return 0, false, false
	}
	k, found := t.byX[string(pub.X.FillBytes(make([]byte, size)))]
	if !found {
		return 0, false, false
	}
	// Same x means the key is k·G or -(k·G). Confirm by exact comparison.
	//nolint:staticcheck
	_, wy := c.ScalarBaseMult(new(big.Int).SetUint64(uint64(k)).Bytes())
	if wy.Cmp(pub.Y) == 0 {
		return k, false, true
	}
	negY := new(big.Int).Sub(c.Params().P, wy)
	if negY.Cmp(pub.Y) == 0 {
		return k, true, true
	}
	return 0, false, false
}
