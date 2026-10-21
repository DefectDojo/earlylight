package version

import "testing"

// checkOrder checks reflexivity, antisymmetry and transitivity of cmp on a
// triple. cmp returns ok=false when a pair is outside its domain.
func checkOrder(t *testing.T, name string, cmp func(a, b string) (int, bool), a, b, c string) {
	vs := [3]string{a, b, c}
	var r [3][3]int
	for i := range vs {
		for j := range vs {
			v, ok := cmp(vs[i], vs[j])
			if !ok {
				return
			}
			if v < -1 || v > 1 {
				t.Fatalf("%s(%q, %q) = %d, want -1, 0 or 1", name, vs[i], vs[j], v)
			}
			r[i][j] = v
		}
	}
	for i := range vs {
		if r[i][i] != 0 {
			t.Fatalf("%s(%q, %q) = %d, want 0", name, vs[i], vs[i], r[i][i])
		}
		for j := range vs {
			if r[i][j] != -r[j][i] {
				t.Fatalf("%s not antisymmetric on %q, %q: %d, %d", name, vs[i], vs[j], r[i][j], r[j][i])
			}
			for k := range vs {
				if r[i][j] <= 0 && r[j][k] <= 0 && r[i][k] > 0 {
					t.Fatalf("%s not transitive: %q <= %q <= %q but %q > %q", name, vs[i], vs[j], vs[k], vs[i], vs[k])
				}
			}
		}
	}
}

func seedTriples(f *testing.F, corpus []string) {
	for i := 0; i+2 < len(corpus); i += 3 {
		f.Add(corpus[i], corpus[i+1], corpus[i+2])
	}
}

func FuzzCompareDpkg(f *testing.F) {
	seedTriples(f, dpkgCorpus())
	f.Fuzz(func(t *testing.T, a, b, c string) {
		checkOrder(t, "CompareDpkg", func(x, y string) (int, bool) {
			r, err := CompareDpkg(x, y)
			return r, err == nil
		}, a, b, c)
		// A parsed version formats to one that parses to an equal version.
		if v, err := ParseDpkg(a); err == nil {
			w, err := ParseDpkg(v.String())
			if err != nil || v.Compare(w) != 0 {
				t.Fatalf("ParseDpkg(%q).String() = %q: %v", a, v.String(), err)
			}
		}
	})
}

func FuzzCompareAPK(f *testing.F) {
	seedTriples(f, apkCorpus())
	f.Fuzz(func(t *testing.T, a, b, c string) {
		// Each generation is an order on its own valid versions.
		checkOrder(t, "apk3", func(x, y string) (int, bool) {
			if !apk3Validate(x) || !apk3Validate(y) {
				return 0, false
			}
			return apk3Compare(x, y), true
		}, a, b, c)
		checkOrder(t, "apk2", func(x, y string) (int, bool) {
			if !apk2Validate(x) || !apk2Validate(y) {
				return 0, false
			}
			return apk2Compare(x, y), true
		}, a, b, c)
		checkOrder(t, "CompareAPK", func(x, y string) (int, bool) {
			r, err := CompareAPK(x, y)
			return r, err == nil
		}, a, b, c)
		// Invalid input never panics either generation.
		apk2Compare(a, b)
		apk3Compare(a, b)
	})
}

func FuzzCompareRPM(f *testing.F) {
	seedTriples(f, rpmCorpus())
	f.Fuzz(func(t *testing.T, a, b, c string) {
		checkOrder(t, "CompareRPM", func(x, y string) (int, bool) { return CompareRPM(x, y), true }, a, b, c)
		e := ParseEVR(a)
		if ParseEVR(e.String()) != e {
			t.Fatalf("ParseEVR(%q).String() = %q does not round-trip", a, e.String())
		}
	})
}
