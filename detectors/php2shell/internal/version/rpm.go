package version

import "strings"

// EVR is an rpm [epoch:]version[-release], split the way rpm's parseEVR
// (rpmio/rpmver.c) splits it.
type EVR struct {
	// Epoch is the epoch as written; empty when absent. HasEpoch distinguishes
	// "0:1.0" from "1.0" (rpm compares a missing epoch as "0", so they are
	// equal).
	Epoch    string
	HasEpoch bool
	Version  string
	// Release is the text after the last hyphen; HasRelease is false when there
	// is no hyphen.
	Release    string
	HasRelease bool
}

// ParseEVR splits an EVR string as rpm does: the epoch is a (possibly empty)
// run of leading digits followed by ':' (an empty epoch means "0"); the
// release is whatever follows the last '-' after the epoch. Anything else is
// the version. Like rpm, it never fails; bytes from a NUL on are ignored, as C
// never sees them.
func ParseEVR(s string) EVR {
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	var e EVR
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	rest := s
	if i < len(s) && s[i] == ':' {
		e.HasEpoch = true
		e.Epoch = s[:i]
		if e.Epoch == "" {
			e.Epoch = "0"
		}
		rest = s[i+1:]
	}
	// rpm looks for the last '-' from the end of the epoch digits; the epoch is
	// digits only, so that is the last '-' of rest.
	if h := strings.LastIndexByte(rest, '-'); h >= 0 {
		e.Version, e.Release, e.HasRelease = rest[:h], rest[h+1:], true
	} else {
		e.Version = rest
	}
	return e
}

// String formats the EVR (epoch kept only when present in the input).
func (e EVR) String() string {
	s := e.Version
	if e.HasEpoch {
		s = e.Epoch + ":" + s
	}
	if e.HasRelease {
		s += "-" + e.Release
	}
	return s
}

// CompareRPM compares two EVR strings as rpm's rpmverCmp (rpm 4.18+, also
// what the Lua rpm.vercmp() and dnf use) does: epochs with rpmvercmp, a
// missing epoch counting as "0"; then versions; then releases, where a missing
// release sorts below any present one. It returns -1, 0 or 1.
func CompareRPM(a, b string) int {
	return ParseEVR(a).Compare(ParseEVR(b))
}

// Compare orders two EVRs; -1, 0 or 1.
func (e EVR) Compare(o EVR) int {
	ea, eb := "0", "0"
	if e.HasEpoch {
		ea = e.Epoch
	}
	if o.HasEpoch {
		eb = o.Epoch
	}
	if r := RPMVerCmp(ea, eb); r != 0 {
		return r
	}
	if r := RPMVerCmp(e.Version, o.Version); r != 0 {
		return r
	}
	switch {
	case !e.HasRelease && !o.HasRelease:
		return 0
	case !o.HasRelease:
		return 1
	case !e.HasRelease:
		return -1
	}
	return RPMVerCmp(e.Release, o.Release)
}

// RPMVerCmp is rpm's rpmvercmp() (rpmio/rpmvercmp.c) on one version or release
// field: alphanumeric segments, separators ignored, "~" sorting before
// everything (also the end), "^" sorting after the end but before any other
// segment, numeric segments compared by value and above alphabetic ones.
// Bytes from a NUL on are ignored.
func RPMVerCmp(a, b string) int {
	if i := strings.IndexByte(a, 0); i >= 0 {
		a = a[:i]
	}
	if i := strings.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	if a == b {
		return 0
	}
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	one, two := 0, 0
	for one < len(a) || two < len(b) {
		for one < len(a) && !isAlnum(a[one]) && a[one] != '~' && a[one] != '^' {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) && b[two] != '~' && b[two] != '^' {
			two++
		}
		c1, c2 := at(a, one), at(b, two)
		if c1 == '~' || c2 == '~' {
			if c1 != '~' {
				return 1
			}
			if c2 != '~' {
				return -1
			}
			one++
			two++
			continue
		}
		if c1 == '^' || c2 == '^' {
			if c1 == 0 {
				return -1
			}
			if c2 == 0 {
				return 1
			}
			if c1 != '^' {
				return 1
			}
			if c2 != '^' {
				return -1
			}
			one++
			two++
			continue
		}
		if c1 == 0 || c2 == 0 {
			break
		}
		s1, s2 := one, two
		isnum := isDigit(c1)
		if isnum {
			for s1 < len(a) && isDigit(a[s1]) {
				s1++
			}
			for s2 < len(b) && isDigit(b[s2]) {
				s2++
			}
		} else {
			for s1 < len(a) && isAlpha(a[s1]) {
				s1++
			}
			for s2 < len(b) && isAlpha(b[s2]) {
				s2++
			}
		}
		if one == s1 {
			return -1 // cannot happen
		}
		if two == s2 {
			if isnum {
				return 1
			}
			return -1
		}
		seg1, seg2 := a[one:s1], b[two:s2]
		if isnum {
			seg1 = strings.TrimLeft(seg1, "0")
			seg2 = strings.TrimLeft(seg2, "0")
			if len(seg1) > len(seg2) {
				return 1
			}
			if len(seg2) > len(seg1) {
				return -1
			}
		}
		if r := strings.Compare(seg1, seg2); r != 0 {
			return r
		}
		one, two = s1, s2
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	if one >= len(a) {
		return -1
	}
	return 1
}
