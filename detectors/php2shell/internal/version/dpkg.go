package version

import (
	"errors"
	"fmt"
	"strings"
)

// DpkgVersion is a parsed Debian package version: [epoch:]upstream[-revision].
type DpkgVersion struct {
	Epoch    int
	Upstream string
	Revision string
}

// String formats the version the way dpkg writes it unambiguously: the epoch
// is omitted when zero unless the upstream version contains a colon.
func (v DpkgVersion) String() string {
	s := v.Upstream
	if v.Epoch != 0 || strings.IndexByte(v.Upstream, ':') >= 0 {
		s = fmt.Sprintf("%d:%s", v.Epoch, s)
	}
	if v.Revision != "" {
		s += "-" + v.Revision
	}
	return s
}

const maxDpkgEpoch = 1<<31 - 1 // INT_MAX, dpkg's limit

// ParseDpkg parses a Debian version exactly as dpkg's parseversion()
// (lib/dpkg/parsehelp.c) does, and rejects everything dpkg rejects or warns
// about:
//
//   - errors in dpkg: empty or blank string, embedded blanks, empty epoch,
//     non-numeric, negative or too large (> INT_MAX) epoch, nothing after the
//     colon, empty revision after a trailing hyphen, empty upstream version;
//   - warnings in dpkg ("has bad syntax" but still compared): upstream not
//     starting with a digit, a character other than [A-Za-z0-9.+~:-] in the
//     upstream version, or other than [A-Za-z0-9.+~] in the revision.
//
// Warnings are treated as errors here on purpose: dpkg still orders such
// versions, but no archive ships them, and a verdict must not rest on a
// version dpkg itself calls malformed. Like dpkg, leading and trailing blanks
// (space, tab) are ignored and the epoch is read with strtol semantics, so
// "+1:2" and "01:2" both have epoch 1. A NUL byte is rejected (dpkg can never
// see one: C strings end there).
func ParseDpkg(s string) (DpkgVersion, error) {
	var v DpkgVersion
	if strings.IndexByte(s, 0) >= 0 {
		return v, errors.New("version string contains a NUL byte")
	}
	i := 0
	for i < len(s) && isBlank(s[i]) {
		i++
	}
	s = s[i:]
	if s == "" {
		return v, errors.New("version string is empty")
	}
	end := 0
	for end < len(s) && !isBlank(s[end]) {
		end++
	}
	for j := end; j < len(s); j++ {
		if !isBlank(s[j]) {
			return v, errors.New("version string has embedded spaces")
		}
	}
	str := s // dpkg searches the colon from here, before cutting at end
	if colon := strings.IndexByte(str, ':'); colon >= 0 {
		epoch, stop, overflow := strtol10(str)
		switch {
		case stop == 0:
			return v, errors.New("epoch in version is empty")
		case stop != colon:
			return v, errors.New("epoch in version is not number")
		case epoch < 0:
			return v, errors.New("epoch in version is negative")
		case overflow || epoch > maxDpkgEpoch:
			return v, errors.New("epoch in version is too big")
		}
		if colon+1 >= len(str) {
			return v, errors.New("nothing after colon in version number")
		}
		v.Epoch = int(epoch)
		// end is an offset into s; the colon precedes it (no blank before end).
		str = s[colon+1 : end]
	} else {
		str = s[:end]
	}
	up, rev := str, ""
	if h := strings.LastIndexByte(str, '-'); h >= 0 {
		up, rev = str[:h], str[h+1:]
		if rev == "" {
			return v, errors.New("revision number is empty")
		}
	}
	if up == "" {
		return v, errors.New("version number is empty")
	}
	if !isDigit(up[0]) {
		return v, errors.New("version number does not start with digit")
	}
	for k := 1; k < len(up); k++ {
		c := up[k]
		if !isDigit(c) && !isAlpha(c) && strings.IndexByte(".-+~:", c) < 0 {
			return v, errors.New("invalid character in version number")
		}
	}
	for k := 0; k < len(rev); k++ {
		c := rev[k]
		if !isDigit(c) && !isAlpha(c) && strings.IndexByte(".+~", c) < 0 {
			return v, errors.New("invalid character in revision number")
		}
	}
	v.Upstream, v.Revision = up, rev
	return v, nil
}

// strtol10 mimics C strtol(s, &end, 10): skip isspace, optional sign, digits.
// stop is the index where parsing stopped, 0 when no digits were read (strtol
// then sets end to the start of the string). overflow reports ERANGE.
func strtol10(s string) (val int64, stop int, overflow bool) {
	i := 0
	for i < len(s) && strings.IndexByte(" \t\n\v\f\r", s[i]) >= 0 {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	var n uint64
	for i < len(s) && isDigit(s[i]) {
		if n > (1<<63)/10 {
			overflow = true
		} else {
			n = n*10 + uint64(s[i]-'0')
			if n > 1<<63 {
				overflow = true
			}
		}
		i++
	}
	if i == start {
		return 0, 0, false
	}
	if overflow {
		if neg {
			return -1 << 63, i, true
		}
		return 1<<63 - 1, i, true
	}
	if neg {
		if n == 1<<63 {
			return -1 << 63, i, false
		}
		return -int64(n), i, false
	}
	if n == 1<<63 {
		return 1<<63 - 1, i, true
	}
	return int64(n), i, false
}

// CompareDpkg compares two Debian package versions with dpkg's ordering
// (Debian Policy 5.6.12, dpkg_version_compare): epoch numerically, then the
// upstream version and the revision with verrevcmp, where "~" sorts before
// everything including the end of the string, letters sort before other
// characters, and digit runs compare numerically. It returns -1, 0 or 1, or an
// error when either version is one dpkg rejects or warns about (see ParseDpkg).
func CompareDpkg(a, b string) (int, error) {
	va, err := ParseDpkg(a)
	if err != nil {
		return 0, fmt.Errorf("dpkg version %q: %w", a, err)
	}
	vb, err := ParseDpkg(b)
	if err != nil {
		return 0, fmt.Errorf("dpkg version %q: %w", b, err)
	}
	return va.Compare(vb), nil
}

// Compare orders two parsed versions; -1, 0 or 1.
func (v DpkgVersion) Compare(o DpkgVersion) int {
	switch {
	case v.Epoch > o.Epoch:
		return 1
	case v.Epoch < o.Epoch:
		return -1
	}
	if r := verrevcmp(v.Upstream, o.Upstream); r != 0 {
		return sign(r)
	}
	return sign(verrevcmp(v.Revision, o.Revision))
}

func dpkgOrder(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp is dpkg's lib/dpkg/version.c verrevcmp on Go strings (the end of
// the string plays the role of the NUL terminator).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0
	}
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := dpkgOrder(a, i), dpkgOrder(b, j)
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(at(a, i)) {
			return 1
		}
		if isDigit(at(b, j)) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
