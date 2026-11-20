package pkgdb

import (
	"strconv"
	"strings"
)

// CompareDpkg compares two Debian versions as dpkg does
// ([epoch:]upstream[-revision]).
func CompareDpkg(a, b string) int {
	ea, ua, ra := splitDeb(a)
	eb, ub, rb := splitDeb(b)
	if c := cmpInt(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDeb(v string) (int, string, string) {
	epoch := 0
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.Atoi(e); err == nil && len(e) < 10 {
			epoch, v = n, rest
		}
	}
	up, rev := v, ""
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		up, rev = v[:i], v[i+1:]
	}
	return epoch, up, rev
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// verrevcmp is dpkg's comparison of an upstream version or revision.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a[i]) || j < len(b) && !isDigit(b[j]) {
			ac, bc := 0, 0
			if i < len(a) && !isDigit(a[i]) {
				ac = order(a[i])
			}
			if j < len(b) && !isDigit(b[j]) {
				bc = order(b[j])
			}
			if ac != bc {
				return cmpInt(ac, bc)
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
		first := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if first == 0 {
				first = cmpInt(int(a[i]), int(b[j]))
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}

// apkSuffix orders apk's version suffixes: pre-releases before the
// release, post-releases after.
var apkSuffix = map[string]int{"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}

type apkVer struct {
	nums   []int
	letter byte
	suf    []struct {
		kind int
		n    int
	}
	rev int
	ok  bool
}

func parseAPK(v string) apkVer {
	var out apkVer
	main, rev, hasRev := strings.Cut(v, "-r")
	if hasRev {
		n, err := strconv.Atoi(rev)
		if err != nil || len(rev) > 9 {
			return out
		}
		out.rev = n
	}
	body, sufs, _ := strings.Cut(main, "_")
	for _, p := range strings.Split(body, ".") {
		if p == "" {
			return out
		}
		digits := strings.TrimRight(p, "abcdefghijklmnopqrstuvwxyz")
		if len(p)-len(digits) > 1 || digits == "" || len(digits) > 9 {
			return out
		}
		if len(digits) != len(p) {
			out.letter = p[len(p)-1]
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return out
		}
		out.nums = append(out.nums, n)
	}
	if sufs != "" {
		for _, s := range strings.Split(sufs, "_") {
			name := strings.TrimRight(s, "0123456789")
			k, ok := apkSuffix[name]
			if !ok || name == "" {
				return out
			}
			n := 0
			if d := s[len(name):]; d != "" {
				if len(d) > 9 {
					return out
				}
				n, _ = strconv.Atoi(d)
			}
			out.suf = append(out.suf, struct {
				kind int
				n    int
			}{k, n})
		}
	}
	out.ok = true
	return out
}

// CompareAPK compares two apk versions; ok is false when either cannot be
// read.
func CompareAPK(a, b string) (int, bool) {
	x, y := parseAPK(a), parseAPK(b)
	if !x.ok || !y.ok {
		return 0, false
	}
	for i := 0; i < len(x.nums) || i < len(y.nums); i++ {
		p, q := -1, -1
		if i < len(x.nums) {
			p = x.nums[i]
		}
		if i < len(y.nums) {
			q = y.nums[i]
		}
		if c := cmpInt(p, q); c != 0 {
			return c, true
		}
	}
	if c := cmpInt(int(x.letter), int(y.letter)); c != 0 {
		return c, true
	}
	for i := 0; i < len(x.suf) || i < len(y.suf); i++ {
		var p, q struct {
			kind int
			n    int
		}
		if i < len(x.suf) {
			p = x.suf[i]
		}
		if i < len(y.suf) {
			q = y.suf[i]
		}
		if c := cmpInt(p.kind, q.kind); c != 0 {
			return c, true
		}
		if c := cmpInt(p.n, q.n); c != 0 {
			return c, true
		}
	}
	return cmpInt(x.rev, y.rev), true
}
