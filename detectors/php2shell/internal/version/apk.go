package version

import (
	"fmt"
	"strings"
)

// CompareAPK compares two Alpine package versions
// (digit{.digit}...{letter}{_suffix{number}}...{~hash}{-rN}) and returns -1, 0
// or 1.
//
// It runs both apk-tools orderings, transcribed from the sources: apk-tools 3
// (src/version.c of 3.0.x, used by Alpine 3.23 and later) and apk-tools 2
// (src/version.c of 2.14.x, Alpine 3.22 and earlier). It returns an error when
// either version is invalid for either implementation (apk_version_validate),
// or when the two implementations order the pair differently, so a verdict
// never depends on which apk-tools generation a system runs. For every version
// Alpine actually ships (8.3.29-r0, 1.2.3_rc1-r2, 2.0_p1~abc123-r0 ...) the two
// agree.
func CompareAPK(a, b string) (int, error) {
	for _, v := range [2]string{a, b} {
		if err := ValidateAPK(v); err != nil {
			return 0, err
		}
	}
	r3 := apk3Compare(a, b)
	r2 := apk2Compare(a, b)
	if r3 != r2 {
		return 0, fmt.Errorf("apk versions %q and %q: apk-tools 2 and 3 order them differently", a, b)
	}
	return r3, nil
}

// ValidateAPK reports whether apk-tools 2 and 3 both accept v as a version.
func ValidateAPK(v string) error {
	if strings.IndexByte(v, 0) >= 0 {
		return fmt.Errorf("apk version %q: contains a NUL byte", v)
	}
	if !apk3Validate(v) {
		return fmt.Errorf("apk version %q: invalid for apk-tools 3", v)
	}
	if !apk2Validate(v) {
		return fmt.Errorf("apk version %q: invalid for apk-tools 2", v)
	}
	return nil
}

// ---- apk-tools 3 ----

const (
	t3InitialDigit = iota
	t3Digit
	t3Letter
	t3Suffix
	t3SuffixNo
	t3CommitHash
	t3RevisionNo
	t3End
	t3Invalid
)

const (
	suf3Invalid = iota
	suf3Alpha
	suf3Beta
	suf3Pre
	suf3RC
	suf3None
	suf3CVS
	suf3SVN
	suf3Git
	suf3Hg
	suf3P
)

type apk3Token struct {
	token  int
	suffix int
	number uint64
	value  string
}

func apk3SuffixValue(s string) int {
	if s == "" {
		return suf3Invalid
	}
	var val int
	var lit string
	switch s[0] {
	case 'a':
		val, lit = suf3Alpha, "alpha"
	case 'b':
		val, lit = suf3Beta, "beta"
	case 'c':
		val, lit = suf3CVS, "cvs"
	case 'g':
		val, lit = suf3Git, "git"
	case 'h':
		val, lit = suf3Hg, "hg"
	case 'p':
		if len(s) > 1 {
			val, lit = suf3Pre, "pre"
		} else {
			val, lit = suf3P, "p"
		}
	case 'r':
		val, lit = suf3RC, "rc"
	case 's':
		val, lit = suf3SVN, "svn"
	default:
		return suf3Invalid
	}
	if s != lit {
		return suf3Invalid
	}
	return val
}

// apk3ParseDigits is token_parse_digits: apk_blob_pull_uint (uint64, wrapping)
// over the leading decimal digits.
func apk3ParseDigits(t *apk3Token, b *string) {
	s := *b
	i := 0
	var n uint64
	for i < len(s) && isDigit(s[i]) {
		n = n*10 + uint64(s[i]-'0')
		i++
	}
	t.number = n
	t.value = s[:i]
	*b = s[i:]
	if i == 0 {
		t.token = t3Invalid
	}
}

func apk3First(t *apk3Token, b *string) {
	t.token = t3InitialDigit
	apk3ParseDigits(t, b)
}

func isHexLower(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') }

func apk3Next(t *apk3Token, b *string) {
	s := *b
	if len(s) == 0 {
		t.token = t3End
		return
	}
	c := s[0]
	switch {
	case isLower(c):
		if t.token > t3Digit {
			t.token = t3Invalid
			return
		}
		t.value = s[:1]
		t.token = t3Letter
		*b = s[1:]
	case c == '.' || isDigit(c):
		if c == '.' {
			if t.token > t3Digit {
				t.token = t3Invalid
				return
			}
			*b = s[1:]
		}
		switch t.token {
		case t3InitialDigit, t3Digit:
			t.token = t3Digit
		case t3Suffix:
			t.token = t3SuffixNo
		default:
			t.token = t3Invalid
			return
		}
		apk3ParseDigits(t, b)
	case c == '_':
		if t.token > t3SuffixNo {
			t.token = t3Invalid
			return
		}
		s = s[1:]
		i := 0
		for i < len(s) && isLower(s[i]) {
			i++
		}
		t.value = s[:i]
		*b = s[i:]
		t.suffix = apk3SuffixValue(t.value)
		if t.suffix == suf3Invalid {
			t.token = t3Invalid
			return
		}
		t.token = t3Suffix
	case c == '~':
		if t.token >= t3CommitHash {
			t.token = t3Invalid
			return
		}
		s = s[1:]
		i := 0
		for i < len(s) && isHexLower(s[i]) {
			i++
		}
		t.value = s[:i]
		*b = s[i:]
		if i == 0 {
			t.token = t3Invalid
			return
		}
		t.token = t3CommitHash
	case c == '-':
		if t.token >= t3RevisionNo {
			t.token = t3Invalid
			return
		}
		if !strings.HasPrefix(s, "-r") {
			t.token = t3Invalid
			return
		}
		*b = s[2:]
		t.token = t3RevisionNo
		apk3ParseDigits(t, b)
	default:
		t.token = t3Invalid
	}
}

func apk3Validate(v string) bool {
	var t apk3Token
	for apk3First(&t, &v); t.token < t3End; apk3Next(&t, &v) {
	}
	return t.token == t3End
}

func blobSort(a, b string) int {
	// apk_blob_sort: memcmp over the common length, then length.
	return strings.Compare(a, b)
}

func apk3TokenCmp(ta, tb *apk3Token) int {
	var a, b uint64
	switch ta.token {
	case t3Digit:
		if ta.value[0] == '0' || tb.value[0] == '0' {
			return sign(blobSort(ta.value, tb.value))
		}
		a, b = ta.number, tb.number
	case t3InitialDigit, t3SuffixNo, t3RevisionNo:
		a, b = ta.number, tb.number
	case t3Letter:
		a, b = uint64(ta.value[0]), uint64(tb.value[0])
	case t3Suffix:
		a, b = uint64(ta.suffix), uint64(tb.suffix)
	default:
		return sign(blobSort(ta.value, tb.value))
	}
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// apk3Compare is apk_version_compare_fuzzy(a, b, false) for valid versions.
func apk3Compare(a, b string) int {
	var ta, tb apk3Token
	apk3First(&ta, &a)
	apk3First(&tb, &b)
	for ta.token == tb.token && ta.token < t3End {
		if r := apk3TokenCmp(&ta, &tb); r != 0 {
			return r
		}
		apk3Next(&ta, &a)
		apk3Next(&tb, &b)
	}
	if ta.token == tb.token {
		return 0
	}
	if ta.token == t3Suffix && ta.suffix < suf3None {
		return -1
	}
	if tb.token == t3Suffix && tb.suffix < suf3None {
		return 1
	}
	if ta.token > tb.token {
		return -1
	}
	if tb.token > ta.token {
		return 1
	}
	return 0
}

// ---- apk-tools 2 ----

const (
	t2Invalid = iota - 1
	t2DigitOrZero
	t2Digit
	t2Letter
	t2Suffix
	t2SuffixNo
	t2RevisionNo
	t2End
)

func apk2NextToken(typ *int, b *string) {
	s := *b
	n := t2Invalid
	switch {
	case len(s) == 0:
		n = t2End
	case (*typ == t2Digit || *typ == t2DigitOrZero) && isLower(s[0]):
		n = t2Letter
	case *typ == t2Letter && isDigit(s[0]):
		n = t2Digit
	case *typ == t2Suffix && isDigit(s[0]):
		n = t2SuffixNo
	default:
		switch s[0] {
		case '.':
			n = t2DigitOrZero
		case '_':
			n = t2Suffix
		case '-':
			if len(s) > 1 && s[1] == 'r' {
				n = t2RevisionNo
				s = s[1:]
			} else {
				n = t2Invalid
			}
		}
		s = s[1:]
	}
	*b = s
	if n < *typ {
		if !((n == t2DigitOrZero && *typ == t2Digit) ||
			(n == t2Suffix && *typ == t2SuffixNo) ||
			(n == t2Digit && *typ == t2Letter)) {
			n = t2Invalid
		}
	}
	*typ = n
}

var (
	apk2Pre  = [...]string{"alpha", "beta", "pre", "rc"}
	apk2Post = [...]string{"cvs", "svn", "git", "hg", "p"}
)

func apk2GetToken(typ *int, b *string) int64 {
	s := *b
	i := 0
	nt := t2Invalid
	var v int64
	if len(s) <= 0 {
		*typ = t2End
		return 0
	}
	invalid := func() int64 {
		*typ = t2Invalid
		return -1
	}
	switch *typ {
	case t2DigitOrZero, t2Digit, t2SuffixNo, t2RevisionNo:
		if *typ == t2DigitOrZero && s[0] == '0' {
			for i+1 < len(s) && s[i+1] == '0' {
				i++
			}
			nt = t2Digit
			v = -int64(i)
			break
		}
		for i < len(s) && isDigit(s[i]) {
			v *= 10
			v += int64(s[i] - '0')
			i++
		}
		if i >= 18 {
			return invalid()
		}
	case t2Letter:
		v = int64(s[i])
		i++
	case t2Suffix:
		found := false
		for k, p := range apk2Pre {
			if strings.HasPrefix(s, p) {
				i = len(p)
				v = int64(k - len(apk2Pre))
				found = true
				break
			}
		}
		if !found {
			for k, p := range apk2Post {
				if strings.HasPrefix(s, p) {
					i = len(p)
					v = int64(k)
					found = true
					break
				}
			}
		}
		if !found {
			return invalid()
		}
	default:
		return invalid()
	}
	s = s[i:]
	*b = s
	switch {
	case len(s) == 0:
		*typ = t2End
	case nt != t2Invalid:
		*typ = nt
	default:
		apk2NextToken(typ, b)
	}
	return v
}

func apk2Validate(v string) bool {
	t := t2Digit
	for t != t2End && t != t2Invalid {
		apk2GetToken(&t, &v)
	}
	return t == t2End
}

// apk2Compare is apk_version_compare_blob_fuzzy(a, b, FALSE).
func apk2Compare(a, b string) int {
	at, bt := t2Digit, t2Digit
	var av, bv int64
	for at == bt && at != t2End && at != t2Invalid && av == bv {
		av = apk2GetToken(&at, &a)
		bv = apk2GetToken(&bt, &b)
	}
	if av < bv {
		return -1
	}
	if av > bv {
		return 1
	}
	if at == bt {
		return 0
	}
	tt := at
	if at == t2Suffix && apk2GetToken(&tt, &a) < 0 {
		return -1
	}
	tt = bt
	if bt == t2Suffix && apk2GetToken(&tt, &b) < 0 {
		return 1
	}
	if at > bt {
		return -1
	}
	if bt > at {
		return 1
	}
	return 0
}
