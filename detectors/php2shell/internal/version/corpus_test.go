package version

import (
	"math/rand/v2"
	"strings"
)

// Version corpora for the differential tests. golden_gen_test.go (build tag
// "golden") runs them through the real dpkg, apk-tools 2 and 3, and rpm in
// Docker and records the results in testdata; difftest_test.go replays them
// offline.

// realPHP are package versions seen in real archives for PHP and its
// dependencies, across Debian, Ubuntu, sury.org, Alpine, RHEL, Amazon and SUSE.
var realPHP = []string{
	"8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.1", "8.3.6-0ubuntu0.24.04",
	"8.2.35-1~deb12u1", "8.2.29-1~deb12u1", "8.2.7-1~deb12u1", "8.2.35-1", "8.2.35-1+b1",
	"8.4.27-1~deb13u1", "8.4.11-1", "8.4.16-1~deb13u1", "8.4.27-1",
	"7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29", "7.4.3-4ubuntu2.28+esm1", "7.4.3-4ubuntu2",
	"5.5.9+dfsg-1ubuntu4.29+esm18", "5.5.9+dfsg-1ubuntu4.29", "5.5.9+dfsg-1ubuntu4.30",
	"7.0.33-0ubuntu0.16.04.16+esm9", "7.2.24-0ubuntu0.18.04.17+esm4", "8.1.2-1ubuntu2.22", "8.1.2-1ubuntu2.23~esm1",
	"1:8.2.35-1+0~20261021.1+debian12~1.gbp1234", "1:8.2.34-1+0~20260904.1+debian12~1.gbpabcd",
	"8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "8.3.35-1+ubuntu24.04.1+deb.sury.org+1", "8.3.36-1+ubuntu22.04.1+deb.sury.org+1",
	"8.2.35-1+debian12.1+deb.sury.org+1", "2:92", "2:93", "1:7.4+76", "2:8.2+93",
	"8.3.29-r0", "8.4.27-r1", "8.4.27-r0", "8.3.36-r0", "8.2.35-r0", "8.4.14-r1", "8.5.12-r0",
	"8.2.13-1.module+el9.4.0+20xxx+abcd1234", "8.2.13-1.module+el9.4.0+21678+aa2d0d51", "8.2.13-1.module+el9.5.0+22521+2f20a3e5",
	"8.0.30-1.el9_2", "8.0.30-3.el9_6", "8.0.30-2.el9_6.1", "1:8.0.30-1.el9_2",
	"8.2.35-150600.3.39.1", "8.2.35-150600.3.40.1", "8.2.20-150600.3.6.1", "8.3.26-1.amzn2023.0.1", "8.4.14-1.amzn2023.0.2",
	"8.2.35-1.fc41", "8.3.26-1.fc42", "8.2.35-1.el8.remi", "8.3.36-1.el9.remi", "7.4.33-21.el8.remi",
	"1.2.3_rc1-r2", "2.0_p1-r0", "1.0_alpha2-r0", "3.5_git20240101-r0", "0.9.8zh-r0", "1.1.1w-r1", "2.4.62-r0",
	"1.36.1-r29", "3.3.2-r0", "1.2.13_git20231212~ab12cd-r1",
	"9.6.6-0+deb12u1", "1:9.6.6+dfsg-1", "2.36-9+deb12u10", "252.39-1~deb12u1",
}

// curatedDpkg probes every branch of parseversion and verrevcmp.
var curatedDpkg = []string{
	"0", "00", "1", "01", "1.0", "1.00", "1.0.0", "1.0~", "1.0~~", "1.0~~a", "1.0~a", "1.0~1", "1.0a", "1.0A", "1.0+",
	"1.0.", "1.0-1", "1.0-0", "1.0-00", "1.0-", "1.0--1", "1.0-1-1", "0:1.0", "1:1.0", "01:1.0", "+1:1.0", "-0:1.0",
	"-1:1.0", ":1.0", "a:1.0", "1a:1.0", "1:", "1::", "1:1:1", "1:1.0-1:2", "-1", "1.0 ", " 1.0", "\t1.0", "1.0\t",
	"1 0", "a1.0", "1.0_1", "1.0-1_2", "1.0@", "~", "~1", "+1", ".1", "2147483647:1", "2147483648:1",
	"99999999999999999999:1", "9223372036854775807:1", "9223372036854775808:1", " 1:1", "\n1:1.0", "1.0\n",
	"1.0-1.", "1.0-1~", "1.0-1+", "1.0-~", "1.0-a", "1.0-A", "1.0-+", "1.0-.", "1.0+~", "1.0~+", "1.0.~", "1.0~.",
	"1.0z", "1.0Z", "1.0zz", "1.0aa", "1.0ab", "1.0b", "1.0.a", "1.0.1a", "1.0a1", "1.0a01", "1.0a001",
	"10", "9", "100", "000100", "1.10", "1.9", "1.010", "1.09", "1:0", "0:0", "2:0", "1.0~rc1", "1.0~rc2", "1.0~beta1",
	"1.0+dfsg", "1.0+dfsg1", "1.0+dfsg-1", "1.0~dfsg-1", "1.0-1ubuntu1", "1.0-1ubuntu0.1", "1.0-1build1", "1.0-1+b1",
	"1.0-1~bpo12+1", "1.0-1~deb12u1", "1.0-1+deb12u1", "1.0é", "1.0-é", "é1", "1.0\x7f", "1:a", "1:~", "1:1~",
	"18446744073709551616", "18446744073709551617", "1.18446744073709551616", "1.18446744073709551615",
}

var curatedAPK = []string{
	"0", "00", "1", "01", "001", "1.0", "1.00", "1.000", "1.01", "1.001", "1.010", "1.1", "1.10", "1.0.0",
	"1.0a", "1.0b", "1.0z", "1.0A", "1.0aa", "1.0a1", "1.0a.1", "1.0_alpha", "1.0_alpha1", "1.0_alpha01", "1.0_beta",
	"1.0_beta2", "1.0_pre", "1.0_pre1", "1.0_rc", "1.0_rc1", "1.0_rc10", "1.0_cvs", "1.0_svn", "1.0_git", "1.0_git20240101",
	"1.0_hg", "1.0_p", "1.0_p1", "1.0_p01", "1.0_px", "1.0_pr", "1.0_preview", "1.0_foo", "1.0_", "1.0_1", "1.0_rc1_p2",
	"1.0_rc1_rc2", "1.0_alpha_beta", "1.0_p1_p2", "1.0-r0", "1.0-r1", "1.0-r01", "1.0-r10", "1.0-r", "1.0-", "1.0-r1-r2",
	"1.0-1", "1.0-rr", "1.0~abc", "1.0~ABC", "1.0~", "1.0~0", "1.0~g", "1.0~abc-r1", "1.0-r1~abc", "1.0~abc~def",
	"1.0_rc1~abc-r2", "1.0a_rc1", "1.0a~f-r3", "1.", ".1", "", "a", "a1", "x1", "1..0", "1.0.", "1.a", "1_rc1",
	"1-r1", "1a", "1a1", "1aa", "12345678901234567", "123456789012345678", "1234567890123456789",
	"18446744073709551615", "18446744073709551616", "18446744073709551617", "1.18446744073709551616", "1.0-r18446744073709551616",
	"1.0-r18446744073709551615", "1.0_p18446744073709551616", "1.012345678901234567", "1.0_rc1-r0", "1.0_rc1-r1",
	"2.0_p1~abc123-r0", "1.2.3_rc1-r2", "8.3.29-r0", "8.4.27-r1", "0.0.0", "0.0", "1.0_alpha-r1", "1.0_alpha1-r1",
	"1.0.0_rc1", "1.0.0-r0", "1.0.1_rc1", "1.0 ", " 1.0", "1.0+1", "1:1.0",
}

var curatedRPM = []string{
	"0", "00", "1", "01", "1.0", "1.00", "1.0.0", "1.0~", "1.0~~", "1.0~rc1", "1.0~rc2", "1.0^", "1.0^1", "1.0^^",
	"1.0^git1", "1.0~^", "1.0^~", "1.0a", "1.0A", "1.0.a", "1.0_1", "1.0+1", "1.0-1", "1.0-0", "1.0-", "-1", "1.0-1-1",
	"0:1.0", "1:1.0", "01:1.0", ":1.0", "a:1.0", "1:", "1:1:1", "1:1.0-1:2", "1.0-1.el9", "1.0-1.el9_2", "1.0-2.el9",
	"1.0-1.fc41", "1.0-10.fc41", "1.0-1.module+el9.4.0+20xxx+abcd1234", "a", "b", "aa", "A", "Z", "z", "1a", "a1",
	"1.a", "a.1", "1..0", "1.-0", "1_0", "1+0", "1~0", "1^0", "~", "^", "~1", "^1", ".", "..", "-", "1.0 ", " 1.0",
	"1.0é", "é", "1.0-é", "10", "9", "010", "1.010", "1.09", "1.9", "1.10", "99999999999999999999", "100000000000000000000",
	"1.0-1.1", "1.0-1.01", "1.0-1.a", "2:0", "0:0", "1.0.el9", "1.0-0.1.rc1", "1.0-0.2.rc1",
}

func rng(seed uint64) *rand.Rand { return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) }

func pick(r *rand.Rand, xs ...string) string { return xs[r.IntN(len(xs))] }

func digits(r *rand.Rand) string {
	switch r.IntN(10) {
	case 0:
		return "0"
	case 1:
		return "0" + itoa(r.IntN(30))
	case 2:
		return itoa(r.IntN(100000))
	default:
		return itoa(r.IntN(12))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// randomDpkg builds mostly well-formed Debian versions with random structure,
// plus a share of near-misses.
func randomDpkg(n int) []string {
	r := rng(1)
	part := func(seps string, letters bool) string {
		var b strings.Builder
		b.WriteString(digits(r))
		for k := r.IntN(5); k > 0; k-- {
			switch r.IntN(6) {
			case 0, 1:
				b.WriteByte(seps[r.IntN(len(seps))])
				b.WriteString(digits(r))
			case 2:
				if letters {
					b.WriteString(pick(r, "a", "b", "z", "A", "Z", "rc", "beta", "ubuntu", "deb", "dfsg", "esm", "build", "bpo", "gbp"))
				}
			case 3:
				b.WriteByte(seps[r.IntN(len(seps))])
			default:
				b.WriteString(digits(r))
				b.WriteByte(seps[r.IntN(len(seps))])
				b.WriteString(digits(r))
			}
		}
		return b.String()
	}
	seen := map[string]bool{}
	var out []string
	for len(out) < n {
		var s string
		if r.IntN(4) == 0 {
			s = itoa(r.IntN(3)) + ":"
		}
		s += part(".+~", true)
		if r.IntN(3) > 0 {
			s += "-" + part(".+~", true)
		}
		if r.IntN(15) == 0 { // near-miss
			i := r.IntN(len(s) + 1)
			s = s[:i] + pick(r, "_", "@", " ", "-", ":", "~", "a", "!") + s[i:]
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func randomAPK(n int) []string {
	r := rng(2)
	seen := map[string]bool{}
	var out []string
	for len(out) < n {
		var b strings.Builder
		b.WriteString(digits(r))
		for k := r.IntN(4); k > 0; k-- {
			b.WriteString("." + digits(r))
		}
		if r.IntN(5) == 0 {
			b.WriteString(pick(r, "a", "b", "z"))
		}
		for k := r.IntN(3); k > 0 && r.IntN(2) == 0; k-- {
			b.WriteString("_" + pick(r, "alpha", "beta", "pre", "rc", "cvs", "svn", "git", "hg", "p"))
			if r.IntN(2) == 0 {
				b.WriteString(digits(r))
			}
		}
		if r.IntN(6) == 0 {
			b.WriteString("~" + pick(r, "a", "0", "abc123", "deadbeef", "f00", "1"))
		}
		if r.IntN(3) > 0 {
			b.WriteString("-r" + digits(r))
		}
		s := b.String()
		if r.IntN(15) == 0 {
			i := r.IntN(len(s) + 1)
			s = s[:i] + pick(r, "_", ".", "-", "~", "a", "A", "-r", "_p") + s[i:]
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func randomRPM(n int) []string {
	r := rng(3)
	seg := func() string {
		var b strings.Builder
		for k := 1 + r.IntN(5); k > 0; k-- {
			switch r.IntN(7) {
			case 0:
				b.WriteString(pick(r, "a", "b", "el", "fc", "rc", "git", "module", "Z", "amzn", "remi"))
			case 1:
				b.WriteString(pick(r, ".", ".", "_", "+", "~", "^", "%"))
			default:
				b.WriteString(digits(r))
				if r.IntN(2) == 0 {
					b.WriteByte('.')
				}
			}
		}
		return b.String()
	}
	seen := map[string]bool{}
	var out []string
	for len(out) < n {
		var s string
		if r.IntN(5) == 0 {
			s = itoa(r.IntN(3)) + ":"
		}
		s += seg()
		if r.IntN(3) > 0 {
			s += "-" + seg()
		}
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dedup(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func dpkgCorpus() []string { return dedup(curatedDpkg, realPHP, randomDpkg(450)) }
func apkCorpus() []string  { return dedup(curatedAPK, realPHP, randomAPK(450)) }
func rpmCorpus() []string  { return dedup(curatedRPM, realPHP, randomRPM(500)) }
