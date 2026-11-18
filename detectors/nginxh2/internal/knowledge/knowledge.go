// Package knowledge holds what is known about the nginx HTTP/2 pair,
// CVE-2026-123007 and CVE-2026-123633, and judges a version against it.
// Every value is sourced in ../../FACTS.md. It knows nothing about files,
// images or the engine.
package knowledge

import (
	"fmt"
	"strconv"
	"strings"
)

// Dates.
const (
	Disclosed = "2026-11-18"
	Checked   = "2026-11-18"
)

// CVSS is the score findings carry (Wiz, CVSS 4.0, both CVEs).
const CVSS = "9.2"

// CVE IDs.
const (
	Flow  = "CVE-2026-123007"
	Reuse = "CVE-2026-123633"
)

// CVE is one of the pair.
type CVE struct {
	ID    string
	Short string // a few words, for messages
	// Introduced is the first upstream release with the flaw.
	Introduced V
	// Fixed is the first fixed release of each line that received a fix.
	// A line newer than every line here branched after the fix.
	Fixed []V
	// PlusFixed is the same for NGINX Plus's numbered releases.
	PlusFixed []V
	// PlusFrom is the first NGINX Plus R release F5 lists as affected.
	PlusFrom int
	Commits  []string
	Advisory string
}

// CVEs are the pair, in report order.
var CVEs = []CVE{
	{
		ID: Flow, Short: "memory corruption in HTTP/2 flow control",
		Introduced: MustV("1.9.5"), Fixed: []V{MustV("1.30.7"), MustV("1.31.9")},
		PlusFixed: []V{MustV("37.0.8.1"), MustV("37.3.0.1")}, PlusFrom: 33,
		Commits:  []string{"e27f5fa84fe6e98505e70bc543b748747dad0a3b", "b89c4100bf6762a45e4a6463eaf4b70368277c94"},
		Advisory: "https://my.f5.com/manage/s/article/K000163926",
	},
	{
		ID: Reuse, Short: "use-after-free in HTTP/2 connection reuse",
		Introduced: MustV("1.19.7"), Fixed: []V{MustV("1.30.7"), MustV("1.31.9")},
		PlusFixed: []V{MustV("37.0.7.1"), MustV("37.2.0.1")}, PlusFrom: 33,
		Commits:  []string{"2df48a501d0fb8212b7d39dffeeff5876332ba59", "0c87dd1db413e440a4e3ef7ee8acc518509e8809"},
		Advisory: "https://my.f5.com/manage/s/article/K000163928",
	},
}

// ByID returns the CVE with that ID.
func ByID(id string) (CVE, bool) {
	for _, c := range CVEs {
		if c.ID == id {
			return c, true
		}
	}
	return CVE{}, false
}

// FixedText is how a message names the fixed releases.
const FixedText = "1.31.9 (mainline) and 1.30.7 (stable)"

// V is a version of dotted numbers, 2 to 4 of them.
type V []int

// ParseV reads "1.31.8" or "37.0.7.1". Anything else (a letter, a
// suffix, a leading zero run longer than the number allows, more than
// four parts) is an error: a version the detector cannot read is never
// judged.
func ParseV(s string) (V, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return nil, fmt.Errorf("version %q: want 2 to 4 numbers", s)
	}
	out := make(V, len(parts))
	for i, p := range parts {
		if p == "" || len(p) > 6 {
			return nil, fmt.Errorf("version %q: bad number %q", s, p)
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("version %q: %q is not a number", s, p)
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		out[i] = n
	}
	return out, nil
}

// MustV is ParseV for constants.
func MustV(s string) V {
	v, err := ParseV(s)
	if err != nil {
		panic(err)
	}
	return v
}

func (v V) String() string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ".")
}

// Cmp compares two versions; a missing part counts as 0.
func Cmp(a, b V) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// Line is a version's first two numbers ("1.31").
func (v V) Line() V {
	if len(v) < 2 {
		return v
	}
	return V{v[0], v[1]}
}

// Status is a judgement.
type Status string

const (
	Vulnerable  Status = "vulnerable"
	Fixed       Status = "fixed"
	NotAffected Status = "not-affected"
	Unknown     Status = "unknown"
)

// lines judges v by per-line fixed releases: at or past the line's fix is
// fixed, before it vulnerable; a line newer than every known one is
// unknown; an older line, or one between, got no fix.
func lines(v V, fixed, others []V) (Status, string) {
	newest := fixed[0]
	known := fixed[0]
	for _, f := range append(append([]V(nil), fixed...), others...) {
		if Cmp(f.Line(), known.Line()) > 0 {
			known = f
		}
	}
	for _, f := range fixed {
		if Cmp(f.Line(), v.Line()) == 0 {
			if Cmp(v, f) >= 0 {
				return Fixed, fmt.Sprintf("%s is at or past %s, the fixed release of its line", v, f)
			}
			return Vulnerable, fmt.Sprintf("%s is before %s, the fixed release of its line", v, f)
		}
		if Cmp(f, newest) > 0 {
			newest = f
		}
	}
	if Cmp(v.Line(), known.Line()) > 0 {
		// A later line would carry the fix, but none was known on the
		// check date: a version that claims one is not taken at its word
		// (NGINX Plus's 37.x numbers, a forged or misread version line).
		return Unknown, fmt.Sprintf("%s is on the %s line, newer than any known on %s (newest %s): not judged", v, v.Line(), Checked, known.Line())
	}
	if Cmp(v.Line(), newest.Line()) > 0 {
		return Fixed, fmt.Sprintf("%s is on the %s line, a known line that came after the fix (%s)", v, v.Line(), newest)
	}
	return Vulnerable, fmt.Sprintf("%s is on the %s line, which received no fix", v, v.Line())
}

// allFixed lists every CVE's fixed releases: the lines known to exist.
func allFixed(plus bool) []V {
	var out []V
	for _, c := range CVEs {
		if plus {
			out = append(out, c.PlusFixed...)
		} else {
			out = append(out, c.Fixed...)
		}
	}
	return out
}

// Nginx judges an upstream nginx version (three numbers).
func Nginx(c CVE, v V) (Status, string) {
	if len(v) != 3 {
		return Unknown, fmt.Sprintf("nginx version %s does not have three numbers", v)
	}
	if Cmp(v, c.Introduced) < 0 {
		return NotAffected, fmt.Sprintf("nginx %s is older than %s, the first release with the flawed code", v, c.Introduced)
	}
	st, why := lines(v, c.Fixed, allFixed(false))
	return st, "nginx " + why
}

// OpenResty releases: the newest known release on each nginx core
// (openresty/openresty tags, 2026-11-18). OpenResty backports nginx
// security fixes as patches without a new core, so a release newer than
// these on an unfixed core may carry the fix.
var OpenRestyNewest = map[string]int{
	"0.8.54": 9, "1.0.4": 2, "1.0.5": 1, "1.0.6": 22, "1.0.8": 26, "1.0.9": 10, "1.0.10": 48, "1.0.11": 28, "1.0.15": 11,
	"1.1.12": 5, "1.1.13": 1, "1.2.1": 14, "1.2.3": 8, "1.2.4": 14, "1.2.6": 6, "1.2.7": 8, "1.2.8": 6, "1.4.1": 3,
	"1.4.2": 9, "1.4.3": 9, "1.5.8": 1, "1.5.11": 1, "1.5.12": 1, "1.7.0": 1, "1.7.2": 1, "1.7.4": 1, "1.7.7": 2,
	"1.7.10": 2, "1.9.3": 2, "1.9.7": 5, "1.9.15": 1, "1.11.2": 5, "1.13.6": 2, "1.15.8": 3, "1.17.8": 2, "1.19.3": 2,
	"1.19.9": 2, "1.21.4": 4, "1.25.3": 2, "1.27.1": 2, "1.29.2": 5, "1.31.1": 1, "1.31.8": 1,
}

// OpenResty judges an OpenResty release (four numbers: the nginx core and
// OpenResty's own).
func OpenResty(c CVE, v V) (Status, string) {
	if len(v) != 4 {
		return Unknown, fmt.Sprintf("OpenResty version %s does not have four numbers", v)
	}
	core := v[:3]
	st, why := Nginx(c, core)
	if st != Vulnerable {
		return st, fmt.Sprintf("OpenResty %s bundles nginx %s: %s", v, core, strings.TrimPrefix(why, "nginx "))
	}
	newest, ok := OpenRestyNewest[core.String()]
	if !ok || v[3] > newest {
		return Unknown, fmt.Sprintf("OpenResty %s is not a release known on %s; its nginx core %s has the flaw, and OpenResty backports fixes as patches, so a newer release may carry it", v, Checked, core)
	}
	return Vulnerable, fmt.Sprintf("OpenResty %s bundles nginx %s (%s), and no OpenResty release carries the fix (newest on %s: 1.31.8.1)", v, core, strings.TrimPrefix(why, "nginx "), Checked)
}

// Newest known releases of the forks that carry the unfixed code
// (FACTS.md: inferred from their source).
var (
	TengineNewest = MustV("3.2.0")
	AngieNewest   = MustV("1.12.4")
)

// Tengine judges a Tengine release by its own number, with its nginx core
// for the lower bound.
func Tengine(c CVE, v, core V) (Status, string) {
	if core != nil && len(core) == 3 && Cmp(core, c.Introduced) < 0 {
		return NotAffected, fmt.Sprintf("Tengine %s is based on nginx %s, older than %s", v, core, c.Introduced)
	}
	if Cmp(v, TengineNewest) <= 0 {
		if core == nil {
			return Unknown, fmt.Sprintf("Tengine %s: its nginx core could not be read", v)
		}
		return Vulnerable, fmt.Sprintf("Tengine %s (nginx core %s) carries the unfixed HTTP/2 code; no Tengine release carries the fix (newest on %s: 3.2.0)", v, core, Checked)
	}
	return Unknown, fmt.Sprintf("Tengine %s is newer than the newest release known on %s (3.2.0); whether it carries the fix is not known", v, Checked)
}

// Angie judges an Angie release. Angie forked from nginx 1.23 (2022),
// after both flaws were in the code.
func Angie(c CVE, v V) (Status, string) {
	if Cmp(v, AngieNewest) <= 0 {
		return Vulnerable, fmt.Sprintf("Angie %s carries the unfixed HTTP/2 code; no Angie release carries the fix (newest on %s: 1.12.4)", v, Checked)
	}
	return Unknown, fmt.Sprintf("Angie %s is newer than the newest release known on %s (1.12.4); whether it carries the fix is not known", v, Checked)
}

// Plus judges NGINX Plus by its own release: "r33", "r33-p2" or a numbered
// release such as "37.0.7.1". core is the nginx version in the same
// binary, used for releases F5 does not list.
func Plus(c CVE, rel string, core V) (Status, string) {
	if v, err := ParseV(rel); err == nil && len(v) == 4 {
		if v[0] < 37 {
			return Unknown, fmt.Sprintf("NGINX Plus %s: a numbered release before 37 is not known", v)
		}
		st, why := lines(v, c.PlusFixed, allFixed(true))
		return st, "NGINX Plus " + why
	}
	r, p, ok := plusR(rel)
	if !ok {
		return Unknown, fmt.Sprintf("NGINX Plus release %q could not be read", rel)
	}
	switch {
	case r >= 37:
		return Unknown, fmt.Sprintf("NGINX Plus R%d%s: how R%d patch releases map to the fixed releases (%s) is not known", r, p, r, plusFixedText(c))
	case r >= c.PlusFrom:
		return Vulnerable, fmt.Sprintf("NGINX Plus R%d%s is affected (F5 lists R%d and later; fixed in %s)", r, p, c.PlusFrom, plusFixedText(c))
	case core != nil:
		st, why := Nginx(c, core)
		return st, fmt.Sprintf("NGINX Plus R%d%s is not listed by F5 (end of life); judged by its nginx core: %s", r, p, why)
	}
	return Unknown, fmt.Sprintf("NGINX Plus R%d%s is not listed by F5 and its nginx core could not be read", r, p)
}

func plusFixedText(c CVE) string {
	s := make([]string, len(c.PlusFixed))
	for i, v := range c.PlusFixed {
		s[i] = v.String()
	}
	return strings.Join(s, " and ")
}

// plusR reads "r33" or "r33-p2".
func plusR(s string) (int, string, bool) {
	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "r") {
		return 0, "", false
	}
	num, patch, _ := strings.Cut(s[1:], "-")
	n, err := strconv.Atoi(num)
	if err != nil || n <= 0 || n > 999 || len(num) > 3 {
		return 0, "", false
	}
	if patch != "" {
		if !strings.HasPrefix(patch, "p") {
			return 0, "", false
		}
		if _, err := strconv.Atoi(patch[1:]); err != nil || len(patch) > 4 {
			return 0, "", false
		}
		patch = "-" + patch
	}
	return n, patch, true
}

// UpstreamOf reads the upstream nginx version from a package version:
// "1:1.22.1-9+deb12u10" (Debian), "1.30.6-r0" (Alpine), "1.31.8-1~trixie"
// (nginx.org), "1.24.0-4.module+el9.4.0+21950+8ebc21e1" (Red Hat).
func UpstreamOf(pkg string) (V, error) {
	if _, after, ok := strings.Cut(pkg, ":"); ok {
		pkg = after
	}
	up, _, _ := strings.Cut(pkg, "-")
	return ParseV(up)
}
