// Package knowledge holds what is known about Java4Shell (CVE-2026-114938)
// release by release, and judges a Java version against it. FACTS.md, next
// to the detector, gives the source of every number here.
package knowledge

import (
	"fmt"
	"strconv"
	"strings"
)

// CVE is the vulnerability this detector checks.
const CVE = "CVE-2026-114938"

// Bug is the OpenJDK change taken as the fix. The mapping is inferred: the
// OpenJDK advisory confirms the component (hotspot/compiler), the lines (17,
// 21, 25, 27) and the last affected releases but names no JDK bug, and the
// public descriptions of the CVE match this change (FACTS.md).
const Bug = "JDK-8393212"

// BugRef is how reasons name the fix.
const BugRef = "JDK-8393212, inferred to be this CVE's fix"

// Checked is the date the release data was last checked: every "as of"
// statement (a vendor or distribution had not published a fix) is as of
// this date.
const Checked = "2026-11-18"

// Dates the release data rests on.
const (
	// Disclosed is when the CVE and the fixed releases were published.
	Disclosed = "2026-11-17"
	// FixReleased is the date of the OpenJDK update releases with the fix.
	FixReleased = "2026-11-15"
	// MainlineFixed is when the fix reached OpenJDK mainline.
	MainlineFixed = "2026-11-16"
	// VendorFixPublished is when Amazon Corretto and SapMachine published
	// their fixed releases.
	VendorFixPublished = "2026-11-17"
)

// The advisories that name the affected releases (read by the lead on
// 2026-11-17/18; FACTS.md).
const (
	OpenJDKAdvisory = "https://openjdk.org/groups/vulnerability/advisories/2026-11-17"
	OracleAdvisory  = "https://www.oracle.com/security-alerts/cspunov2026.html"
)

// CVSS is the score OpenJDK and Oracle give (CVSS 3.1
// AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H). Calif scores it 9.2 and Red Hat
// 9.8 (FACTS.md).
const CVSS = "8.1"

// Vendor status as of Checked, for fix texts.
const (
	// VendorsFixed published fixed releases.
	VendorsFixed = "Amazon Corretto and SapMachine"
	// VendorsNotFixed had published none.
	VendorsNotFixed = "Temurin, Microsoft, Debian, Ubuntu, Alpine and Red Hat"
	// VendorsNotChecked could not be checked.
	VendorsNotChecked = "Azul and BellSoft Liberica"
)

// VendorStatus says who had published a fixed release, in words.
func VendorStatus() string {
	return VendorsFixed + " published theirs on " + VendorFixPublished + "; " + VendorsNotFixed + " had not " + AsOf() + "; " + VendorsNotChecked + " were not checked"
}

// AsOf says a status statement's date.
func AsOf() string { return "as of " + Checked + ", the date of this detector's release data" }

// Status is what the release data says about a version.
type Status string

const (
	// Vulnerable: a release with the AVX-512 VBMI decode path and without the fix.
	Vulnerable Status = "vulnerable"
	// Fixed: a release with the fix.
	Fixed Status = "fixed"
	// NotAffected: a release without the vulnerable code.
	NotAffected Status = "not-affected"
	// Unknown: the release data does not settle it.
	Unknown Status = "unknown"
)

// Version is a Java version as the runtime reports it: its numbers
// (feature, interim, update, patch and any vendor numbers), the build number
// after "+" and whether it is an early-access build.
type Version struct {
	Nums  []int
	Build int  // -1 when absent
	EA    bool // a pre-release or self-built JDK: -ea, -beta, -internal, adhoc
	// SelfBuilt is a JDK built from source (-internal, adhoc): its build
	// number is not the release's, so it cannot place it before or after a
	// build boundary.
	SelfBuilt bool
	Raw       string
}

// Feature is the major release (8, 11, 17...).
func (v Version) Feature() int {
	if len(v.Nums) == 0 {
		return 0
	}
	return v.Nums[0]
}

// String is the dotted version without the build.
func (v Version) String() string { return join(v.Nums) }

func join(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

const maxVersionLen = 120

// Parse reads the version strings Java runtimes report: "17.0.21.1+2-LTS",
// "21.0.13.0.3+1", "17.0.21+9-1-deb12u1-Debian", "1.8.0_452-b09",
// "28-ea+24", "25.0.5". A string that does not start with a version is
// refused.
func Parse(s string) (Version, bool) {
	v := Version{Build: -1, Raw: s}
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxVersionLen {
		return v, false
	}
	// Java 8 and older: 1.8.0_452-b09.
	if rest, ok := strings.CutPrefix(s, "1."); ok {
		feat, rest2 := leadingInt(rest)
		if feat < 2 || feat > 8 || !strings.HasPrefix(rest2, ".0") {
			return v, false
		}
		v.Nums = []int{feat, 0}
		rest2 = strings.TrimPrefix(rest2, ".0")
		if r, ok := strings.CutPrefix(rest2, "_"); ok {
			u, r2 := leadingInt(r)
			if u < 0 {
				return v, false
			}
			v.Nums = append(v.Nums, u)
			rest2 = r2
		}
		if i := strings.Index(rest2, "-b"); i >= 0 {
			if b, _ := leadingInt(rest2[i+2:]); b >= 0 {
				v.Build = b
			}
		}
		v.EA = strings.Contains(rest2, "-ea")
		return v, true
	}
	rest := s
	for {
		n, r := leadingInt(rest)
		if n < 0 {
			break
		}
		v.Nums = append(v.Nums, n)
		rest = r
		if len(v.Nums) > 8 {
			return v, false
		}
		if !strings.HasPrefix(rest, ".") {
			break
		}
		rest = rest[1:]
	}
	if len(v.Nums) == 0 || v.Nums[0] < 9 || v.Nums[0] > 99 {
		return v, false
	}
	// A pre-release identifier ("-ea", "-internal") comes before the build.
	if r, ok := strings.CutPrefix(rest, "-"); ok {
		pre := r
		rest = ""
		if i := strings.IndexByte(r, '+'); i >= 0 {
			pre, rest = r[:i], r[i:]
		}
		switch {
		case pre == "", strings.EqualFold(pre, "LTS"), pre[0] >= '0' && pre[0] <= '9':
			// A vendor suffix (21.0.13.1-LTS) or an rpm release
			// (21.0.13.1.2-1.el9), not a pre-release.
		case strings.HasPrefix(pre, "internal"):
			v.EA, v.SelfBuilt = true, true
		default:
			v.EA = true // ea, beta, rc, a build date
		}
	}
	if r, ok := strings.CutPrefix(rest, "+"); ok {
		if b, _ := leadingInt(r); b >= 0 {
			v.Build = b
		}
		// A self-built JDK ("+0-adhoc.root.jdk17u") is not a release.
		if strings.Contains(r, "adhoc") {
			v.EA, v.SelfBuilt = true, true
		}
	}
	return v, true
}

func leadingInt(s string) (int, string) {
	i := 0
	for i < len(s) && i < 9 && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return -1, s
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return -1, s
	}
	return n, s[i:]
}

// Compare compares two dotted versions, missing numbers counting as zero.
func Compare(a, b []int) int {
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

// Line is one Java feature release line.
type Line struct {
	Feature int
	// Introduced is the first version with the AVX-512 VBMI decode path
	// (nil: the whole line has it).
	Introduced []int
	// IntroducedBuild is the first build of Introduced that has it (17.0.6+3).
	IntroducedBuild int
	// Fixed is the first release with the fix (nil: none), and FixedBuild
	// the first build of it that has the fix: earlier builds of the same
	// release (17.0.21.1+0 and +1) do not.
	Fixed      []int
	FixedBuild int
	// Note is why the line has no fix, or other context.
	Note string
}

// Lines is the release data, newest last. FACTS.md gives the sources.
var Lines = []Line{
	{Feature: 17, Introduced: []int{17, 0, 6}, IntroducedBuild: 3, Fixed: []int{17, 0, 21, 1}, FixedBuild: 2},
	{Feature: 18, Note: "JDK 18 is end of life and received no fix"},
	{Feature: 19, Note: "JDK 19 is end of life and received no fix"},
	{Feature: 20, Note: "JDK 20 is end of life and received no fix"},
	{Feature: 21, Fixed: []int{21, 0, 13, 1}, FixedBuild: 2},
	{Feature: 22, Note: "JDK 22 is end of life and received no fix"},
	{Feature: 23, Note: "JDK 23 is end of life and received no fix"},
	{Feature: 24, Note: "JDK 24 is end of life and received no fix"},
	{Feature: 25, Fixed: []int{25, 0, 5, 1}, FixedBuild: 2},
	{Feature: 26, Note: "JDK 26 is end of life (last release 26.0.2.1) and received no fix"},
	{Feature: 27, Fixed: []int{27, 0, 1, 1}, FixedBuild: 4},
}

// EAFeature is the line in early access, and the last EA build known to
// lack the fix (the fix reached mainline after jdk-28+24).
const (
	EAFeature       = 28
	EALastUnfixed   = 24
	newestFeature   = 28
	firstVBMIDecode = 17
)

// maxPatch is the largest fourth version number taken as an OpenJDK patch
// release.
const maxPatch = 3

// Backports are lines whose OpenJDK releases do not have the decoder but
// whose vendor builds do: the last update known to carry the decoder
// without the fix. Oracle names Java SE 8u511b33-perf (its Performance
// Pack build of Java 8) as affected; no fixed 8u-perf build is known.
var Backports = map[int][]int{8: {8, 0, 511}}

// JudgeBackport judges a runtime of a line without the decoder whose VM
// library carries it anyway (a vendor backport such as Oracle's Java 8
// Performance Pack).
func JudgeBackport(v Version) (Status, string) {
	last, ok := Backports[v.Feature()]
	if ok && Compare(v.Nums, last) <= 0 {
		return Vulnerable, fmt.Sprintf("Java %s carries the AVX-512 VBMI Base64 decoder as a vendor backport (Oracle names Java SE 8u511b33-perf as affected), and no fixed build of it was known on %s", v, Checked)
	}
	return Unknown, fmt.Sprintf("Java %s should predate the AVX-512 VBMI Base64 decoder, but this VM library carries its stubs: a vendor backport, and whether it has the fix is not known", v)
}

// LineOf returns the release line of a feature release.
func LineOf(feature int) (Line, bool) {
	for _, l := range Lines {
		if l.Feature == feature {
			return l, true
		}
	}
	return Line{}, false
}

// FixedVersion is the first fixed release of a line, "" when it has none.
func FixedVersion(feature int) string {
	if l, ok := LineOf(feature); ok && l.Fixed != nil {
		return join(l.Fixed)
	}
	return ""
}

// Upgrade names the releases to move to from a line without a fix.
func Upgrade(feature int) string {
	switch {
	case feature <= 21:
		return "21.0.13.1 (or 25.0.5.1)"
	case feature <= 25:
		return "25.0.5.1 (or 27.0.1.1)"
	}
	return "27.0.1.1 (or 25.0.5.1, a long-term support release)"
}

// Judge says what the release data shows about a HotSpot runtime of version
// v on x86-64, with the reason in words.
func Judge(v Version) (Status, string) {
	f := v.Feature()
	ver := v.String()
	switch {
	case f == 0:
		return Unknown, "the version could not be read"
	case f < firstVBMIDecode:
		return NotAffected, fmt.Sprintf("Java %s: OpenJDK %d has no x86-64 Base64 decode intrinsic, so it does not have the vulnerable AVX-512 code", ver, f)
	case f == EAFeature && len(v.Nums) > 1:
		return Unknown, fmt.Sprintf("Java %s is an update of JDK %d, which had no release when this detector's data was checked (%s)", ver, f, Checked)
	case f == EAFeature:
		if v.Build >= 0 && v.Build <= EALastUnfixed {
			return Vulnerable, fmt.Sprintf("JDK %d build %d: the fix reached mainline after jdk-28+%d", f, v.Build, EALastUnfixed)
		}
		return Unknown, fmt.Sprintf("JDK %d build %s: the fix reached mainline on %s, after jdk-28+%d; check that this build includes %s", f, buildText(v), MainlineFixed, EALastUnfixed, BugRef)
	case f > newestFeature:
		return Unknown, fmt.Sprintf("Java %s is newer than this detector's release data (%s)", ver, Checked)
	}
	l, ok := LineOf(f)
	if !ok {
		return Unknown, fmt.Sprintf("Java %s is not in this detector's release data", ver)
	}
	// After a patch number (the fourth, small), a fifth number is a build:
	// 17.0.21.1.1 is 17.0.21.1 build 1 (Corretto, SapMachine and Red Hat
	// write it so), which can predate the fix of 17.0.21.1.
	if len(v.Nums) >= 5 && v.Nums[3] <= maxPatch {
		if len(v.Nums) > 5 {
			return Unknown, fmt.Sprintf("Java %s has more numbers than a Java version and a build: what it names is not known", ver)
		}
		if v.Build < 0 {
			v.Build = v.Nums[4]
		}
		v.Nums = v.Nums[:4]
	}
	if l.Introduced != nil {
		c := Compare(v.Nums, l.Introduced)
		if c == 0 && v.SelfBuilt {
			return Unknown, fmt.Sprintf("Java %s is a self-built JDK of %s, the update the decoder came in with (build %d): its build number does not show whether it has it", ver, join(l.Introduced), l.IntroducedBuild)
		}
		if c < 0 || c == 0 && v.EA && v.Build >= 0 && v.Build < l.IntroducedBuild {
			return NotAffected, fmt.Sprintf("Java %s predates %s, the first %d update with the AVX-512 VBMI Base64 decoder (8268276)", ver, join(l.Introduced), f)
		}
	}
	if l.Fixed == nil {
		return Vulnerable, fmt.Sprintf("Java %s has the AVX-512 VBMI Base64 decoder without the fix: %s", ver, l.Note)
	}
	// The update first (17.0.21 of 17.0.21.1): older is unfixed whatever
	// follows it.
	upd := v.Nums[:min(3, len(v.Nums))]
	switch c := Compare(upd, l.Fixed[:3]); {
	case c < 0:
		return Vulnerable, fmt.Sprintf("Java %s is older than %s, the first %d release with the fix (%s)", ver, join(l.Fixed), f, BugRef)
	case c > 0:
		// A later update (17.0.22) was not released when the data was
		// checked, and its development builds did not have the fix yet.
		return Unknown, fmt.Sprintf("Java %s is a later update than %s; it was not released when this detector's data was checked (%s), and the %d update repository did not have %s yet: check its release notes", ver, join(l.Fixed), Checked, f, BugRef)
	}
	if len(v.Nums) >= 4 && v.Nums[3] > maxPatch {
		// OpenJDK patch numbers are small (17.0.8.1, 21.0.13.1); a larger
		// fourth number is a vendor's build number (Amazon Corretto's
		// 21.0.13.11), which says nothing about the patch.
		return Unknown, fmt.Sprintf("Java %s: the fourth number looks like a vendor build number, not an OpenJDK patch release, so the version does not show whether it has the fix (%s)", ver, BugRef)
	}
	switch c := Compare(v.Nums, l.Fixed); {
	case c < 0:
		return Vulnerable, fmt.Sprintf("Java %s is older than %s, the first %d release with the fix (%s)", ver, join(l.Fixed), f, BugRef)
	case c == 0 && v.SelfBuilt:
		return Unknown, fmt.Sprintf("Java %s is a self-built JDK of %s, the release the fix reached in build %d: its build number does not show whether its source had the fix (%s)", ver, join(l.Fixed), l.FixedBuild, BugRef)
	case c == 0 && v.Build >= 0 && v.Build < l.FixedBuild:
		return Vulnerable, fmt.Sprintf("Java %s build %d predates the fix: it reached %s in build %d (%s)", ver, v.Build, join(l.Fixed), l.FixedBuild, BugRef)
	}
	if v.EA {
		return Unknown, fmt.Sprintf("Java %s is a pre-release or self-built JDK; check that it includes %s", ver, BugRef)
	}
	return Fixed, fmt.Sprintf("Java %s is at or past %s, the first %d release with the fix (%s)", ver, join(l.Fixed), f, BugRef)
}

func buildText(v Version) string {
	if v.Build < 0 {
		return "(no build number)"
	}
	return strconv.Itoa(v.Build)
}
