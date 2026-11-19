package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// GraalVM: Oracle's Critical Security Patch Update of November 2026 names
// Oracle GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3 and GraalVM Enterprise
// Edition 21.3.20.0.3 as affected. A GraalVM JDK is HotSpot with JVMCI, so
// its VM library has the same decoder; its version line is the JDK's with
// "-jvmci-" in it (17.0.6+10-jvmci-22.3-b13). Oracle's and the GraalVM
// project's fixed builds are numbered their own way, so a GraalVM build is
// judged fixed only at a fixed GraalVM build listed here. FACTS.md gives
// the sources.

// Build is a release and the first build of it that has the fix.
type Build struct {
	Version []int
	Build   int // -1: every build of Version
}

// GraalVM distributions, whose fixed builds are published separately.
const (
	GraalVMOracle    = "oracle"    // Oracle GraalVM (and GraalVM Enterprise)
	GraalVMCommunity = "community" // GraalVM Community Edition
)

// GraalVMKey is a distribution's Java line.
type GraalVMKey struct {
	Dist    string
	Feature int
}

// GraalVMFixed is, per distribution and Java line, the first GraalVM build
// with the fix. Empty: no fixed GraalVM build had been published as of
// Checked.
var GraalVMFixed = map[GraalVMKey]Build{}

// GraalVMDist names the distribution a release file's IMPLEMENTOR names,
// "" when it names neither.
func GraalVMDist(implementor string) string {
	switch implementor {
	case "GraalVM Community":
		return GraalVMCommunity
	case "Oracle Corporation":
		return GraalVMOracle
	}
	return ""
}

// graalVMAffected names what Oracle lists, for reasons.
const graalVMAffected = "Oracle names GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3 and GraalVM Enterprise Edition 21.3.20.0.3 as affected"

// IsGraalVM reports a GraalVM version string: the JDK version with JVMCI
// ("17.0.6+10-jvmci-22.3-b13", "21.0.5+9-LTS-jvmci-23.1-b48").
func IsGraalVM(version string) bool { return strings.Contains(version, "-jvmci-") }

// JudgeGraalVM judges a GraalVM build of a distribution (GraalVMOracle,
// GraalVMCommunity, "" when not known) by its JDK version. It is
// vulnerable wherever the OpenJDK release would be; it is fixed only at or
// past a fixed build of the same distribution listed in GraalVMFixed.
func JudgeGraalVM(v Version, dist string) (Status, string) {
	st, why := Judge(v)
	switch st {
	case NotAffected:
		return st, why
	case Vulnerable:
		return st, "GraalVM: " + why + "; " + graalVMAffected
	}
	// A row clears only what OpenJDK's data also judges fixed: a vendor
	// build number in the fourth place or a later update stays unknown.
	if fx, ok := GraalVMFixed[GraalVMKey{dist, v.Feature()}]; ok && dist != "" && st == Fixed {
		c := Compare(v.Nums, fx.Version)
		// A version without its build is taken as the GA build, as for OpenJDK.
		if c < 0 || c == 0 && fx.Build >= 0 && v.Build >= 0 && v.Build < fx.Build {
			return Vulnerable, fmt.Sprintf("GraalVM build of Java %s, older than the first fixed GraalVM build (%s)", v, buildName(fx))
		}
		return Fixed, fmt.Sprintf("GraalVM build of Java %s, at or past the first fixed GraalVM build (%s)", v, buildName(fx))
	}
	return Unknown, fmt.Sprintf("GraalVM build of Java %s: %s, and no fixed GraalVM build had been published as of %s, so its OpenJDK version does not show whether it has the fix (%s)", v, graalVMAffected, Checked, BugRef)
}

func buildName(b Build) string {
	if b.Build < 0 {
		return join(b.Version)
	}
	return fmt.Sprintf("%s+%d", join(b.Version), b.Build)
}

// JudgeBackportGraalVM judges a GraalVM build of a line without the
// decoder (Java 8 or 11) whose VM library carries it anyway.
func JudgeBackportGraalVM(v Version) (Status, string) {
	return Vulnerable, fmt.Sprintf("GraalVM build of Java %s whose VM library carries the AVX-512 VBMI Base64 decoder: %s, and no fixed GraalVM build had been published as of %s", v, graalVMAffected, Checked)
}

// GraalVM releases numbered the GraalVM way (22.3.1 for Java 17), as
// version managers name them (sdkman 22.3.1.r17-grl, asdf
// graalvm-22.3.1+java17): which JDK update they are built on, read from
// the releases themselves (FACTS.md).
var (
	// graalVM17Without is the last GraalVM release for Java 17 built on an
	// update without the decoder (22.3.0: 17.0.5); graalVM17With the first
	// built on one with it (22.3.1: 17.0.6). Later GraalVM releases are
	// built on later updates.
	graalVM17Without = []int{22, 3, 0}
	graalVM17With    = []int{22, 3, 1}
)

// GraalVMOwnNumber reports a version in GraalVM's own numbers (22.3.1,
// 23.1.2, GraalVM Community's 25.1.3 for JDK 25.0.3 and 25.5.5.0.3 for JDK
// 25.0.5.0.3) rather than a Java version: Java's second number has been 0
// since JDK 10.
func GraalVMOwnNumber(s string) bool {
	v, ok := Parse(s)
	return ok && NotJava(v.Nums)
}

// NotJava reports numbers that are not a Java version: since JDK 10 the
// second number (the interim release) has always been 0.
func NotJava(nums []int) bool { return len(nums) >= 2 && nums[0] >= 10 && nums[1] != 0 }

// NotJavaWhy says why a version is not judged.
func NotJavaWhy(v string) string {
	return fmt.Sprintf("%s is not a Java version: Java's second number has been 0 since JDK 10 (GraalVM Community's own release numbers, such as 25.5.5.0.3 for JDK 25.0.5.0.3, look like this), so which Java update it names is not known", v)
}

// graalRelease is a well-formed GraalVM release number: two to four
// numbers without leading zeros.
var graalRelease = regexp.MustCompile(`^(?:0|[1-9]\d?)\.(?:0|[1-9]\d?)(?:\.(?:0|[1-9]\d{0,2})){0,2}$`)

// JudgeGraalVMRelease judges a GraalVM release named by GraalVM's own
// number and the Java line it is built for. community is true for GraalVM
// Community's own names (sdkman grl and graalce, asdf graalvm): only those
// are cleared, since the releases checked are GraalVM Community's; the
// numbering of Liberica NIK, Mandrel and Oracle's builds is not checked.
func JudgeGraalVMRelease(graal string, java int, community bool) (Status, string) {
	name := fmt.Sprintf("GraalVM %s for Java %d", graal, java)
	if !graalRelease.MatchString(graal) {
		return Unknown, fmt.Sprintf("%s: the GraalVM version could not be read", name)
	}
	var nums []int
	for _, p := range strings.Split(graal, ".") {
		n, _ := strconv.Atoi(p)
		nums = append(nums, n)
	}
	is213 := Compare(nums[:2], []int{21, 3}) == 0
	// The GraalVM releases looked at are 19.x to 22.3 (minor versions 0
	// to 3); later ones are numbered by the JDK.
	looked := nums[0] >= 19 && nums[0] <= 22 && nums[1] <= 3
	switch {
	case java < 8:
		return Unknown, fmt.Sprintf("%s: not a Java line GraalVM is built for", name)
	case java < firstVBMIDecode && community && looked && !is213:
		return NotAffected, fmt.Sprintf("%s is built on OpenJDK %d, which has no x86-64 Base64 decode intrinsic (the Java 11 build of GraalVM Community 22.3.1 carries no decoder stubs)", name, java)
	case java < firstVBMIDecode:
		return Unknown, fmt.Sprintf("%s: OpenJDK %d has no decoder, but whether this build carries one is not known (GraalVM Enterprise Edition 21.3.20.0.3 is listed as affected without its Java line, and other vendors' GraalVM builds were not checked)", name, java)
	case java >= newestFeature:
		return Unknown, fmt.Sprintf("%s: Java %d is newer than this detector's release data (%s)", name, java, Checked)
	case java > firstVBMIDecode:
		// Every release of Java 18 and later has the decoder.
		return Vulnerable, fmt.Sprintf("%s: every Java %d release has the AVX-512 VBMI Base64 decoder; %s, and no fixed GraalVM build had been published as of %s", name, java, graalVMAffected, Checked)
	}
	if community && len(nums) == 3 && Compare(nums, graalVM17Without) == 0 {
		return NotAffected, fmt.Sprintf("%s is built on Java 17.0.5, which predates the AVX-512 VBMI Base64 decoder (17.0.6)", name)
	}
	if len(nums) >= 3 && Compare(nums, graalVM17With) >= 0 || len(nums) >= 2 && Compare(nums[:2], []int{22, 3}) > 0 {
		return Vulnerable, fmt.Sprintf("%s is built on Java 17.0.6 or later (GraalVM 22.3.1 is 17.0.6), which has the AVX-512 VBMI Base64 decoder; %s, and no fixed GraalVM build had been published as of %s", name, graalVMAffected, Checked)
	}
	return Unknown, fmt.Sprintf("%s: GraalVM Community 22.3.0 is built on Java 17.0.5 (before the decoder) and 22.3.1 and later on 17.0.6 and later (with it); which Java 17 update this release is built on is not known", name)
}
