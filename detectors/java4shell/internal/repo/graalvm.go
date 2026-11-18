package repo

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// graalVendors are the version-manager names of GraalVM distributions:
// GraalVM itself and the native-image kits built on it (Liberica NIK,
// Mandrel), whose JDK is HotSpot with the same decoder.
var graalVendors = map[string]bool{"grl": true, "graal": true, "graalce": true, "nik": true, "mandrel": true,
	"graalvm": true, "graalvm-community": true, "oracle-graalvm": true,
	"GraalVM CE": true, "Oracle GraalVM": true, "Liberica NIK": true, "Mandrel": true}

func isGraal(vendor string) bool { return graalVendors[vendor] }

// graalDist is the GraalVM distribution a vendor name or family names,
// for its fixed builds; "" for NIK, Mandrel and unknown names.
func graalDist(vendor string) string {
	switch vendor {
	case "graal", "oracle-graalvm", "Oracle GraalVM":
		return knowledge.GraalVMOracle
	case "graalce", "grl", "graalvm", "graalvm-community", "GraalVM CE", "GraalVM Community":
		return knowledge.GraalVMCommunity
	}
	return ""
}

// graalRelease is a GraalVM release in GraalVM's own numbers with the Java
// line it is for: sdkman 22.3.1.r17, asdf graalvm-22.3.1+java17, mandrel
// 22.3.1.0-Final+java17.
var (
	sdkmanGraal = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,9}){1,4})\.r([1-9]\d?)$`)
	// javaLine ends the name: graalvm-22.3.0+java17.0.9 and
	// graalvm-22.3.0+java11+java17 are not read.
	javaLine = regexp.MustCompile(`[+-]java([1-9]\d?)$`)
)

// graalTag judges a GraalVM image tag: vulnerable where the OpenJDK
// release would be, and otherwise unknown until a fixed GraalVM build is
// known (the image has to be read).
func graalTag(tv TagVersion, st knowledge.Status, why, dist string) (knowledge.Status, string) {
	if knowledge.GraalVMOwnNumber(tv.Text) {
		return knowledge.Unknown, ownNumberWhy(tv.Text)
	}
	switch st {
	case knowledge.Vulnerable:
		return st, "GraalVM: " + why
	case knowledge.NotAffected:
		return st, why
	}
	if tv.Exact || len(tv.Nums) >= 3 {
		// No fixed GraalVM build is known, so the newest release a tag
		// such as 21.0.13 names is not fixed either.
		gs, gwhy := knowledge.JudgeGraalVM(knowledge.Version{Nums: tv.Nums, Build: tv.OpenJDKBuild}, dist)
		return gs, "the tag names Java " + tv.Text + ": " + gwhy
	}
	return knowledge.Unknown, why
}

// ownNumberWhy says why a GraalVM release in GraalVM's own numbers is not
// judged as a Java version.
func ownNumberWhy(v string) string {
	return fmt.Sprintf("%s is in GraalVM's own version numbers, not a Java version (GraalVM Community 25.1.3 is JDK 25.0.3, 25.5.5.0.3 is JDK 25.0.5.0.3): which Java update it is built on is not read from it", v)
}

// graalFix is what to do about a GraalVM release without the fix that
// where (a version file; "" for an image) selects.
func graalFix(feature int, where string) string {
	alt := "use a JDK release with the fix (17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1) from a vendor that has published one"
	if l, ok := knowledge.LineOf(feature); ok && l.Fixed == nil {
		alt = fmt.Sprintf("move to a supported Java release with the fix, such as %s (Java %d received none)", knowledge.Upgrade(feature), feature)
	}
	what := "Select a GraalVM release with the fix in " + where
	if where == "" {
		what = "Move to a GraalVM image with the fix"
	}
	return fmt.Sprintf("%s once Oracle or the GraalVM project publishes one (none had been as of %s), or %s. Until then run Java with -XX:-UseBASE64Intrinsics (for example JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics).", what, knowledge.Checked, alt)
}

// graalOwn judges a GraalVM release written in GraalVM's own numbers;
// value is the text as written.
// community is true for GraalVM Community's own names (sdkman grl and
// graalce, asdf graalvm).
func (s *scanner) graalOwn(rel string, line int, graal string, java int, community bool, value, source string) {
	st, why := knowledge.JudgeGraalVMRelease(graal, java, community)
	props := map[string]string{"source": source, "current": refs.CleanText(value, 80), "graalvm": graal}
	switch st {
	case knowledge.NotAffected:
		return
	case knowledge.Vulnerable:
		rule, level := RuleJavaPin, "warning"
		msg := fmt.Sprintf("%s selects %s (GraalVM %s for Java %d), without the Java4Shell fix", source, refs.CleanText(value, 80), graal, java)
		if l, ok := knowledge.LineOf(java); ok && l.Fixed == nil {
			rule, level = RuleLine, "error"
			msg = fmt.Sprintf("%s selects %s (GraalVM %s for Java %d), a line that received no Java4Shell fix", source, refs.CleanText(value, 80), graal, java)
		}
		s.add(Finding{Rule: rule, File: rel, Line: line, Level: level, Status: StatusVulnerable, Reason: why, Message: msg,
			Fix: graalFix(java, source), Props: props})
		return
	}
	s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Reason: why,
		Message: fmt.Sprintf("%s selects %s, written in GraalVM's own version numbers: not checked for the Java4Shell fix", source, refs.CleanText(value, 80)),
		Fix:     "Check which Java update this GraalVM release is built on; no fixed GraalVM build had been published as of " + knowledge.Checked + ".",
		Props:   props})
}

// graalVersion handles a GraalVM release named by its JDK version
// (sdkman 21.0.5-graal, asdf oracle-graalvm-21.0.5) once judgeVersion has
// judged it as a JDK (st, why). An exact version is judged as a GraalVM
// build of its distribution (dist): vulnerable where the JDK is, fixed only
// at a listed fixed build of that distribution, otherwise not checked. A
// moving version is vulnerable where the whole line is, else not checked.
func (s *scanner) graalVersion(rel string, line int, tv TagVersion, st knowledge.Status, why, source, dist string, props map[string]string) {
	verText := tv.Text
	if knowledge.GraalVMOwnNumber(verText) {
		s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Reason: ownNumberWhy(verText),
			Message: fmt.Sprintf("%s selects GraalVM %s, written in GraalVM's own version numbers: not checked for the Java4Shell fix", source, verText),
			Fix:     "Check which Java update this GraalVM release is built on; no fixed GraalVM build had been published as of " + knowledge.Checked + ".",
			Props:   props})
		return
	}
	if st == knowledge.NotAffected {
		return
	}
	gs, gwhy := st, why
	switch {
	case tv.Exact:
		gs, gwhy = knowledge.JudgeGraalVM(knowledge.Version{Nums: tv.Nums, Build: tv.OpenJDKBuild}, dist)
	case st == knowledge.Vulnerable:
		gwhy = "GraalVM: " + why
	default:
		gs, gwhy = knowledge.Unknown, fmt.Sprintf("the version names the newest GraalVM release of Java %s when it is installed, and no fixed GraalVM build had been published as of %s", verText, knowledge.Checked)
	}
	switch gs {
	case knowledge.Fixed, knowledge.NotAffected:
		return
	case knowledge.Vulnerable:
		rule, level := RuleJavaPin, "warning"
		msg := fmt.Sprintf("%s selects GraalVM for Java %s, without the Java4Shell fix", source, verText)
		if l, ok := knowledge.LineOf(tv.Nums[0]); ok && l.Fixed == nil && tv.Nums[0] > 17 {
			rule, level = RuleLine, "error"
			msg = fmt.Sprintf("%s selects GraalVM for Java %s, a line that received no Java4Shell fix", source, verText)
		}
		s.add(Finding{Rule: rule, File: rel, Line: line, Level: level, Status: StatusVulnerable, Reason: gwhy, Message: msg,
			Fix: graalFix(tv.Nums[0], source), Props: props})
		return
	}
	s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Reason: gwhy,
		Message: fmt.Sprintf("%s selects GraalVM for Java %s: not checked for the Java4Shell fix", source, verText),
		Fix:     "Check that this GraalVM release includes the fix; no fixed GraalVM build had been published as of " + knowledge.Checked + ".",
		Props:   props})
}

// graalNamed reads a GraalVM release in its own numbers from a version
// manager's name, with the Java line: ok is false when it names none.
func graalNamed(value string) (graal string, java int, ok bool) {
	if m := sdkmanGraal.FindStringSubmatch(value); m != nil {
		return m[1], atoi(m[2]), true
	}
	// asdf: graalvm-22.3.1+java17, mandrel-22.3.1.0-Final+java17. The
	// GraalVM number is everything between the name and the Java line, so
	// a malformed one (22.3.0-dev) stays malformed and is not judged.
	j := javaLine.FindStringSubmatchIndex(value)
	if j == nil {
		return "", 0, false
	}
	before := strings.TrimRight(value[:j[0]], "+-_")
	i := strings.IndexAny(before, "0123456789")
	if i < 0 {
		return "", 0, false
	}
	return strings.TrimSuffix(before[i:], "-Final"), atoi(value[j[2]:j[3]]), true
}
