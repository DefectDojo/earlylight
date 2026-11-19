package repo

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// redHatImage is a Red Hat OpenJDK image: registry.access.redhat.com/ubi9/openjdk-21,
// ubi8/openjdk-17-runtime, openjdk/openjdk-11-rhel7, on registry.redhat.io too.
// Its tags name the image's release (1.20, 1.20-2.1729089285), not the
// Java update.
var rhSource = regexp.MustCompile(`^(java-\d{1,2}-openjdk)`)

var redHatImage = regexp.MustCompile(`^(?:registry\.access\.redhat\.com|registry\.redhat\.io)/(?:ubi(\d{1,2})|openjdk)/openjdk-(\d{1,2})(?:-runtime)?(?:-rhel(\d{1,2}))?$`)

// redHatRef judges a Red Hat OpenJDK image by the Red Hat backport table.
// ok is false for an image that is not one.
func (s *scanner) redHatRef(r refs.Ref, img string, props map[string]string, mit string) bool {
	repo, tag := repoName(img)
	m := redHatImage.FindStringSubmatch(repo)
	if m == nil {
		return false
	}
	feature, el := atoi(m[2]), m[1]+m[3]
	if feature == 8 || feature == 11 {
		// Red Hat's Java 8 and 11 builds: OpenJDK 8 and 11 have no decode
		// intrinsic (skipped by name, as eclipse-temurin:11 is; FACTS.md).
		return true
	}
	props["vendor"] = "Red Hat"
	pkg := fmt.Sprintf("java-%d-openjdk", feature)
	pull := func(why string) {
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r, Props: props,
			Reason: why, Message: fmt.Sprintf("image %s: %s", img, why)})
	}
	if !redHatLines[feature] {
		pull(fmt.Sprintf("Red Hat's OpenJDK %d images are not in this detector's release data: only the image can show which Java it holds", feature))
		return true
	}
	if fx, ok := redHatRowFor(pkg, el); ok {
		pull(fmt.Sprintf("Red Hat published %s %s (%s); whether this image has it, only the image can show: its tag names the image's release, not the Java update", pkg, fx.EVR, fx.Advisory))
		return true
	}
	moving := tag == "" && !strings.Contains(img, "@") || tag == "latest"
	if feature == 17 && !moving {
		pull(fmt.Sprintf("the tag names the image's release, not the Java update: Java 17 images built before 17.0.6 do not have the decoder, and none has the fix (%s)", knowledge.RedHatStatus()))
		return true
	}
	why := fmt.Sprintf("every Java %d release has the AVX-512 VBMI Base64 decoder, and %s, so every image Red Hat had published lacks the fix", feature, knowledge.RedHatStatus())
	if feature == 17 {
		why = fmt.Sprintf("the newest image carries a Java 17 update at or after 17.0.6, which brought the decoder, and %s", knowledge.RedHatStatus())
	}
	f := Finding{Rule: RuleImagePin, File: r.File, Line: r.Line, Level: "error", Status: StatusVulnerable, Reason: why, ref: &r, Props: props,
		Message: fmt.Sprintf("image %s holds Red Hat's OpenJDK %d, without the Java4Shell fix", img, feature),
		Fix: fmt.Sprintf("Rebuild on a %s image with Red Hat's fixed %s once Red Hat publishes it (it had not %s), and redeploy. Until then set JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics for the container.",
			repo, pkg, knowledge.AsOf())}
	if l, ok := knowledge.LineOf(feature); ok && l.Fixed == nil {
		f.Fix = fmt.Sprintf("Java %d received no fix: move to a Red Hat image of a supported release with the fix, such as %s.", feature, knowledge.Upgrade(feature))
	}
	if mit != "" {
		f.Status, f.Reason = StatusMitigated, why+"; "+mit
		f.Message += ", mitigated by its JVM options until it is updated"
	}
	s.add(f)
	return true
}

// redHatLines are the Java lines of Red Hat's OpenJDK images this
// detector judges by name: the lines Red Hat ships with the decoder.
var redHatLines = map[int]bool{17: true, 21: true, 25: true}

// redHatRowFor returns a table row for a package in any stream of a RHEL
// major release ("9" matches el9, el9_6...); el "" (openjdk/openjdk-11-rhel7
// has a release) matches any.
func redHatRowFor(pkg, el string) (knowledge.RedHatFix, bool) {
	for _, f := range knowledge.RedHatFixed {
		if f.Package != pkg {
			continue
		}
		if d := strings.TrimPrefix(f.Dist, "el"); el == "" || d == el || strings.HasPrefix(d, el+"_") {
			return f, true
		}
	}
	return knowledge.RedHatFix{}, false
}

// redHatPin judges a pinned rpm of Red Hat's OpenJDK
// (java-17-openjdk-headless-17.0.21.0.9-1.el9) by the backport table. ok is
// false when the table does not decide it.
func redHatPin(h pkgHit) (st knowledge.Status, why string, ok bool) {
	if h.mgr != "rpm" || h.vendor != "distribution" || h.ver == "" {
		return "", "", false
	}
	return knowledge.JudgeRedHat(h.name, h.ver)
}

// redHatPublished reports whether Red Hat had published a fixed build of a
// package on any RHEL release, and names it.
func redHatPublished(name string) (string, bool) {
	m := rhSource.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	var out []string
	for _, f := range knowledge.RedHatFixed {
		if f.Package == m[1] {
			out = append(out, fmt.Sprintf("%s for %s (%s)", f.EVR, f.Dist, f.Advisory))
		}
	}
	return strings.Join(out, ", "), len(out) > 0
}

// rpmFix is what to do about an rpm of OpenJDK without the fix. Red Hat
// backports fixes, so its fixed build may keep the upstream version.
func rpmFix(name string) string {
	return fmt.Sprintf("Rebuild once Red Hat (or your rpm distribution) publishes a fixed %s and check the installed build: Red Hat backports fixes, so its fixed build may keep the upstream version and differ only in the rpm release. Until then set ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in this stage.", name)
}
