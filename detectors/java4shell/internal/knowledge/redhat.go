package knowledge

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Red Hat backports security fixes into the OpenJDK update it ships, so a
// fixed Red Hat build can keep the upstream version (its VM library still
// reads 17.0.21+9) and only the rpm release moves. Its fixed builds are
// therefore listed by rpm version-release, per package and RHEL major
// release. FACTS.md gives the sources.

// RedHatFix is the first Red Hat build of an OpenJDK package with the fix
// on one RHEL major release.
type RedHatFix struct {
	Package  string // source package: java-17-openjdk
	EL       int    // RHEL major release: 8, 9, 10
	EVR      string // [epoch:]version-release: 1:17.0.21.0.9-2.el9_6
	Advisory string // RHSA-...
}

// RedHatFixed is empty: Red Hat's CVE page, read on Checked, lists the
// OpenJDK packages as affected and names no fixed build, erratum or UBI
// image ("exact upstream fixed version ... not yet confirmed by Oracle").
// An entry here marks that package's builds from EVR on as fixed, whatever
// their VM library's version line says.
var RedHatFixed = []RedHatFix{}

// RedHatStatus says what Red Hat had published, for reasons.
func RedHatStatus() string {
	if len(RedHatFixed) == 0 {
		return "Red Hat had published no fixed OpenJDK build " + AsOf() + " (its CVE page lists none)"
	}
	var parts []string
	for _, f := range RedHatFixed {
		parts = append(parts, fmt.Sprintf("%s %s on RHEL %d (%s)", f.Package, f.EVR, f.EL, f.Advisory))
	}
	return "Red Hat's fixed builds: " + strings.Join(parts, ", ")
}

var (
	elRelease  = regexp.MustCompile(`\.el(\d{1,2})(?:[._]|$)`)
	rhPackage  = regexp.MustCompile(`^(java-\d{1,2}-openjdk)(?:-(?:headless|devel|jmods|src|demo|javadoc|javadoc-zip|static-libs|fastdebug|slowdebug)\b.*)?$`)
	rpmVersion = regexp.MustCompile(`^(?:(\d+):)?([^-]+)(?:-(.+))?$`)
)

// RedHatPackage returns the source package and the RHEL major release of
// an rpm of Red Hat's OpenJDK: java-17-openjdk-headless with release
// 1.el9_6 is java-17-openjdk on RHEL 9. ok is false for other packages and
// for releases that are not Red Hat's (.fc41, .amzn2023).
func RedHatPackage(name, evr string) (pkg string, el int, ok bool) {
	m := rhPackage.FindStringSubmatch(name)
	if m == nil {
		return "", 0, false
	}
	e := elRelease.FindStringSubmatch(evr)
	if e == nil {
		return "", 0, false
	}
	n, _ := strconv.Atoi(e[1])
	return m[1], n, true
}

// RedHatFixFor returns the table's entry for a package on a RHEL release.
func RedHatFixFor(pkg string, el int) (RedHatFix, bool) {
	for _, f := range RedHatFixed {
		if f.Package == pkg && f.EL == el {
			return f, true
		}
	}
	return RedHatFix{}, false
}

// JudgeRedHat judges an rpm of Red Hat's OpenJDK (name and
// [epoch:]version-release) by the backport table. known is false when the
// table has no entry for its package and RHEL release: then only its
// upstream version can judge it.
func JudgeRedHat(name, evr string) (st Status, why string, known bool) {
	pkg, el, ok := RedHatPackage(name, evr)
	if !ok {
		return Unknown, "", false
	}
	fx, ok := RedHatFixFor(pkg, el)
	if !ok {
		return Unknown, "", false
	}
	a, b := evr, fx.EVR
	if !strings.Contains(a, ":") || !strings.Contains(b, ":") {
		// An install path or a package argument leaves the epoch out.
		a, b = stripEpoch(a), stripEpoch(b)
	}
	if CompareRPM(a, b) < 0 {
		return Vulnerable, fmt.Sprintf("Red Hat build %s-%s is older than %s, the first RHEL %d build with the fix (%s)", pkg, stripEpoch(evr), stripEpoch(fx.EVR), el, fx.Advisory), true
	}
	return Fixed, fmt.Sprintf("Red Hat build %s-%s is at or past %s, the first RHEL %d build with Red Hat's backport of the fix (%s)", pkg, stripEpoch(evr), stripEpoch(fx.EVR), el, fx.Advisory), true
}

func stripEpoch(evr string) string {
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		return evr[i+1:]
	}
	return evr
}

// RPMUpstream turns a Red Hat or Fedora OpenJDK rpm version into the Java
// version it packages: they append the build to the update, padding the
// patch with 0 (17.0.21.0.9-1.el9 is 17.0.21+9, 17.0.21.1.1 is 17.0.21.1+1).
// A version with fewer than five numbers is returned without its release.
func RPMUpstream(evr string) string {
	m := rpmVersion.FindStringSubmatch(evr)
	if m == nil {
		return evr
	}
	ver := m[2]
	parts := strings.Split(ver, ".")
	if len(parts) != 5 {
		return ver
	}
	return strings.Join(parts[:4], ".") + "+" + parts[4]
}

// CompareRPM compares two [epoch:]version[-release] strings the way rpm
// does (rpmvercmp on each part; a missing epoch is 0).
func CompareRPM(a, b string) int {
	ma, mb := rpmVersion.FindStringSubmatch(a), rpmVersion.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return strings.Compare(a, b)
	}
	ea, _ := strconv.Atoi(ma[1])
	eb, _ := strconv.Atoi(mb[1])
	switch {
	case ea < eb:
		return -1
	case ea > eb:
		return 1
	}
	if c := rpmvercmp(ma[2], mb[2]); c != 0 {
		return c
	}
	if ma[3] == "" || mb[3] == "" {
		return 0
	}
	return rpmvercmp(ma[3], mb[3])
}

// rpmvercmp is rpm's comparison of one version or release: alternating
// numeric and alphabetic segments, separators ignored, numbers newer than
// letters, and a tilde sorting before anything.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	isAlnum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	for {
		for a != "" && !isAlnum(a[0]) && a[0] != '~' {
			a = a[1:]
		}
		for b != "" && !isAlnum(b[0]) && b[0] != '~' {
			b = b[1:]
		}
		if a != "" && a[0] == '~' || b != "" && b[0] == '~' {
			switch {
			case a == "" || a[0] != '~':
				return 1
			case b == "" || b[0] != '~':
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		num := isDigit(a[0])
		seg := func(s string) (string, string) {
			i := 0
			for i < len(s) && (num && isDigit(s[i]) || !num && isAlnum(s[i]) && !isDigit(s[i])) {
				i++
			}
			return s[:i], s[i:]
		}
		sa, ra := seg(a)
		sb, rb := seg(b)
		if sb == "" {
			// Different kinds of segment: a number is newer than letters.
			if num {
				return 1
			}
			return -1
		}
		if num {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) < len(sb) {
					return -1
				}
				return 1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}
