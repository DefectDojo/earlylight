package knowledge

import "strings"

// Backport is a distribution package that carries a CVE's fix without a
// new nginx version.
type Backport struct {
	Distro   string // os-release ID: debian, ubuntu, alpine, rhel
	Release  string // VERSION_ID for Debian and Ubuntu ("12"), the branch for Alpine ("3.24"); "" for any
	Package  string // source package
	Fixed    string // first fixed package version
	CVEs     []string
	Advisory string
}

// Backports is empty: no distribution had published a fixed nginx package
// on 2026-11-18 (FACTS.md).
var Backports []Backport

// DistroStatus says, for a distribution's own nginx package, what was
// published by the check date.
var DistroStatus = map[string]string{
	"debian": "Debian had published no fixed nginx package on " + Checked + " (security tracker: unfixed in bookworm, trixie, forky and sid)",
	"ubuntu": "Ubuntu had published no fixed nginx package on " + Checked + " (newest: jammy 1.18.0-6ubuntu14.22, noble 1.24.0-2ubuntu7.19, questing 1.28.0-6ubuntu1.8, resolute 1.28.3-2ubuntu1.12)",
	"alpine": "Alpine had published no fixed nginx package on " + Checked + " (3.24 1.30.6-r0, edge 1.30.6-r1, 3.22 and 3.23 1.28.3-r7, 3.21 1.26.3-r3)",
	"rhel":   "Red Hat's status could not be read on " + Checked + "; a Red Hat build is judged by its version until a fixed build is known",
}

// DistroOf maps an os-release ID (and ID_LIKE) to the family whose status
// applies.
func DistroOf(id, like string) string {
	for _, w := range append([]string{id}, strings.Fields(like)...) {
		switch w {
		case "debian", "ubuntu", "alpine":
			return w
		case "rhel", "centos", "rocky", "almalinux", "ol", "fedora", "amzn":
			return "rhel"
		}
	}
	return ""
}

// NginxOrgMaintainer is in the Maintainer field of nginx.org's packages,
// which ship the upstream release and never backport.
func NginxOrgMaintainer(m string) bool {
	m = strings.ToLower(m)
	return strings.Contains(m, "nginx-packaging@f5.com") || strings.Contains(m, "nginx-packaging@nginx.com") || strings.Contains(m, "nginx packaging")
}

// UpdateText is the fix text for an upstream build.
const UpdateText = "Update nginx to 1.31.9 (mainline) or 1.30.7 (stable): the Docker official image tags 1.31.9 and 1.30.7 (every variant), or nginx.org's packages of those releases."

// Interim is the mitigation text, never a fix.
const Interim = "Until it is updated, turning HTTP/2 off (\"http2 off;\" from 1.25.1, and no \"http2\" parameter on any listen) removes the published path; it is not a fix."
