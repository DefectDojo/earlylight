package assess

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
)

// Package is the OS package that installed a runtime.
type Package struct {
	Manager string `json:"manager"` // apk, dpkg, rpm
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	// From says how it was found: the package database, or the install path
	// (rpm, whose database this detector does not read).
	From string `json:"from"`
}

// javaPackage reports a package name that can hold a Java runtime.
func javaPackage(name string) bool {
	n := strings.ToLower(name)
	for _, s := range []string{"openjdk", "jdk", "jre", "java", "corretto", "temurin", "zulu", "liberica", "sapmachine", "semeru", "graalvm", "jbr"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// APKOwners maps the files of Java packages in an apk database to their
// package.
func APKOwners(db []byte) map[string]Package {
	out := map[string]Package{}
	var name, ver, dir string
	keep := false
	for _, line := range strings.Split(string(db), "\n") {
		if len(line) < 2 || line[1] != ':' {
			if line == "" {
				name, ver, dir, keep = "", "", "", false
			}
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			name, keep = v, javaPackage(v)
		case 'V':
			ver = v
		case 'F':
			dir = v
		case 'R':
			if keep && strings.HasPrefix(v, "libjvm.so") || keep && v == "release" {
				out["/"+path.Join(dir, v)] = Package{Manager: "apk", Name: name, Version: ver, From: "/lib/apk/db/installed"}
			}
		}
	}
	return out
}

// DpkgOwners maps the files listed in dpkg .list files of Java packages to
// their package, with versions from the status file.
func DpkgOwners(status []byte, lists map[string][]byte) map[string]Package {
	versions := map[string]string{}
	var name string
	for _, line := range strings.Split(string(status), "\n") {
		switch {
		case strings.HasPrefix(line, "Package: "):
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		case strings.HasPrefix(line, "Version: ") && name != "":
			versions[name] = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		case line == "":
			name = ""
		}
	}
	out := map[string]Package{}
	for pkg, b := range lists {
		n, _, _ := strings.Cut(pkg, ":")
		for _, f := range strings.Split(string(b), "\n") {
			f = strings.TrimSpace(f)
			if strings.HasSuffix(f, "/libjvm.so") || strings.HasSuffix(f, "/release") {
				out[f] = Package{Manager: "dpkg", Name: n, Version: versions[n], From: "/var/lib/dpkg/status"}
			}
		}
	}
	return out
}

// IsDpkgList reports a dpkg file list worth reading.
func IsDpkgList(p string) bool {
	return strings.HasPrefix(p, "/var/lib/dpkg/info/") && strings.HasSuffix(p, ".list") &&
		javaPackage(strings.TrimSuffix(path.Base(p), ".list"))
}

// rpmPath is how Red Hat, Fedora, SUSE and Amazon Linux name a packaged
// runtime: /usr/lib/jvm/java-17-openjdk-17.0.13.0.11-3.el9.x86_64.
var rpmPath = regexp.MustCompile(`^/usr/lib(?:64)?/jvm/(java-(\d+)-openjdk)-(\d[\w.]*-[\w.]+?)\.(x86_64|aarch64|ppc64le|s390x)$`)

// rpmFromPath names the rpm package a runtime directory belongs to.
func rpmFromPath(root string) (Package, bool) {
	m := rpmPath.FindStringSubmatch(root)
	if m == nil {
		if strings.HasPrefix(root, "/usr/lib/jvm/java-") && strings.Contains(root, "amazon-corretto") {
			return Package{Manager: "rpm", Name: path.Base(root), From: "install path"}, true
		}
		return Package{}, false
	}
	return Package{Manager: "rpm", Name: m[1] + "-headless", Version: m[3], From: "install path"}, true
}

// upgradeLine is the command that upgrades a package.
func upgradeLine(p Package) string {
	switch p.Manager {
	case "apk":
		return "apk upgrade " + p.Name
	case "dpkg":
		return "apt-get install --only-upgrade " + p.Name
	case "rpm":
		return "dnf upgrade " + p.Name + " (or yum upgrade)"
	}
	return ""
}

// distroStatus says whether the distribution had a fixed package when the
// data was checked.
func distroStatus(p Package) string {
	switch p.Manager {
	case "apk":
		return "Alpine had published no fixed package " + knowledge.AsOf()
	case "dpkg":
		return "Debian and Ubuntu had published no fixed package " + knowledge.AsOf()
	case "rpm":
		if pkg, el, ok := knowledge.RedHatPackage(p.Name, p.Version); ok {
			if fx, ok := knowledge.RedHatFixFor(pkg, el); ok {
				return fmt.Sprintf("Red Hat's first fixed %s build is %s, %s", el, fx.EVR, fx.Advisory)
			}
			return knowledge.RedHatStatus()
		}
		return "the distribution's fix status was not checked"
	}
	return ""
}
