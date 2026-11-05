package assess

import (
	"path"
	"strconv"
	"strings"
)

// Package is an installed package that owns a file.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Format  string `json:"format"` // "apk"
}

// APKOwners parses an apk installed database (/lib/apk/db/installed) into a
// map from absolute file path to the package that installed it.
func APKOwners(db []byte) map[string]Package {
	out := map[string]Package{}
	for _, rec := range strings.Split(strings.ReplaceAll(string(db), "\r\n", "\n"), "\n\n") {
		var p Package
		dir := ""
		var files []string
		for _, l := range strings.Split(rec, "\n") {
			if len(l) < 2 || l[1] != ':' {
				continue
			}
			v := l[2:]
			switch l[0] {
			case 'P':
				p.Name = v
			case 'V':
				p.Version = v
			case 'F':
				dir = "/" + v
			case 'R':
				files = append(files, path.Join(dir, v))
			}
		}
		if p.Name == "" || p.Version == "" {
			continue
		}
		p.Format = "apk"
		for _, f := range files {
			out[f] = p
		}
	}
	return out
}

// apkVersion is an Alpine openssh version: 10.0_p1-r11.
type apkVersion struct {
	upstream Version
	pkgver   string // "10.0_p1"
	rel      int
}

func parseAPK(v string) (apkVersion, bool) {
	pkgver, rel, ok := strings.Cut(v, "-r")
	if !ok {
		return apkVersion{}, false
	}
	r, err := strconv.Atoi(rel)
	if err != nil {
		return apkVersion{}, false
	}
	up, ok := ParseRelease(strings.Replace(pkgver, "_p", "p", 1))
	if !ok {
		return apkVersion{}, false
	}
	return apkVersion{upstream: up, pkgver: pkgver, rel: r}, true
}

// alpineFixed is the first fixed release of each openssh version Alpine
// ships: aports pw.patch (upstream 4353fdc43), released 2026-11-05 on every
// branch from 3.16 to 3.24 and edge. Checked against each branch's APKINDEX
// and APKBUILD on 2026-11-05; 3.15 and older have no fixed package.
var alpineFixed = map[string]struct {
	rel    int
	branch string
}{
	"9.0_p1":  {6, "3.16"},
	"9.1_p1":  {7, "3.17"},
	"9.3_p2":  {4, "3.18"},
	"9.6_p1":  {3, "3.19"},
	"9.7_p1":  {6, "3.20"},
	"9.9_p2":  {1, "3.21"},
	"10.0_p1": {11, "3.22"},
	"10.2_p1": {1, "3.23"},
	"10.3_p1": {2, "3.24"},
}

// AlpineFixedFor returns the fixed package version for an Alpine branch
// ("3.22"), and edge's for "edge".
func AlpineFixedFor(branch string) (string, bool) {
	if branch == "edge" {
		return "10.6_p2-r0", true
	}
	for pv, f := range alpineFixed {
		if f.branch == branch {
			return pv + "-r" + strconv.Itoa(f.rel), true
		}
	}
	return "", false
}

// AlpineBranches lists the branches with a fixed package, oldest first.
func AlpineBranches() []string {
	return []string{"3.16", "3.17", "3.18", "3.19", "3.20", "3.21", "3.22", "3.23", "3.24", "edge"}
}

// apkStatus judges an Alpine openssh package version.
func apkStatus(version string) (fixed bool, why string, ok bool) {
	v, ok := parseAPK(version)
	if !ok {
		return false, "", false
	}
	if !v.upstream.Less(FixedRelease) {
		return true, "Alpine package " + version + " is OpenSSH " + v.upstream.String() + " or later, which has the fix", true
	}
	if v.upstream.Less(FirstAffected) {
		return true, "OpenSSH " + v.upstream.String() + " predates 7.3p1 and never borrows another account's salt", true
	}
	f, known := alpineFixed[v.pkgver]
	switch {
	case !known:
		return false, "Alpine never shipped a fix for openssh " + v.pkgver + "; only each branch's current version was patched", true
	case v.rel >= f.rel:
		return true, "Alpine package " + version + " carries the backported fix (" + v.pkgver + "-r" + strconv.Itoa(f.rel) + " and later)", true
	}
	return false, "Alpine package " + version + " is older than the fixed " + v.pkgver + "-r" + strconv.Itoa(f.rel), true
}

// APKFixed judges an Alpine openssh package version: fixed, why, and false
// when the version cannot be read.
func APKFixed(version string) (bool, string, bool) { return apkStatus(version) }
