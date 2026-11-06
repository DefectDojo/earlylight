package assess

import (
	"path"
	"strconv"
	"strings"
)

// OpkgOwners parses OpenWrt's opkg database: the status file and the
// per-package file lists (/usr/lib/opkg/info/NAME.list), into a map from
// file path to package.
func OpkgOwners(status []byte, lists map[string][]byte) map[string]Package {
	versions := map[string]string{}
	for _, rec := range strings.Split(strings.ReplaceAll(string(status), "\r\n", "\n"), "\n\n") {
		name, ver, installed := "", "", false
		for _, l := range strings.Split(rec, "\n") {
			k, v, ok := strings.Cut(l, ": ")
			if !ok {
				continue
			}
			switch k {
			case "Package":
				name = v
			case "Version":
				ver = v
			case "Status":
				installed = strings.Contains(v, "installed") && !strings.Contains(v, "not-installed")
			}
		}
		if name != "" && ver != "" && installed {
			versions[name] = ver
		}
	}
	out := map[string]Package{}
	for name, list := range lists {
		v, ok := versions[name]
		if !ok {
			continue
		}
		for _, f := range strings.Split(string(list), "\n") {
			if f = strings.TrimSpace(f); strings.HasPrefix(f, "/") {
				out[path.Clean(f)] = Package{Name: name, Version: v, Format: "opkg"}
			}
		}
	}
	return out
}

// openwrtFixed is the release of each OpenWrt openssh version that carries
// the fix: openwrt/packages "backport security mitigation from 10.6p2"
// (23.05, 24.10) and the 10.6_p2 update (master, 25.12), all 2026-11-05.
// 22.03 and older were not patched.
var openwrtFixed = map[string]int{"9.8p1": 2, "9.9_p2": 2}

// opkgStatus judges an OpenWrt openssh package version ("9.9_p2-2").
func opkgStatus(version string) (fixed bool, why string, ok bool) {
	i := strings.LastIndexByte(version, '-')
	if i < 0 {
		return false, "", false
	}
	pkgver, relStr := version[:i], version[i+1:]
	rel, err := strconv.Atoi(relStr)
	if err != nil {
		return false, "", false
	}
	up, ok := ParseRelease(strings.Replace(pkgver, "_p", "p", 1))
	if !ok {
		return false, "", false
	}
	if !up.Less(FixedRelease) {
		return true, "OpenWrt package " + version + " is OpenSSH " + up.String() + " or later, which has the fix", true
	}
	f, known := openwrtFixed[pkgver]
	switch {
	case !known:
		return false, "OpenWrt published no fix for openssh " + pkgver + " (fixed: 23.05 9.8p1-2, 24.10 9.9_p2-2, 25.12 10.6_p2-1)", true
	case rel >= f:
		return true, "OpenWrt package " + version + " carries the backported fix", true
	}
	return false, "OpenWrt package " + version + " is older than the fixed " + pkgver + "-" + strconv.Itoa(f), true
}
