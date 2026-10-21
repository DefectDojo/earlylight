package pkgdb

import (
	"strings"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
)

// OSRelease reads the distribution identity: /etc/os-release, or
// /usr/lib/os-release when /etc/os-release is absent from files (in images it
// is usually a symlink to ../usr/lib/os-release, so the walk only collects the
// target). Without either, it falls back to /etc/alpine-release (ID alpine)
// and /etc/debian_version (ID debian; a numeric "12.7" gives VERSION_ID "12",
// "trixie/sid" gives the codename). It returns false when nothing identifies
// the system.
func OSRelease(files map[string][]byte) (knowledge.OSRelease, bool) {
	norm := make(map[string][]byte, 4)
	for p, c := range files {
		switch cp := clean(p); cp {
		case "/etc/os-release", "/usr/lib/os-release", "/etc/alpine-release", "/etc/debian_version":
			norm[cp] = c
		}
	}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if data, ok := norm[p]; ok {
			if os, ok := parseOSRelease(data); ok {
				return os, true
			}
		}
	}
	if data, ok := norm["/etc/alpine-release"]; ok {
		if v := strings.TrimSpace(firstLine(data)); v != "" {
			return knowledge.OSRelease{ID: "alpine", VersionID: v}, true
		}
	}
	if data, ok := norm["/etc/debian_version"]; ok {
		v := strings.TrimSpace(firstLine(data))
		if v != "" {
			os := knowledge.OSRelease{ID: "debian"}
			if v[0] >= '0' && v[0] <= '9' {
				os.VersionID = strings.SplitN(v, ".", 2)[0]
			} else {
				os.Codename = strings.SplitN(v, "/", 2)[0]
			}
			return os, true
		}
	}
	return knowledge.OSRelease{}, false
}

func firstLine(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// parseOSRelease parses os-release(5): KEY=value lines, values optionally in
// single or double quotes with shell-style backslash escapes in double quotes.
func parseOSRelease(data []byte) (knowledge.OSRelease, bool) {
	vals := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" {
			continue
		}
		vals[strings.TrimSpace(k)] = unquoteOSRelease(strings.TrimSpace(v))
	}
	os := knowledge.OSRelease{
		ID:        strings.ToLower(vals["ID"]),
		IDLike:    strings.Fields(strings.ToLower(vals["ID_LIKE"])),
		VersionID: vals["VERSION_ID"],
		Codename:  vals["VERSION_CODENAME"],
		Pretty:    vals["PRETTY_NAME"],
	}
	if os.Codename == "" {
		os.Codename = vals["UBUNTU_CODENAME"]
	}
	if os.ID == "" {
		return os, false
	}
	return os, true
}

func unquoteOSRelease(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
		var b strings.Builder
		for i := 0; i < len(v); i++ {
			if v[i] == '\\' && i+1 < len(v) && strings.IndexByte("\"\\$`", v[i+1]) >= 0 {
				i++
			}
			b.WriteByte(v[i])
		}
		return b.String()
	}
	return v
}
