package assess

import (
	"bytes"
	"debug/elf"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Libc is the C library an sshd binary runs on.
type Libc string

const (
	Musl    Libc = "musl"
	Glibc   Libc = "glibc"
	UClibc  Libc = "uclibc"
	Bionic  Libc = "bionic"
	Unknown Libc = "unknown"
)

// Binary is what an OpenSSH server executable proves about itself.
type Binary struct {
	Path string `json:"path"`
	// Role is "sshd" (the listener, or a pre-9.8 monolithic server),
	// "sshd-session" or "sshd-auth".
	Role string `json:"role"`
	// Release is the OpenSSH release the binary reports ("10.0p2").
	Release string  `json:"release,omitempty"`
	Version Version `json:"-"`
	Interp  string  `json:"interpreter,omitempty"`
	Libc    Libc    `json:"libc"`
	Static  bool    `json:"static,omitempty"`
	// PAM is true when the binary links libpam (or carries PAM statically).
	PAM bool `json:"pam"`
	// Helpers are the sshd-session and sshd-auth paths the binary runs.
	Helpers []string `json:"helpers,omitempty"`
	// Config is the default sshd_config path compiled in.
	Config string `json:"config,omitempty"`
}

// Version is an OpenSSH release: major.minor plus the portable patch level.
type Version struct {
	Major, Minor, Portable int
}

func (v Version) Less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Portable < o.Portable
}

func (v Version) String() string {
	s := strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor)
	if v.Portable > 0 {
		s += "p" + strconv.Itoa(v.Portable)
	}
	return s
}

// Upstream releases that matter.
var (
	// FixedRelease is the first upstream release with the fix (commit
	// 4353fdc43, "avoid password authn bypass", 2026-11-05).
	FixedRelease = Version{10, 6, 2}
	// FirstAffected is the first release that picks a salt from another
	// account for a one-character password field (commit 9286875a7,
	// "Determine appropriate salt for invalid users", OpenSSH 7.3p1).
	// Before it, sshd hashed with the DES salt "xx", which musl never fails.
	FirstAffected = Version{7, 3, 1}
)

var releaseRE = regexp.MustCompile(`^OpenSSH_([0-9]{1,3})\.([0-9]{1,3})(?:p([0-9]{1,3}))?$`)

// ParseRelease parses "10.0p2" or "OpenSSH_10.0p2".
func ParseRelease(s string) (Version, bool) {
	if !strings.HasPrefix(s, "OpenSSH_") {
		s = "OpenSSH_" + s
	}
	m := releaseRE.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.Portable, _ = strconv.Atoi(m[3])
	}
	return v, true
}

// cstrings returns the NUL-terminated printable strings of at least min bytes.
func cstrings(b []byte, min int, keep func(string) bool) []string {
	var out []string
	start := -1
	for i, c := range b {
		printable := c >= 0x20 && c < 0x7f
		switch {
		case printable && start < 0:
			start = i
		case !printable:
			if start >= 0 && c == 0 && i-start >= min {
				if s := string(b[start:i]); keep(s) {
					out = append(out, s)
				}
			}
			start = -1
		}
	}
	return out
}

// IsSSHD reports whether data looks like an OpenSSH server executable worth
// inspecting: an ELF file naming sshd_config and an OpenSSH release.
func IsSSHD(data []byte) bool {
	return len(data) > 4 && bytes.HasPrefix(data, []byte("\x7fELF")) &&
		bytes.Contains(data, []byte("sshd_config")) && bytes.Contains(data, []byte("OpenSSH_"))
}

// Inspect reads an OpenSSH server executable. ok is false for anything else.
func Inspect(p string, data []byte) (*Binary, bool) {
	if !IsSSHD(data) {
		return nil, false
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return nil, false
	}
	b := &Binary{Path: p, Libc: Unknown}

	// The release is the exact SSH_RELEASE string ("OpenSSH_10.0p2"); the
	// compat table's patterns ("OpenSSH_7.4*") never match exactly. Some
	// builds also carry SSH_VERSION alone ("OpenSSH_10.0"): keep the most
	// specific one.
	var best Version
	found := false
	for _, s := range cstrings(data, 9, func(s string) bool { return strings.HasPrefix(s, "OpenSSH_") }) {
		v, ok := ParseRelease(s)
		if !ok {
			continue
		}
		// A release with its portable level beats one without; otherwise
		// the higher wins.
		if !found || (v.Portable > 0) != (best.Portable > 0) && v.Portable > 0 || (v.Portable > 0) == (best.Portable > 0) && best.Less(v) {
			best, found = v, true
		}
	}
	if !found {
		return nil, false
	}
	b.Version, b.Release = best, best.String()

	for _, s := range cstrings(data, 8, func(s string) bool { return strings.HasPrefix(s, "/") }) {
		switch {
		case strings.HasSuffix(s, "/sshd_config") && b.Config == "":
			b.Config = path.Clean(s)
		case isHelper(s):
			b.Helpers = appendOnce(b.Helpers, path.Clean(s))
		}
	}

	for _, prog := range f.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		buf := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(buf, 0); err == nil {
			b.Interp = string(bytes.TrimRight(buf, "\x00"))
		}
	}
	needed, _ := f.ImportedLibraries()
	for _, n := range needed {
		if strings.HasPrefix(n, "libpam.so") {
			b.PAM = true
		}
	}
	b.Libc = libcOf(b.Interp, needed, data)
	b.Static = b.Interp == "" && len(needed) == 0
	if b.Static && bytes.Contains(data, []byte("pam_authenticate")) {
		b.PAM = true
	}
	b.Role = role(p, data)
	return b, true
}

func isHelper(s string) bool {
	base := path.Base(s)
	for _, h := range []string{"sshd-session", "sshd-auth"} {
		if base == h || strings.HasPrefix(base, h+".") {
			return true
		}
	}
	return false
}

func appendOnce(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// role names the part of the server a binary is. File names decide first,
// since vendors rename (sshd.pam, sshd-session.krb5); strings decide for
// anything renamed beyond recognition.
func role(p string, data []byte) string {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(base, "sshd-session"):
		return "sshd-session"
	case strings.HasPrefix(base, "sshd-auth"):
		return "sshd-auth"
	case strings.HasPrefix(base, "sshd"):
		return "sshd"
	case bytes.Contains(data, []byte("Server listening on")):
		return "sshd"
	}
	return "sshd-session"
}

func libcOf(interp string, needed []string, data []byte) Libc {
	base := path.Base(interp)
	switch {
	case strings.HasPrefix(base, "ld-musl-"):
		return Musl
	case strings.HasPrefix(base, "ld-uClibc"):
		return UClibc
	case base == "linker" || base == "linker64":
		return Bionic
	case strings.HasPrefix(base, "ld-linux") || strings.HasPrefix(base, "ld64.so") || strings.HasPrefix(base, "ld.so"):
		return Glibc
	}
	for _, n := range needed {
		switch {
		case strings.HasPrefix(n, "libc.musl-") || n == "libc.musl.so":
			return Musl
		case n == "libc.so.6":
			return Glibc
		case strings.HasPrefix(n, "libc.so.0"):
			return UClibc
		}
	}
	if interp == "" && len(needed) == 0 {
		// Statically linked. musl's getspnam reads tcb shadow files first,
		// so a static musl sshd carries that path; glibc's carries its own
		// markers.
		switch {
		case bytes.Contains(data, []byte("/etc/tcb/%s/shadow")):
			return Musl
		case bytes.Contains(data, []byte("GLIBC_PRIVATE")) || bytes.Contains(data, []byte("FATAL: kernel too old")):
			return Glibc
		}
	}
	return Unknown
}
