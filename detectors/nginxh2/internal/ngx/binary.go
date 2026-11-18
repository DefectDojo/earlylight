// Package ngx reads what an nginx executable proves about itself: the
// product and version in its version line, whether HTTP/2 and TLS are
// compiled in, where its configuration lives, and its word size. It knows
// nothing about the engine.
package ngx

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Product is the server a binary is.
type Product string

const (
	Nginx     Product = "nginx"
	OpenResty Product = "openresty"
	Tengine   Product = "tengine"
	Angie     Product = "angie"
	Plus      Product = "nginx-plus"
	// Other is a version line naming something else ("nginx version:
	// MyServer/2.0"): a renamed build.
	Other Product = "other"
	// Hidden is an nginx binary with no version line to read.
	Hidden Product = "hidden"
)

// Tri is a fact that may not be readable.
type Tri string

const (
	Yes     Tri = "yes"
	No      Tri = "no"
	Unknown Tri = "unknown"
)

// Binary is what one executable proves.
type Binary struct {
	Path    string  `json:"path"`
	Product Product `json:"product"`
	// Name and Version are the version line's ("openresty", "1.31.8.1").
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	// Core is the nginx version the build is based on (OpenResty, Tengine,
	// Plus), "" when not read.
	Core string `json:"core,omitempty"`
	// Build is the version line's parenthesised text ("Ubuntu",
	// "nginx-plus-r33-p2").
	Build string `json:"build,omitempty"`
	// PlusRelease is NGINX Plus's own release ("r33-p2", "37.0.7.1").
	PlusRelease string `json:"plus_release,omitempty"`
	HTTP2       Tri    `json:"http2"`
	TLS         Tri    `json:"tls"`
	// Configure is the configure arguments, when the binary has them.
	Configure string `json:"configure,omitempty"`
	// ConfPath and Prefix are the defaults compiled in.
	ConfPath string `json:"conf_path,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Bits     int    `json:"bits,omitempty"`
	Arch     string `json:"arch,omitempty"`
	// Conflict is set when the binary's version strings disagree.
	Conflict string `json:"conflict,omitempty"`
}

const maxField = 4096

var (
	configureMark = []byte("configure arguments:")
	coreModule    = []byte("\x00ngx_core_module\x00")
	v2Module      = []byte("\x00ngx_http_v2_module\x00")
	sslModule     = []byte("\x00ngx_http_ssl_module\x00")
)

// Inspect reads data as an nginx executable. ok is false for anything
// else: an nginx binary has its "configure arguments:" line and either a
// version line or the core module's name. Dynamic modules have neither
// version nor configure line.
func Inspect(p string, data []byte) (*Binary, bool) {
	if !bytes.Contains(data, configureMark) {
		return nil, false
	}
	b := &Binary{Path: p, HTTP2: Unknown, TLS: Unknown}
	found := b.versionLines(data)
	if !found {
		if !bytes.Contains(data, coreModule) {
			return nil, false
		}
		b.Product = Hidden
	}
	b.Bits, b.Arch = header(data)
	b.configure(data)
	b.features(data)
	b.paths(data)
	b.consistent(data)
	return b, true
}

// line returns the text after mark up to a newline, NUL or limit.
func line(data []byte, at int) string {
	end := at
	for end < len(data) && end-at < maxField && data[end] != 0 && data[end] != '\n' && data[end] != '\r' {
		end++
	}
	return string(data[at:end])
}

// versionLines reads "nginx version: ", "Tengine version: " and "Angie
// version: " lines. The first nginx line decides; a second, different
// one is a conflict.
func (b *Binary) versionLines(data []byte) bool {
	ng := lines(data, "nginx version: ")
	te := lines(data, "Tengine version: ")
	an := lines(data, "Angie version: ")
	switch {
	case len(an) > 0:
		b.Product = Angie
		b.Name, b.Version, b.Build = split(an[0])
		if len(uniq(an)) > 1 {
			b.Conflict = "the binary has more than one Angie version line: " + strings.Join(uniq(an), "; ")
		}
		return true
	case len(te) > 0:
		b.Product = Tengine
		b.Name, b.Version, b.Build = split(te[0])
		if len(uniq(te)) > 1 {
			b.Conflict = "the binary has more than one Tengine version line: " + strings.Join(uniq(te), "; ")
		}
		if len(ng) > 0 {
			if n, v, _ := split(ng[0]); n == "nginx" {
				b.Core = v
			}
		}
		return true
	case len(ng) == 0:
		return false
	}
	if len(uniq(ng)) > 1 {
		b.Conflict = "the binary has more than one nginx version line: " + strings.Join(uniq(ng), "; ")
	}
	b.Name, b.Version, b.Build = split(ng[0])
	switch {
	case strings.EqualFold(b.Name, "openresty"):
		b.Product = OpenResty
		if parts := strings.Split(b.Version, "."); len(parts) == 4 {
			b.Core = strings.Join(parts[:3], ".")
		}
	case b.Name == "nginx" && strings.Contains(asciiLower(b.Build), "nginx-plus"):
		b.Product = Plus
		b.Core = b.Version
		low := asciiLower(b.Build) // same length as Build, so its indexes hold
		i := strings.Index(low, "nginx-plus-")
		if i >= 0 {
			rel := b.Build[i+len("nginx-plus-"):]
			if j := strings.IndexAny(rel, " ,;)"); j >= 0 {
				rel = rel[:j]
			}
			b.PlusRelease = rel
		}
	case b.Name == "nginx":
		b.Product = Nginx
		b.Core = b.Version
	default:
		b.Product = Other
	}
	return true
}

// asciiLower lowers ASCII letters only, keeping every byte where it is.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// lines returns each line that follows mark, in order.
func lines(data []byte, mark string) []string {
	var out []string
	m := []byte(mark)
	for off := 0; off < len(data) && len(out) < 16; {
		i := bytes.Index(data[off:], m)
		if i < 0 {
			break
		}
		at := off + i + len(m)
		out = append(out, line(data, at))
		off = at
	}
	return out
}

func uniq(xs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// split reads "nginx/1.24.0 (Ubuntu)" into name, version and build.
func split(s string) (name, version, build string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " ("); i >= 0 && strings.HasSuffix(s, ")") {
		build = s[i+2 : len(s)-1]
		s = s[:i]
	}
	name, version, ok := strings.Cut(s, "/")
	if !ok {
		return s, "", build
	}
	return name, strings.TrimSpace(version), build
}

func (b *Binary) configure(data []byte) {
	i := bytes.Index(data, configureMark)
	if i < 0 {
		return
	}
	b.Configure = strings.TrimSpace(line(data, i+len(configureMark)))
}

// features decides HTTP/2 and TLS. The module's name in the module list
// proves it is compiled in. Its absence proves it is not only when the
// configure arguments were read and do not ask for it either (builds
// before 1.9.11 have no module list).
func (b *Binary) features(data []byte) {
	cfg := " " + b.Configure + " "
	decide := func(name []byte, flag string) Tri {
		switch {
		case bytes.Contains(data, name), strings.Contains(cfg, " "+flag+" "):
			return Yes
		case b.Configure != "":
			return No
		}
		return Unknown
	}
	b.HTTP2 = decide(v2Module, "--with-http_v2_module")
	b.TLS = decide(sslModule, "--with-http_ssl_module")
}

// paths reads the default configuration file and prefix: the help text
// first (it is what the binary uses), then the configure arguments.
func (b *Binary) paths(data []byte) {
	if c := between(data, "set configuration file (default: ", ")"); c != "" {
		b.ConfPath = c
	}
	if p := between(data, "set prefix path (default: ", ")"); p != "" {
		b.Prefix = p
	}
	for _, w := range strings.Fields(b.Configure) {
		if v, ok := strings.CutPrefix(w, "--conf-path="); ok && b.ConfPath == "" {
			b.ConfPath = strings.Trim(v, "'\"")
		}
		if v, ok := strings.CutPrefix(w, "--prefix="); ok && b.Prefix == "" {
			b.Prefix = strings.Trim(v, "'\"")
		}
	}
	if b.ConfPath == "" && b.Prefix != "" {
		b.ConfPath = strings.TrimSuffix(b.Prefix, "/") + "/conf/nginx.conf"
	}
	if b.ConfPath != "" && !strings.HasPrefix(b.ConfPath, "/") && b.Prefix != "" {
		b.ConfPath = strings.TrimSuffix(b.Prefix, "/") + "/" + b.ConfPath
	}
}

func between(data []byte, start, end string) string {
	i := bytes.Index(data, []byte(start))
	if i < 0 {
		return ""
	}
	rest := line(data, i+len(start))
	j := strings.Index(rest, end)
	if j <= 0 || j > 1024 {
		return ""
	}
	return rest[:j]
}

// consistent checks the binary's other "<name>/<version>" strings (the
// Server header, the error page footer) against its version line: a
// binary whose strings disagree has been edited or merged, and is not
// judged by either.
func (b *Binary) consistent(data []byte) {
	if b.Conflict != "" || b.Version == "" {
		return
	}
	name := b.Name
	if b.Product == Angie {
		name = "Angie"
	}
	if b.Product == Tengine {
		name = "Tengine"
	}
	mark := []byte(name + "/")
	for off := 0; off < len(data); {
		i := bytes.Index(data[off:], mark)
		if i < 0 {
			return
		}
		at := off + i
		off = at + len(mark)
		if at > 0 && isWord(data[at-1]) {
			continue // part of a longer name or a path ("/etc/nginx/")
		}
		v := versionAt(data, off)
		if v == "" {
			continue
		}
		if v != b.Version {
			b.Conflict = "the binary's version line says " + name + "/" + b.Version + " but it also carries " + name + "/" + v
			return
		}
	}
}

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '/' || c == '.'
}

// versionAt reads dotted digits at i, "" when there are none.
func versionAt(data []byte, i int) string {
	j := i
	for j < len(data) && j-i < 32 && (data[j] >= '0' && data[j] <= '9' || data[j] == '.') {
		j++
	}
	if j == i || data[i] == '.' {
		return ""
	}
	return strings.TrimRight(string(data[i:j]), ".")
}

// header reads the word size and CPU from an ELF, PE or Mach-O header.
func header(d []byte) (int, string) {
	switch {
	case len(d) >= 20 && bytes.HasPrefix(d, []byte("\x7fELF")):
		bits := 0
		switch d[4] {
		case 1:
			bits = 32
		case 2:
			bits = 64
		}
		var order binary.ByteOrder = binary.LittleEndian
		if d[5] == 2 {
			order = binary.BigEndian
		}
		return bits, elfMachine[order.Uint16(d[18:20])]
	case len(d) >= 64 && d[0] == 'M' && d[1] == 'Z':
		off := int(binary.LittleEndian.Uint32(d[0x3c:]))
		if off < 0 || off+6 > len(d) || string(d[off:off+4]) != "PE\x00\x00" {
			return 0, ""
		}
		switch binary.LittleEndian.Uint16(d[off+4:]) {
		case 0x8664:
			return 64, "x86_64"
		case 0xaa64:
			return 64, "aarch64"
		case 0x14c:
			return 32, "i386"
		}
		return 0, ""
	case len(d) >= 8:
		magic := binary.LittleEndian.Uint32(d)
		cpu := binary.LittleEndian.Uint32(d[4:])
		switch magic {
		case 0xfeedfacf:
			switch cpu {
			case 0x01000007:
				return 64, "x86_64"
			case 0x0100000c:
				return 64, "arm64"
			}
			return 64, ""
		case 0xfeedface:
			return 32, ""
		}
	}
	return 0, ""
}

var elfMachine = map[uint16]string{3: "i386", 8: "mips", 20: "ppc", 21: "ppc64", 22: "s390x", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv64"}
