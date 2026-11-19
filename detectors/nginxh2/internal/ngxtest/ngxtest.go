// Package ngxtest builds small files that read like nginx executables,
// for tests. They are not runnable.
package ngxtest

import (
	"bytes"
	"encoding/binary"
)

// Build describes a fake nginx executable.
type Build struct {
	// Line is the version line's text after "nginx version: "
	// ("nginx/1.31.8", "openresty/1.31.8.1", "nginx/1.24.0 (Ubuntu)").
	Line string
	// Tengine and Angie add their own version lines.
	Tengine, Angie string
	// Configure is the configure arguments ("" writes an empty line: every
	// nginx binary has one).
	Configure string
	// Modules are module names in the module list.
	Modules []string
	// Extra strings (Server header, error pages).
	Extra []string
	// ConfPath is the help text's default configuration file.
	ConfPath string
	Bits     int // 32 or 64 (default 64)
	Machine  uint16
}

// Default is an official-image-like nginx 1.31.8 with HTTP/2 and TLS.
func Default(version string) Build {
	return Build{
		Line:      "nginx/" + version,
		Configure: "--prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --with-http_ssl_module --with-http_v2_module",
		Modules:   []string{"ngx_core_module", "ngx_http_module", "ngx_http_ssl_module", "ngx_http_v2_module"},
		Extra:     []string{"nginx/" + version, "Server: nginx/" + version + "\r\n"},
		ConfPath:  "/etc/nginx/nginx.conf",
	}
}

// Bytes renders the build.
func (b Build) Bytes() []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 64)
	copy(hdr, "\x7fELF")
	hdr[4] = 2
	if b.Bits == 32 {
		hdr[4] = 1
	}
	hdr[5] = 1
	m := b.Machine
	if m == 0 {
		m = 62
	}
	binary.LittleEndian.PutUint16(hdr[18:], m)
	buf.Write(hdr)
	s := func(x string) {
		buf.WriteByte(0)
		buf.WriteString(x)
		buf.WriteByte(0)
	}
	for _, m := range b.Modules {
		s(m)
	}
	if b.Angie != "" {
		s("Angie version: " + b.Angie + "\n")
	}
	if b.Tengine != "" {
		s("Tengine version: " + b.Tengine + "\n")
	}
	if b.Line != "" {
		s("nginx version: " + b.Line + "\n")
	}
	s("configure arguments:" + func() string {
		if b.Configure == "" {
			return ""
		}
		return " " + b.Configure
	}() + "\n")
	if b.ConfPath != "" {
		s("  -c filename   : set configuration file (default: " + b.ConfPath + ")\n")
	}
	for _, x := range b.Extra {
		s(x)
	}
	return buf.Bytes()
}
