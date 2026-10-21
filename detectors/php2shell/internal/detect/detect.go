// Package detect recognises PHP runtimes (the CLI, PHP-FPM, CGI, the Apache
// module, LiteSpeed, FrankenPHP and embedded builds) by content, not by name, and
// reads the version each one was built as.
//
// Every PHP runtime links main/SAPI.c, which compiles the header
// "X-Powered-By: PHP/" PHP_VERSION into one NUL-terminated string, and the Zend
// engine, which compiles "Zend Engine v" ZEND_VERSION ", Copyright (c) ..." into
// another. A file is reported only when it is an executable or shared library
// (ELF, Mach-O or PE) and holds both strings, so source code, documentation,
// test fixtures and fingerprint databases that quote the header are not mistaken
// for PHP.
package detect

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/version"
)

// Marker is the header string every PHP runtime carries.
var Marker = []byte("X-Powered-By: PHP/")

var zendMarker = []byte("Zend Engine v")

// Binary is one PHP runtime file.
type Binary struct {
	Path string `json:"path"`
	// Version is the PHP_VERSION string compiled in, exactly as found.
	Version string `json:"version"`
	// Zend is the Zend engine version compiled in.
	Zend string `json:"zend_version"`
	// SAPI is how this file runs PHP: cli, fpm-fcgi, cgi-fcgi, apache2handler,
	// litespeed, frankenphp, embed, or unknown.
	SAPI string `json:"sapi"`
	Size int    `json:"size"`
	// Digests of the file, used to confirm it is the file a package installed.
	MD5    []byte `json:"-"`
	SHA1   []byte `json:"-"`
	SHA224 []byte `json:"-"`
	SHA256 []byte `json:"-"`
	SHA384 []byte `json:"-"`
	SHA512 []byte `json:"-"`
	// Problem is set when the file is a PHP runtime but its version cannot be
	// trusted (several different versions, or a Zend version that contradicts it).
	Problem string `json:"problem,omitempty"`
}

// Executable reports whether data starts like an ELF, Mach-O or PE file. head
// may be just the first bytes of the file.
func Executable(head []byte) bool {
	switch {
	case bytes.HasPrefix(head, []byte("\x7fELF")):
		return true
	case bytes.HasPrefix(head, []byte("MZ")):
		return true
	case len(head) >= 4:
		switch string(head[:4]) {
		case "\xfe\xed\xfa\xce", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xcf\xfa\xed\xfe":
			return true
		case "\xca\xfe\xba\xbe", "\xbe\xba\xfe\xca":
			// A Mach-O universal binary, or a Java class file (same magic). A class
			// file's bytes 4..8 are its version (major >= 45); a fat header there is a
			// small architecture count.
			if len(head) >= 8 {
				n := uint32(head[4])<<24 | uint32(head[5])<<16 | uint32(head[6])<<8 | uint32(head[7])
				if head[0] == 0xbe {
					n = uint32(head[7])<<24 | uint32(head[6])<<16 | uint32(head[5])<<8 | uint32(head[4])
				}
				return n > 0 && n < 45
			}
		}
	}
	return false
}

// versionChars are the bytes PHP_VERSION can hold: digits, dots, letters for
// RC/alpha/beta/dev tags and PHP_EXTRA_VERSION, and '-', '+', '~', '_'.
func versionChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-' || c == '+' || c == '~' || c == '_'
}

const maxVersionLen = 64

// cstrings returns every NUL-terminated value that follows prefix in data and
// starts with a digit, bounded in length.
func cstrings(data, prefix []byte, allow func(byte) bool) []string {
	var out []string
	seen := map[string]bool{}
	for off := 0; ; {
		i := bytes.Index(data[off:], prefix)
		if i < 0 {
			break
		}
		start := off + i + len(prefix)
		off = start
		j := start
		for j < len(data) && j-start <= maxVersionLen && allow(data[j]) {
			j++
		}
		if j == start || j >= len(data) || data[j] != 0 || j-start > maxVersionLen || data[start] < '0' || data[start] > '9' {
			continue
		}
		v := string(data[start:j])
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

var zendRe = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.-]*), Copyright \(c\)`)

// zendVersions returns the ZEND_VERSION values in "Zend Engine vX, Copyright (c)".
func zendVersions(data []byte) []string {
	var out []string
	seen := map[string]bool{}
	for off := 0; ; {
		i := bytes.Index(data[off:], zendMarker)
		if i < 0 {
			break
		}
		start := off + i + len(zendMarker)
		off = start
		end := start + 96
		if end > len(data) {
			end = len(data)
		}
		m := zendRe.FindSubmatch(data[start:end])
		if m == nil {
			continue
		}
		v := string(m[1])
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Inspect returns the PHP runtime in data, or nil when data is not one.
func Inspect(p string, data []byte) *Binary {
	if !Executable(data) {
		return nil
	}
	vs := cstrings(data, Marker, versionChar)
	if len(vs) == 0 {
		return nil
	}
	zs := zendVersions(data)
	if len(zs) == 0 {
		return nil
	}
	b := &Binary{Path: p, Version: vs[0], Zend: zs[0], SAPI: SAPI(p), Size: len(data)}
	m, s1, s224, s256, s384, s512 := md5.Sum(data), sha1.Sum(data), sha256.Sum224(data), sha256.Sum256(data), sha512.Sum384(data), sha512.Sum512(data)
	b.MD5, b.SHA1, b.SHA224, b.SHA256, b.SHA384, b.SHA512 = m[:], s1[:], s224[:], s256[:], s384[:], s512[:]
	switch {
	case len(vs) > 1:
		b.Problem = fmt.Sprintf("the file carries several PHP versions (%s)", strings.Join(vs, ", "))
	case len(zs) > 1:
		b.Problem = fmt.Sprintf("the file carries several Zend engine versions (%s)", strings.Join(zs, ", "))
	default:
		b.Problem = zendMismatch(b.Version, b.Zend)
	}
	return b
}

// zendMismatch checks the one relation that holds for every PHP 8 release: Zend
// engine 4.MINOR.PATCH ships with PHP 8.MINOR.PATCH.
func zendMismatch(php, zend string) string {
	v, err := version.ParsePHP(php)
	if err != nil {
		return fmt.Sprintf("unrecognised PHP version %q", php)
	}
	if v.Major != 8 {
		return ""
	}
	want := fmt.Sprintf("4.%d.%d", v.Minor, v.Patch)
	if !strings.HasPrefix(zend, want) {
		return fmt.Sprintf("PHP version %s does not match Zend engine %s (expected %s)", php, zend, want)
	}
	return ""
}

// SAPI names how the file at p runs PHP, from its name and location.
func SAPI(p string) string {
	base := path.Base(p)
	dir := path.Dir(p)
	low := strings.ToLower(base)
	switch {
	case strings.HasPrefix(low, "php-fpm") || strings.HasPrefix(low, "php_fpm") || strings.HasPrefix(low, "php-fpm."):
		return "fpm-fcgi"
	case strings.HasPrefix(low, "php-cgi") || strings.HasPrefix(low, "php_cgi"):
		return "cgi-fcgi"
	case strings.HasPrefix(low, "lsphp"):
		return "litespeed"
	case strings.HasPrefix(low, "frankenphp"):
		return "frankenphp"
	case strings.HasPrefix(low, "mod_php") || (strings.HasPrefix(low, "libphp") && (strings.Contains(dir, "apache") || strings.Contains(dir, "httpd"))):
		return "apache2handler"
	case phpDLL.MatchString(low):
		// Windows: php8ts.dll / php8.dll hold the engine for every SAPI.
		return "core-library"
	case strings.HasPrefix(low, "libphp") || strings.HasPrefix(low, "php") && strings.Contains(low, ".so"):
		return "embed"
	case strings.HasPrefix(low, "php"):
		return "cli"
	}
	return "unknown"
}

var phpDLL = regexp.MustCompile(`^php[0-9]+(ts)?(_debug)?\.dll$`)

// WebSAPI reports whether the SAPI serves web requests directly.
func WebSAPI(s string) bool {
	switch s {
	case "fpm-fcgi", "cgi-fcgi", "apache2handler", "litespeed", "frankenphp", "core-library":
		return true
	}
	return false
}
