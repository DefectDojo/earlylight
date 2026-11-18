// Package jvm reads what a Java runtime's files prove: the VM library's CPU
// architecture (from its ELF, PE or Mach-O header), the VM name and version
// compiled into it, whether it carries the AVX-512 VBMI Base64 decode stubs,
// and the runtime's release file. It knows nothing about the engine.
package jvm

import (
	"bytes"
	"encoding/binary"
	"path"
	"regexp"
	"strings"
)

// Arch is a CPU architecture.
type Arch string

const (
	X8664   Arch = "x86-64"
	AArch64 Arch = "aarch64"
	X86     Arch = "x86"
	ARM     Arch = "arm"
	PPC64   Arch = "ppc64"
	S390X   Arch = "s390x"
	RISCV64 Arch = "riscv64"
	Other   Arch = "other"
)

// Library is one JVM library file: libjvm.so, jvm.dll, libjvm.dylib, or an
// OpenJ9 VM library.
type Library struct {
	Path   string `json:"path"`
	Format string `json:"format"` // elf, pe, macho
	// Archs are the architectures the file holds code for (a universal
	// Mach-O file holds several).
	Archs []Arch `json:"archs"`
	// VMName, VMVersion and JREVersion come from the version line compiled
	// into HotSpot ("OpenJDK 64-Bit Server VM (21.0.13+9-LTS) for
	// linux-amd64 JRE (21.0.13+9-LTS)"). Empty when it is not there.
	VMName     string `json:"vm_name,omitempty"`
	VMVersion  string `json:"vm_version,omitempty"`
	JREVersion string `json:"jre_version,omitempty"`
	Platform   string `json:"platform,omitempty"` // "linux-amd64"
	// VBMIStubs is true when the library names the AVX-512 VBMI Base64
	// decode stubs (lookup_lo_base64, pack_vec_base64), which come with the
	// vulnerable decoder (8268276).
	VBMIStubs bool `json:"vbmi_stubs"`
	// OpenJ9 is true for an OpenJ9 VM library or redirector.
	OpenJ9 bool `json:"openj9,omitempty"`
	// Variant is the VM directory: server, client, minimal, zero, j9vm...
	Variant string `json:"variant,omitempty"`
}

// HotSpot reports whether the library is a HotSpot VM.
func (l *Library) HotSpot() bool { return !l.OpenJ9 && l.VMName != "" }

// Has reports whether the library holds code for a.
func (l *Library) Has(a Arch) bool {
	for _, x := range l.Archs {
		if x == a {
			return true
		}
	}
	return false
}

var libNames = map[string]bool{"libjvm.so": true, "jvm.dll": true, "libjvm.dylib": true}

// IsOpenJ9Name reports an OpenJ9 VM library name (libj9vm29.so, j9vm29.dll).
func IsOpenJ9Name(base string) bool {
	b := strings.ToLower(base)
	return (strings.HasPrefix(b, "libj9vm") || strings.HasPrefix(b, "j9vm")) &&
		(strings.HasSuffix(b, ".so") || strings.HasSuffix(b, ".dll") || strings.HasSuffix(b, ".dylib"))
}

// IsLibraryName reports whether a file name is a JVM library.
func IsLibraryName(base string) bool {
	return libNames[base] || libNames[strings.ToLower(base)] || IsOpenJ9Name(base)
}

// vmLine is the version line HotSpot compiles in. JDK 8 has the same shape
// ("... JRE (1.8.0_452-b09)"), and musl builds name their platform
// linux-amd64-musl.
var vmLine = regexp.MustCompile(`([A-Za-z][ -~]{2,80}?VM) \(([0-9][!-'*-~]{0,60})\) for ([a-z0-9_]{1,20})-([a-z0-9_]{1,20}(?:-[a-z0-9_]{1,20})?) JRE \(([0-9][!-'*-~]{0,80})\)`)

// maxScan bounds how much of a file the version line is looked for in: it
// sits in read-only data, and a libjvm is under 64 MiB.
const maxScan = 256 << 20

// Inspect reads a JVM library. ok is false when the file is not one (wrong
// name or not an executable format).
func Inspect(p string, data []byte) (*Library, bool) {
	base := path.Base(p)
	if !IsLibraryName(base) {
		return nil, false
	}
	format, archs := header(data)
	if format == "" {
		return nil, false
	}
	l := &Library{Path: p, Format: format, Archs: archs, Variant: path.Base(path.Dir(p))}
	b := data
	if len(b) > maxScan {
		b = b[:maxScan]
	}
	if m := findVMLine(b); m != nil {
		l.VMName, l.VMVersion, l.JREVersion = string(m[1]), string(m[2]), string(m[5])
		l.Platform = string(m[3]) + "-" + string(m[4])
	}
	l.VBMIStubs = bytes.Contains(b, []byte("lookup_lo_base64\x00")) && bytes.Contains(b, []byte("pack_vec_base64\x00"))
	// OpenJ9: its VM library by name, or its lib/server redirector, which
	// has no HotSpot version line, no HotSpot decoder stubs and names
	// OPENJ9_JAVA_OPTIONS.
	if IsOpenJ9Name(base) || l.VMName == "" && !l.VBMIStubs && bytes.Contains(b, []byte("OPENJ9_JAVA_OPTIONS")) {
		l.OpenJ9 = true
	}
	return l, true
}

// findVMLine looks for the version line only around the literal " JRE (",
// so a large file of printable text cannot make the regular expression
// scan it all from every position.
func findVMLine(b []byte) [][]byte {
	const before, after, maxHits = 260, 100, 4096
	anchor := []byte(" JRE (")
	off := 0
	for hits := 0; hits < maxHits; hits++ {
		i := bytes.Index(b[off:], anchor)
		if i < 0 {
			return nil
		}
		at := off + i
		lo, hi := max(0, at-before), min(len(b), at+len(anchor)+after)
		if m := vmLine.FindSubmatch(b[lo:hi]); m != nil {
			return m
		}
		off = at + len(anchor)
	}
	return nil
}

// header reads an executable header: the format and the architectures.
func header(b []byte) (string, []Arch) {
	switch {
	case len(b) >= 20 && bytes.HasPrefix(b, []byte("\x7fELF")):
		var m uint16
		if b[5] == 2 {
			m = binary.BigEndian.Uint16(b[18:20])
		} else {
			m = binary.LittleEndian.Uint16(b[18:20])
		}
		return "elf", []Arch{elfArch(m)}
	case len(b) >= 64 && b[0] == 'M' && b[1] == 'Z':
		off := int(binary.LittleEndian.Uint32(b[60:64]))
		if off < 0 || off+6 > len(b) || !bytes.Equal(b[off:off+4], []byte("PE\x00\x00")) {
			return "", nil
		}
		return "pe", []Arch{peArch(binary.LittleEndian.Uint16(b[off+4 : off+6]))}
	case len(b) >= 8:
		le := binary.LittleEndian.Uint32(b[0:4])
		if le == 0xfeedfacf || le == 0xfeedface {
			return "macho", []Arch{machoArch(binary.LittleEndian.Uint32(b[4:8]))}
		}
		be := binary.BigEndian.Uint32(b[0:4])
		if be == 0xcafebabe || be == 0xcafebabf {
			n := int(binary.BigEndian.Uint32(b[4:8]))
			// A Java class file has the same magic; its "count" is a version
			// number of 45 or more. A universal binary holds a few slices.
			if n < 1 || n > 8 {
				return "", nil
			}
			size := 20
			if be == 0xcafebabf {
				size = 32
			}
			var out []Arch
			for i := 0; i < n; i++ {
				o := 8 + i*size
				if o+4 > len(b) {
					return "", nil
				}
				out = append(out, machoArch(binary.BigEndian.Uint32(b[o:o+4])))
			}
			return "macho", out
		}
	}
	return "", nil
}

func elfArch(m uint16) Arch {
	switch m {
	case 0x3e:
		return X8664
	case 0xb7:
		return AArch64
	case 3:
		return X86
	case 0x28:
		return ARM
	case 0x15:
		return PPC64
	case 0x16:
		return S390X
	case 0xf3:
		return RISCV64
	}
	return Other
}

func peArch(m uint16) Arch {
	switch m {
	case 0x8664:
		return X8664
	case 0xaa64:
		return AArch64
	case 0x14c:
		return X86
	}
	return Other
}

func machoArch(c uint32) Arch {
	switch c {
	case 0x01000007:
		return X8664
	case 0x0100000c:
		return AArch64
	case 7:
		return X86
	}
	return Other
}

// variantDirs are the directories a VM library sits in.
var variantDirs = map[string]bool{"server": true, "client": true, "minimal": true, "zero": true, "j9vm": true, "default": true,
	"compressedrefs": true, "classic": true, "hotspot": true, "jvmci": true}

// archDirs are the CPU directories of JDK 8 layouts (jre/lib/amd64/server).
var archDirs = map[string]bool{"amd64": true, "x86_64": true, "i386": true, "i586": true, "aarch64": true, "arm64": true, "ppc64le": true, "ppc64": true,
	"s390x": true, "riscv64": true, "arm": true, "sparcv9": true}

// Root returns the runtime directory a VM library belongs to:
// <root>/lib/server/libjvm.so, <root>/bin/server/jvm.dll,
// <root>/lib/amd64/server/libjvm.so (Java 8). ok is false for any other
// place.
func Root(lib string) (string, bool) {
	dir := path.Dir(lib)
	if !variantDirs[path.Base(dir)] {
		// OpenJ9 and some builds keep a VM library directly in lib/ or bin/.
		if b := path.Base(dir); b == "lib" || b == "bin" {
			return path.Dir(dir), true
		}
		return "", false
	}
	dir = path.Dir(dir)
	if archDirs[path.Base(dir)] {
		dir = path.Dir(dir)
	}
	if b := path.Base(dir); b != "lib" && b != "bin" {
		return "", false
	}
	return path.Dir(dir), true
}

// Release is a runtime's release file.
type Release map[string]string

// maxRelease bounds a release file: real ones are a few KiB.
const maxRelease = 64 << 10

// ParseRelease reads KEY="value" lines. ok is false for a file too large
// or with nothing a release file has.
func ParseRelease(b []byte) (Release, bool) {
	if len(b) > maxRelease {
		return nil, false
	}
	r := Release{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		k, v, ok := strings.Cut(line, "=")
		if !ok || k == "" || len(k) > 64 || strings.ContainsAny(k, " \t\"") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		if len(v) > 4096 {
			v = v[:4096]
		}
		if _, dup := r[k]; !dup {
			r[k] = v
		}
	}
	if r["JAVA_VERSION"] == "" {
		return nil, false
	}
	return r, true
}

// Version is the most precise version the release file states.
func (r Release) Version() string {
	if v := r["JAVA_RUNTIME_VERSION"]; v != "" {
		return v
	}
	return r["JAVA_VERSION"]
}

// OpenJ9 reports a release file that names the OpenJ9 VM.
func (r Release) OpenJ9() bool { return strings.EqualFold(r["JVM_VARIANT"], "openj9") }

// JLinked reports a runtime made with jlink: a release file with MODULES and
// without java.se, the module every full JDK and JRE has. A jlink image
// keeps only JAVA_VERSION and MODULES of the JDK's release file.
func (r Release) JLinked() bool {
	m := r["MODULES"]
	if m == "" {
		return false
	}
	for _, x := range strings.Fields(m) {
		if x == "java.se" {
			return false
		}
	}
	return true
}
