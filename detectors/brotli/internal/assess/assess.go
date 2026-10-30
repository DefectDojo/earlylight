// Package assess judges one executable or shared library for CVE-2026-111497
// from what internal/fingerprint reads in it, and names the fix for the
// software it belongs to. It knows nothing about the engine, so other tools
// can copy it with fingerprint.
package assess

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/fingerprint"
)

// CVE is the vulnerability assessed.
const CVE = "CVE-2026-111497"

// Status is a verdict.
type Status string

const (
	Vulnerable Status = "vulnerable"
	Fixed      Status = "fixed"
	Unknown    Status = "unknown"
)

// Kind separates a shared decoder library, fixed by an OS package update,
// from a copy bundled into other software, fixed only by updating that
// software.
type Kind string

const (
	Library Kind = "decoder-library"
	Bundled Kind = "bundled-decoder"
	// GoPort is a pure Go port with the same logic error, which panics
	// instead of corrupting memory: not CVE-2026-111497 itself.
	GoPort Kind = "go-port"
)

// Product is the software a decoder belongs to, as far as the file shows.
type Product string

const (
	LibBrotliDec Product = "libbrotlidec"
	Node         Product = "node"
	Dotnet       Product = "dotnet"
	PyBrotli     Product = "python-brotli"
	BrotliCFFI   Product = "python-brotlicffi"
	Bun          Product = "bun"
	Envoy        Product = "envoy"
	Electron     Product = "electron"
	GoBrotli     Product = "go-andybalholm-brotli"
	// PyWheel is a libbrotlidec that a Python wheel vendored next to its
	// own code (auditwheel's and delvewheel's <package>.libs, delocate's
	// <package>/.dylibs): updating the system package does not touch it.
	PyWheel Product = "python-wheel"
	Other   Product = "other"
)

// Finding is the verdict on one file.
type Finding struct {
	Kind    Kind    `json:"kind"`
	Path    string  `json:"path"`
	Status  Status  `json:"status"`
	Reason  string  `json:"reason"`
	Message string  `json:"message"`
	Method  string  `json:"method"`
	Product Product `json:"product"`
	// Version is the product's own release, when the file proves it.
	Version string `json:"version,omitempty"`
	// Fix is what to do; empty when Status is Fixed.
	Fix string `json:"fix,omitempty"`
	// Table describes the decoder's error table: "bare" (Brotli 1.0.x),
	// "prefixed" (1.1.0 and later), or empty when the build stripped it.
	Table       string `json:"table,omitempty"`
	BlockSwitch bool   `json:"block_switch"`
	Distance    bool   `json:"distance"`
	// NotTheCVE is set for a related flaw that is not CVE-2026-111497 itself
	// (the Go port's crash).
	NotTheCVE bool `json:"not_the_cve,omitempty"`
}

// Fixed releases per release line of the software that bundles Brotli. A
// line missing here has no fixed release.
var (
	NodeFixed = map[int]fingerprint.Version{
		22: fingerprint.V(22, 23, 4),
		24: fingerprint.V(24, 22, 1),
		26: fingerprint.V(26, 12, 1),
	}
	DotnetFixed = map[int]fingerprint.Version{
		8:  fingerprint.V(8, 0, 33),
		9:  fingerprint.V(9, 0, 22),
		10: fingerprint.V(10, 0, 14),
	}
	BunFixed = fingerprint.V(1, 4, 4)
)

// identify names the product from the file name and the version stamps in it.
func identify(p string, data []byte) (Product, fingerprint.Version, bool) {
	if i := strings.LastIndex(p, "!/"); i >= 0 {
		p = p[i+2:] // an archive member is named by its own path
	}
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, `\`, "/")))
	switch {
	case strings.HasPrefix(base, "libbrotlidec") || strings.HasPrefix(base, "brotlidec"):
		return LibBrotliDec, fingerprint.Version{}, false
	case strings.Contains(base, "system.io.compression.native"):
		v, ok := fingerprint.DotnetRuntime(data)
		return Dotnet, v, ok
	case strings.HasPrefix(base, "_brotlicffi"):
		return BrotliCFFI, fingerprint.Version{}, false
	case strings.HasPrefix(base, "_brotli."):
		return PyBrotli, fingerprint.Version{}, false
	}
	// Bun before Node.js: Bun also carries Node.js's headers URL, for
	// process.release.
	if v, ok := fingerprint.BunVersion(data); ok {
		return Bun, v, true
	}
	if v, ok := fingerprint.NodeVersion(data); ok {
		return Node, v, true
	}
	switch base {
	case "node", "node.exe":
		return Node, fingerprint.Version{}, false
	case "envoy", "envoy.exe":
		return Envoy, fingerprint.Version{}, false
	}
	return Other, fingerprint.Version{}, false
}

// wheelPackage names the Python package that vendored the library at p, from
// the directory a wheel repair tool put it in: <package>.libs (auditwheel on
// Linux, delvewheel on Windows) names the distribution, <module>/.dylibs
// (delocate on macOS) the import package, so imported reports which. Only
// paths inside site-packages, dist-packages or a wheel count, so a libtool
// .libs build directory stays the system library.
func wheelPackage(p string) (name string, imported, ok bool) {
	p = strings.ReplaceAll(p, `\`, "/")
	lower := strings.ToLower(p)
	if !strings.Contains(lower, "/site-packages/") && !strings.Contains(lower, "/dist-packages/") && !strings.Contains(lower, ".whl!/") {
		return "", false, false
	}
	if i := strings.LastIndex(p, "!/"); i >= 0 {
		p = "/" + p[i+2:]
	}
	dir := path.Dir(p)
	parent := path.Base(dir)
	switch {
	case parent == ".dylibs":
		pkg := path.Base(path.Dir(dir))
		if pkg == "." || pkg == "/" || pkg == "site-packages" || pkg == "dist-packages" {
			return "", false, false
		}
		return pkg, true, true
	case strings.HasSuffix(parent, ".libs") && parent != ".libs":
		return strings.TrimSuffix(parent, ".libs"), false, true
	}
	return "", false, false
}

// update returns the fix for a product line: "Update Node.js 24.22.0 to
// 24.22.1", or, for a line with no fixed release, the lines to move to.
func update(name string, v fingerprint.Version, known bool, fixed map[int]fingerprint.Version, all string) string {
	if !known {
		return "Update " + name + " to " + all + "."
	}
	if f, ok := fixed[v.Major]; ok {
		return fmt.Sprintf("Update %s %s to %s.", name, v, f)
	}
	return fmt.Sprintf("%s %d has no fixed release: move to %s.", name, v.Major, all)
}

func fixFor(p Product, v fingerprint.Version, known bool) string {
	switch p {
	case LibBrotliDec:
		return "Update the system Brotli package (libbrotli1, brotli-libs, libbrotli or brotli) to your vendor's fixed build, or build Brotli 1.0.10, 1.1.1 or 1.2.1, then restart the programs that load it."
	case Node:
		return update("Node.js", v, known, NodeFixed, "22.23.4, 24.22.1 or 26.12.1")
	case Dotnet:
		return update(".NET", v, known, DotnetFixed, "8.0.33, 9.0.22 or 10.0.14") + " Rebuild self-contained apps and images that bundle the runtime."
	case PyBrotli:
		return "Upgrade the Brotli Python package to 1.2.1."
	case BrotliCFFI:
		return "Upgrade the brotlicffi Python package to 1.2.1.0."
	case Bun:
		return "Update Bun to 1.4.4, and rebuild executables made with bun build --compile."
	case Envoy:
		return "Update Envoy to 1.37.8, 1.38.6, 1.39.3 or 1.40.0 (Istio 1.29.9, 1.30.6 or 1.31.2)."
	case Electron:
		return "Update Electron to a current release (43.8.4, 44.10.0, 45.1.0 or later), then rebuild and ship the app."
	}
	return "Rebuild it with Brotli 1.0.10, 1.1.1 or 1.2.1, or update it to a release that includes one of them."
}

var labels = map[Product]string{
	LibBrotliDec: "libbrotlidec", Node: "Node.js", Dotnet: ".NET", PyBrotli: "Brotli Python package",
	BrotliCFFI: "brotlicffi Python package", Bun: "Bun", Envoy: "Envoy", Electron: "Electron",
}

func label(p Product, v fingerprint.Version, known bool) string {
	n, ok := labels[p]
	if !ok {
		return ""
	}
	if known {
		n += " " + v.String()
	}
	return " (" + n + ")"
}

// File judges one executable, shared library or WebAssembly module. It
// returns false for a file that carries no Brotli decoder.
func File(p string, data []byte) (Finding, bool) {
	prod, v, known := identify(p, data)
	f := Finding{Kind: Bundled, Path: p, Product: prod, Fix: fixFor(prod, v, known)}
	what := label(prod, v, known)
	if prod == LibBrotliDec {
		if pkg, imported, ok := wheelPackage(p); ok {
			prod, f.Product = PyWheel, PyWheel
			who := "the " + pkg + " Python package"
			if imported {
				who = "the Python package that provides " + pkg
			}
			f.Fix = "Upgrade " + who + " to a release whose wheel bundles Brotli 1.0.10, 1.1.1, 1.2.1 or later. Updating the system Brotli package does not change this copy."
			what = " (vendored in " + who + ")"
		} else {
			f.Kind = Library
		}
	}
	if known {
		f.Version = v.String()
	}
	judge := func(s Status, reason string) {
		f.Status, f.Reason = s, reason
		if s == Fixed {
			f.Fix = ""
		}
	}

	if tables := fingerprint.Tables(data); len(tables) > 0 {
		f.Method = "brotli-error-table"
		f.Table = "bare"
		unfixed, old, ancient := 0, 0, 0
		for _, t := range tables {
			if t.Prefixed {
				f.Table = "prefixed"
			}
			switch {
			case t.BlockSwitch:
				f.BlockSwitch, f.Distance = true, true
			case t.Distance:
				f.Distance = true
				unfixed++
			default:
				old++
				if !t.Prefixed {
					ancient++ // a bare table without DISTANCE: Brotli before 1.0.3 (0.x had no COMPOUND_DICTIONARY either)
				}
			}
		}
		switch {
		case unfixed > 0 && fingerprint.StrayBlockSwitch(data, tables):
			f.Message = "Brotli decoder whose error table lacks the fix's error code, in a file that names it elsewhere" + what
			judge(Unknown, "the decoder's error table has no BLOCK_SWITCH, but the file names BLOCK_SWITCH in another string; check which Brotli it was built from")
		case unfixed > 0:
			f.Message = "Brotli decoder without the " + CVE + " fix" + what
			judge(Vulnerable, "the decoder's error table has DISTANCE (Brotli 1.0.3 and later) but not BLOCK_SWITCH, the error code the fix added")
		case old > 0 && ancient == old && !f.BlockSwitch && !fingerprint.NamesDistance(data):
			f.Message = "Brotli decoder older than 1.0.3, which predates the flaw" + what
			judge(Fixed, "the decoder's error table is in the bare form of Brotli 1.0.x and older, without DISTANCE, and the file names DISTANCE nowhere: releases before 1.0.3 predate the flaw")
			f.Fix = ""
		case old > 0:
			f.Message = "Brotli decoder older than 1.0.3 or not recognised" + what
			judge(Unknown, "the decoder's error table has neither DISTANCE (Brotli 1.0.3) nor BLOCK_SWITCH (the fix): Brotli before 1.0.3 is not affected, but the table does not prove the version")
		default:
			f.Message = "Brotli decoder with the " + CVE + " fix" + what
			judge(Fixed, "the decoder's error table has BLOCK_SWITCH, the error code the fix added, so it has the fix (upstream or a vendor backport)")
		}
		return f, true
	}

	// No error table: the build stripped it, or a linker folded its names
	// into other strings. A product version or the decoder's own code
	// settles it.
	decoder := fingerprint.HasDecoderTables(data) || fingerprint.ExportsDecoder(data)
	if !decoder {
		return Finding{}, false
	}
	if fingerprint.RustPort(data) {
		return Finding{}, false // the Rust port, with no C error table: not this decoder
	}
	if gp, ok := goPort(data); ok {
		return gp(f), true
	}
	byCode := func(what string) bool {
		n, located := fingerprint.CodeMarker(data)
		if !located {
			return false
		}
		f.Method = "decoder-code"
		f.Message = what
		switch {
		case n == 0:
			judge(Vulnerable, "the decoder's code never returns -17 (BLOCK_SWITCH), the error code the fix added; every fixed build does")
		case n >= 3:
			judge(Fixed, fmt.Sprintf("the decoder's code returns -17 (BLOCK_SWITCH), the error code the fix added, from %d places", n))
		default:
			judge(Unknown, fmt.Sprintf("the decoder's code returns -17 from only %d place(s), which proves neither the fix nor its absence; check which Brotli it was built from", n))
		}
		return true
	}
	switch {
	case fingerprint.IsElectron(data):
		// Electron's decoder is Chromium's copy, which follows Brotli's
		// master branch, not the bundled Node.js's: its version says nothing.
		f.Product, f.Kind, f.Version = Electron, Bundled, ""
		f.Fix = "Update Electron to a current release (43.8.4, 44.10.0, 45.1.0 or later), then rebuild and ship the app."
		if byCode("Electron Brotli decoder (Chromium's copy)") {
			return f, true
		}
		f.Method = "decoder-tables"
		f.Message = "Electron Brotli decoder (Chromium's copy)"
		judge(Unknown, "Electron's decoder is Chromium's, which its version does not identify, and its code was not readable on this architecture; check the Electron release")
		return f, true
	case prod == Node && known:
		// Official Node.js builds bundle Brotli; Node.js 26 and the Windows
		// builds keep no readable table.
		f.Method = "node-version"
		f.Message = "Node.js " + v.String() + " Brotli decoder"
		fixedIn, line := NodeFixed[v.Major]
		switch {
		case !line && v.Major > 26:
			judge(Fixed, fmt.Sprintf("Node.js %d was released after the fix", v.Major))
		case !line:
			judge(Vulnerable, fmt.Sprintf("Node.js %d bundles Brotli and has no fixed release", v.Major))
		case v.Less(fixedIn):
			judge(Vulnerable, fmt.Sprintf("Node.js %s is earlier than %s, the first %d.x release with the fix", v, fixedIn, v.Major))
		default:
			judge(Fixed, fmt.Sprintf("Node.js %s includes the fix (first in %s)", v, fixedIn))
		}
		return f, true
	case prod == Dotnet:
		if !known {
			if ma, mi, build, _, ok := fingerprint.PEFileVersion(data); ok && ma >= 5 && ma <= 10 {
				// The Windows builds keep it in the version resource, in
				// the same scheme as the @(#)Version stamp.
				v, known = fingerprint.V(ma, mi, build/100), true
				if build < 100 {
					v.Patch = 0
				}
				f.Version, f.Fix = v.String(), fixFor(prod, v, true)
			}
		}
		f.Method = "dotnet-version"
		if !known {
			if byCode(".NET compression library Brotli decoder") {
				return f, true
			}
			f.Message = ".NET compression library with a Brotli decoder whose version could not be read"
			judge(Unknown, "the library has no Brotli error table and no readable .NET version; check the .NET runtime version")
			return f, true
		}
		f.Message = ".NET " + v.String() + " Brotli decoder"
		fixedIn, line := DotnetFixed[v.Major]
		switch {
		case !line && (v.Major == 6 || v.Major == 7):
			judge(Vulnerable, fmt.Sprintf(".NET %d bundles Brotli 1.0.9 and is out of support, with no fixed release", v.Major))
		case !line && v.Major > 10:
			judge(Fixed, fmt.Sprintf(".NET %d was released after the fix", v.Major))
		case !line:
			judge(Unknown, fmt.Sprintf(".NET %d is out of support and its bundled Brotli version is not known; move to a supported release", v.Major))
		case v.Less(fixedIn):
			judge(Vulnerable, fmt.Sprintf(".NET %s is earlier than %s, the first %d.0 release with the fix", v, fixedIn, v.Major))
		default:
			judge(Fixed, fmt.Sprintf(".NET %s includes the fix (first in %s)", v, fixedIn))
		}
		return f, true
	case prod == Bun:
		f.Method = "bun-version"
		f.Message = "Bun " + v.String() + " Brotli decoder"
		if v.Less(BunFixed) {
			judge(Vulnerable, fmt.Sprintf("Bun %s links Brotli and is earlier than %s, the first release with the fix", v, BunFixed))
		} else {
			judge(Fixed, fmt.Sprintf("Bun %s includes the fix (first in %s)", v, BunFixed))
		}
		return f, true
	}
	if ev, dev, ok := fingerprint.EnvoyVersion(data); ok || prod == Envoy {
		f.Product, f.Kind = Envoy, Bundled
		if ok {
			f.Version = ev.String()
			if dev {
				f.Version += "-dev"
			}
			f.Fix = fixFor(Envoy, ev, true)
			f.Method = "envoy-version"
			f.Message = "Envoy " + f.Version + " Brotli decoder"
			switch st, why := envoyStatus(ev, dev); st {
			case Vulnerable, Fixed:
				judge(st, why)
				return f, true
			}
		}
		if byCode("Envoy Brotli decoder" + label(Envoy, ev, ok)) {
			return f, true
		}
		f.Method = "decoder-tables"
		f.Message = "Envoy with Brotli, version not readable from the binary"
		judge(Unknown, "this Envoy build's version does not settle it and its decoder code was not readable; it is exposed when the Brotli decompressor filter is configured; check the Envoy or Istio version")
		return f, true
	}
	if dv, ok := fingerprint.DecoderVersion(data); ok {
		fixed, predates := fingerprint.ReleaseFixed(dv)
		f.Version = dv.String()
		switch {
		case fixed:
			f.Method, f.Message = "decoder-version", "Brotli "+dv.String()+" decoder"+what
			judge(Fixed, fmt.Sprintf("BrotliDecoderVersion returns %s, a release with the fix", dv))
			return f, true
		case predates:
			f.Method, f.Message = "decoder-version", "Brotli "+dv.String()+" decoder"+what
			judge(Fixed, fmt.Sprintf("BrotliDecoderVersion returns %s, which predates the flaw (it came with 1.0.3)", dv))
			return f, true
		}
	}
	if byCode("Brotli decoder whose error table was stripped" + what) {
		return f, true
	}
	if n, ok := fingerprint.WasmMinus17(data); ok && n == 0 {
		f.Method = "decoder-code"
		f.Message = "WebAssembly Brotli decoder without the " + CVE + " fix" + what
		judge(Vulnerable, "the module carries the Brotli decoder's tables and its code never uses -17 (BLOCK_SWITCH), the error code the fix added")
		return f, true
	}
	if fingerprint.ExportsDecoder(data) {
		f.Method = "exports"
		f.Message = "Brotli decoder whose error table was stripped" + what
		judge(Unknown, "the file exports the Brotli decoder but has no error table, version or readable code this detector can judge; check which Brotli it was built from")
		return f, true
	}
	f.Method = "decoder-tables"
	f.Message = "Brotli decoder whose error table and symbols were stripped" + what
	judge(Unknown, "the file carries the Brotli decoder's code-length tables, so a decoder is linked in, but no error table, version or readable code this detector can judge; check which Brotli it was built from")
	return f, true
}

// EnvoyFixed is the first fixed patch of each Envoy minor; 1.36 is out of
// support but got 1.36.12, and minors before it got nothing.
var EnvoyFixed = map[int]int{36: 12, 37: 8, 38: 6, 39: 3}

// envoyStatus judges an Envoy release. X.Y.Z-dev holds X.Y.(Z-1) and later
// commits, so it is fixed past the fixed patch and unknown at it.
func envoyStatus(v fingerprint.Version, dev bool) (Status, string) {
	if v.Major != 1 {
		return Unknown, ""
	}
	switch {
	case v.Minor == 40 && dev && v.Patch == 0:
		// 1.40.0-dev is main between the 1.39 branch and 1.40.0: it may
		// predate the fix.
		return Unknown, ""
	case v.Minor >= 40:
		return Fixed, fmt.Sprintf("Envoy %s is later than every release that needed the fix", envoyName(v, dev))
	}
	fixedPatch, line := EnvoyFixed[v.Minor]
	if !line {
		return Vulnerable, fmt.Sprintf("Envoy 1.%d has no fixed release", v.Minor)
	}
	switch {
	case !dev && v.Patch >= fixedPatch:
		return Fixed, fmt.Sprintf("Envoy %s includes the fix (first in 1.%d.%d)", v, v.Minor, fixedPatch)
	case !dev:
		return Vulnerable, fmt.Sprintf("Envoy %s is earlier than 1.%d.%d, the first 1.%d release with the fix", v, v.Minor, fixedPatch, v.Minor)
	case v.Patch-1 >= fixedPatch:
		return Fixed, fmt.Sprintf("Envoy %s-dev contains 1.%d.%d, which has the fix", v, v.Minor, v.Patch-1)
	case v.Patch < fixedPatch:
		return Vulnerable, fmt.Sprintf("Envoy %s-dev is a development build before 1.%d.%d, the first 1.%d release with the fix", v, v.Minor, fixedPatch, v.Minor)
	}
	return Unknown, ""
}

// goPort judges a Go program whose Brotli decoder is a pure Go port: it has
// the C decoder's tables, but not its memory corruption. andybalholm/brotli
// had the same logic error, a crash (denial of service), fixed in v1.2.7.
func goPort(data []byte) (func(Finding) Finding, bool) {
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	for _, d := range bi.Deps {
		path, ver := d.Path, d.Version
		if d.Replace != nil {
			path, ver = d.Replace.Path, d.Replace.Version
		}
		if path != "github.com/andybalholm/brotli" {
			continue
		}
		return func(f Finding) Finding {
			f.Product, f.Kind, f.Version, f.Method, f.NotTheCVE = GoBrotli, GoPort, ver, "go-buildinfo", true
			f.Message = "Go program with andybalholm/brotli " + ver + ", a pure Go port of the decoder"
			if semverLess(ver, "v1.2.7") {
				f.Status, f.Reason = Vulnerable, "andybalholm/brotli before v1.2.7 has the same block-switch logic error as the C decoder; in Go it panics (a denial of service) instead of corrupting memory"
				f.Fix = "Upgrade github.com/andybalholm/brotli to v1.2.7 (go get github.com/andybalholm/brotli@v1.2.7) and rebuild."
			} else {
				f.Status, f.Reason, f.Fix = Fixed, "andybalholm/brotli "+ver+" carries the port of the fix (v1.2.7)", ""
			}
			return f
		}, true
	}
	return nil, false
}

// semverLess compares Go module versions vX.Y.Z: a pre-release or
// pseudo-version sorts before its release (v1.2.7-rc.1 and
// v1.2.7-0.20261022010101-abcdef are before v1.2.7), anything unparsable
// first.
func semverLess(a, b string) bool {
	pa, preA, okA := parseSemver(a)
	pb, preB, okB := parseSemver(b)
	if !okA {
		return okB
	}
	if pa != pb {
		return pa.Less(pb)
	}
	return preA != "" && preB == ""
}

func parseSemver(v string) (fingerprint.Version, string, bool) {
	v = strings.TrimPrefix(v, "v")
	core, pre, _ := strings.Cut(v, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return fingerprint.Version{}, "", false
	}
	n := [3]int{}
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil {
			return fingerprint.Version{}, "", false
		}
		n[i] = x
	}
	return fingerprint.V(n[0], n[1], n[2]), pre, true
}

func envoyName(v fingerprint.Version, dev bool) string {
	if dev {
		return v.String() + "-dev"
	}
	return v.String()
}
