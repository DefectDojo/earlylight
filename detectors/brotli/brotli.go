// Package brotli is the detector for CVE-2026-111497 (also called Node2Shell,
// Broccoli2Shell and HTTP2Shell): an out-of-bounds write in Google Brotli's C
// decoder, in every release from 1.0.3 through 1.2.0, fixed in 1.0.10, 1.1.1
// and 1.2.1 on October 21, 2026. It finds Brotli decoders in filesystems and
// container images, as shared libraries (libbrotlidec) and as copies bundled
// into Node.js, .NET, Python packages, Bun and other software, and judges each
// by what the binary itself proves (see internal/fingerprint), so vendor
// backports are recognised without any distribution data.
//
// internal/fingerprint and internal/assess know nothing about the engine;
// this file only adapts them.
package brotli

import (
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/fingerprint"
	"github.com/DefectDojo/earlylight/internal/archive"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// ID is the detector's ID.
const ID = "brotli"

// Kind IDs.
const (
	KindLibrary = string(assess.Library)
	KindBundled = string(assess.Bundled)
	KindGoPort  = string(assess.GoPort)
)

// Detector implements engine.Detector, engine.Reader, engine.RepoScanner and
// engine.Fixer.
type Detector struct{}

func init() { engine.Register(&Detector{}) }

const about = " Brotli 1.0.3 through 1.2.0 discard an error from the block-switch decoder, so a crafted" +
	" compressed stream corrupts decoder memory: a crash, disclosure of process memory or code execution." +
	" Anything that decompresses untrusted Brotli data with it is exposed, such as HTTP clients and" +
	" servers that accept Content-Encoding: br. Fixed in Brotli 1.0.10, 1.1.1 and 1.2.1."

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	cwe := []string{"CWE-252", "CWE-787"}
	return engine.Manifest{
		ID:    ID,
		Title: "Brotli decoder vulnerable to " + assess.CVE,
		CVEs:  []string{assess.CVE},
		Advisories: []string{
			"https://github.com/advisories/GHSA-9v8h-qqgm-4m35",
			"https://github.com/google/brotli/releases/tag/v1.2.1",
			"https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
			"https://github.com/dotnet/announcements/issues/494",
		},
		Disclosed: "2026-10-21",
		Targets:   []engine.TargetKind{engine.Filesystem, engine.Image, engine.Repository},
		Kinds: append([]engine.Kind{
			{ID: KindLibrary, Title: "Brotli decoder library is vulnerable to " + assess.CVE, Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
				Description: "A shared Brotli decoder library (libbrotlidec) without the fix. Every program that loads it is exposed." + about},
			{ID: KindBundled, Title: "Bundled Brotli decoder is vulnerable to " + assess.CVE, Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
				Description: "A program or library that carries its own copy of the Brotli decoder (Node.js, .NET, a Python package, Bun and others) without the fix. Updating the system Brotli package does not fix it." + about},
			{ID: KindGoPort, Title: "Go program with a Brotli port that panics on the same malformed stream", Level: "warning", SecuritySeverity: "5.3", CWEs: []string{"CWE-252"},
				Description: "A Go program built with github.com/andybalholm/brotli before v1.2.7, a pure Go port of the decoder with the same block-switch logic error. In Go it panics instead of writing out of bounds: a denial of service, not CVE-2026-111497 itself. Fixed in v1.2.7."},
		}, repoKinds()...),
		Tags:     []string{"security", "brotli", "Node2Shell", "Broccoli2Shell"},
		Archives: true, // wheels, jars, npm tarballs and NuGet packages carry native decoders
		Data:     "Brotli decoder error-code tables (google/brotli 1.0.0 to 1.2.1) and the fixed Node.js, .NET and Bun releases",
	}
}

// Load has nothing to load: the knowledge is in the code.
func (d *Detector) Load() error { return nil }

// Wants reads executables and shared libraries, where decoders live, and
// archives, which can carry them.
func (d *Detector) Wants(_ string, head []byte, _ bool) bool {
	return archive.IsExecutable(head) || archive.IsArchive(head) || fingerprint.IsWasm(head)
}

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(engine.TargetKind) engine.Scan { return &scan{} }

type scan struct{ findings []engine.Finding }

func (s *scan) Visit(f engine.File) []engine.Skip {
	if !archive.IsExecutable(f.Data) && !fingerprint.IsWasm(f.Data) {
		return nil
	}
	if x, ok := assess.File(f.Path, f.Data); ok {
		s.findings = append(s.findings, finding(x))
	}
	return nil
}

func (s *scan) Finish(engine.TargetContext) []engine.Finding { return s.findings }

var verdicts = map[assess.Status]engine.Verdict{
	assess.Vulnerable: engine.Vulnerable,
	assess.Fixed:      engine.Fixed,
	assess.Unknown:    engine.Unknown,
}

func finding(x assess.Finding) engine.Finding {
	v, ok := verdicts[x.Status]
	if !ok {
		v = engine.Unknown
	}
	facts := map[string]string{"product": string(x.Product)}
	if x.Version != "" {
		facts["version"] = x.Version
	}
	if x.Table != "" {
		facts["error_table"] = x.Table
		facts["block_switch"] = yes(x.BlockSwitch)
		facts["distance"] = yes(x.Distance)
	}
	return engine.Finding{
		Kind:    string(x.Kind),
		Path:    x.Path,
		Verdict: v,
		Reason:  x.Reason,
		Message: x.Message,
		Method:  x.Method,
		Facts:   facts,
		CVEs:    cves(x, v),
		Fix:     x.Fix,
		Details: x,
	}
}

func cves(x assess.Finding, v engine.Verdict) []engine.CVEResult {
	if x.NotTheCVE {
		return nil
	}
	return []engine.CVEResult{{ID: assess.CVE, Verdict: v, Reason: x.Reason}}
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
