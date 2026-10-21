// Package emudhra is the detector for the eMudhra intermediate CA keys
// compromised in October 2026 (Mozilla bug 2083449): trust stores, keystores,
// bundles and binaries that still trust them, Go binaries without Go's
// blocklist, and servers presenting certificates the compromised keys signed.
//
// The detection itself lives in internal/, copied verbatim from emudhra-scan
// (see SNAPSHOT at the repo root). This file only adapts it to the engine and
// replays emudhra-scan's per-target collector, so verdicts stay identical.
package emudhra

import (
	"context"
	"strings"
	"time"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/detect"
	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/host"
)

// ID is the detector's ID.
const ID = "emudhra"

// Detector implements engine.Detector and engine.Prober.
type Detector struct {
	det *detect.Detector
}

func init() { engine.Register(&Detector{}) }

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	return engine.Manifest{
		ID:         ID,
		Title:      "Trust in the compromised eMudhra intermediate CA keys",
		CVEs:       []string{"CVE-2026-111943"},
		Advisories: []string{"https://bugzilla.mozilla.org/show_bug.cgi?id=2083449"},
		Disclosed:  "2026-10-20",
		Targets:    []engine.TargetKind{engine.Filesystem, engine.Image, engine.Host},
		Kinds: []engine.Kind{
			{ID: string(detect.TrustsCompromisedKey), Title: "Contains a compromised eMudhra intermediate key", Level: "error"},
			{ID: string(detect.TrustsPathRoot), Title: "Contains a CA that issued or cross-signed the compromised eMudhra intermediates", Level: "error"},
			{ID: string(detect.WeakKey), Title: "Certificate key with a trivially small private scalar", Level: "error"},
			{ID: string(detect.UnpatchedGo), Title: "Go binary without the CVE-2026-111943 blocklist", Level: "warning"},
			{ID: string(detect.IssuedByCompromised), Title: "Certificate issued by a compromised eMudhra CA", Level: "error"},
		},
		Tags:     []string{"security", "tls", "pki"},
		Archives: true,
		Data:     "eight compromised intermediates and four path roots (Mozilla bug 2083449)",
	}
}

// Load loads and verifies the knowledge base: each compromised key is proven
// to be k·G for its small k before anything is scanned.
func (d *Detector) Load() error {
	if d.det != nil {
		return nil
	}
	det, err := detect.New()
	if err != nil {
		return err
	}
	d.det = det
	return nil
}

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(engine.TargetKind) engine.Scan {
	return &scan{det: d.det, files: map[string][]byte{}, dedupe: map[string]bool{}}
}

// Probe checks the certificate chain a TLS server presents.
func (d *Detector) Probe(_ context.Context, addr string, timeout time.Duration) (string, int, []engine.Finding, error) {
	target, certs, err := host.Chain(addr, timeout)
	if err != nil {
		return target, 0, nil, err
	}
	var out []engine.Finding
	for _, f := range d.det.Chain(target, certs) {
		out = append(out, finding(assess.Result{Finding: f, Status: assess.Active}))
	}
	return target, len(certs), out, nil
}

type scan struct {
	det      *detect.Detector
	findings []detect.Finding
	files    map[string][]byte
	dedupe   map[string]bool
}

// keep reports whether the assessment rules need this file's content: the
// system's own ca-certificates.conf (never a copy inside an archive), and any
// certifi/core.py, which is only ever read for the cacert.pem next to it.
func keep(p string) bool {
	return p == "/etc/ca-certificates.conf" || strings.HasSuffix(p, "/certifi/core.py")
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if keep(f.Path) {
		s.files[f.Path] = f.Data // raw path: lookups must never alias another file
	}
	found, skips := s.det.ScanAll(f.Path, f.Data)
	for _, x := range found {
		// The same certificate can be seen twice in one file, for example in an
		// xz file's stored chunk and in its decompressed content: report it once.
		k := x.Path + "\x00" + string(x.Kind) + "\x00" + x.SPKI
		if s.dedupe[k] {
			continue
		}
		s.dedupe[k] = true
		s.findings = append(s.findings, x)
	}
	var out []engine.Skip
	for _, sk := range skips {
		out = append(out, engine.Skip{Path: sk.Path, Reason: sk.Reason})
	}
	return out
}

func (s *scan) Finish(ctx engine.TargetContext) []engine.Finding {
	rs := assess.Assess(s.findings, assess.Context{
		Read:   func(p string) []byte { return s.files[p] },
		Exists: ctx.Exists,
		Env:    ctx.Env(),
	})
	out := make([]engine.Finding, 0, len(rs))
	for _, r := range rs {
		out = append(out, finding(r))
	}
	return out
}

var verdicts = map[assess.Status]engine.Verdict{
	assess.Active:   engine.Vulnerable,
	assess.Inactive: engine.Inactive,
	assess.Platform: engine.Managed,
}

func finding(r assess.Result) engine.Finding {
	facts := map[string]string{}
	if r.SPKI != "" {
		facts["spki_sha256"] = r.SPKI
	}
	if r.CertHash != "" {
		facts["cert_sha256"] = r.CertHash
	}
	if r.Subject != "" {
		facts["subject"] = r.Subject
	}
	v, ok := verdicts[r.Status]
	if !ok {
		v = engine.Unknown
	}
	return engine.Finding{
		Kind:    string(r.Kind),
		Path:    r.Path,
		Verdict: v,
		Reason:  r.Reason,
		Message: r.Detail,
		Method:  r.Method,
		Facts:   facts,
		Details: r.Finding,
	}
}
