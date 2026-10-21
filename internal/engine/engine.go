// Package engine defines what a detector is and runs detectors over a target.
//
// The engine reads each target once and hands every file to each detector that
// supports that kind of target. Detectors decide verdicts. The engine decides
// nothing about any vulnerability itself, but it does enforce one rule for every
// detector: a finding can only be cleared (fixed, inactive or managed) with a
// reason attached.
package engine

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Verdict is a finding's outcome.
type Verdict string

const (
	// Vulnerable: proven exposed.
	Vulnerable Verdict = "vulnerable"
	// Unknown: the evidence does not settle it. The reason says what to check.
	Unknown Verdict = "unknown"
	// Fixed: proven to have the fix.
	Fixed Verdict = "fixed"
	// Inactive: present but provably not used.
	Inactive Verdict = "inactive"
	// Managed: another layer decides (an OS keychain, a browser's blocklist).
	// Listed, not counted.
	Managed Verdict = "managed"
)

// Cleared reports whether v takes a finding off the list of things to act on.
func (v Verdict) Cleared() bool { return v == Fixed || v == Inactive || v == Managed }

// TargetKind is a kind of thing the engine scans.
type TargetKind string

const (
	Filesystem TargetKind = "filesystem"
	Image      TargetKind = "image"
	Host       TargetKind = "host"
	Repository TargetKind = "repository"
)

// Kind is one type of finding a detector reports.
type Kind struct {
	ID    string // stable, used in SARIF rule IDs as "<detector>/<kind>"
	Title string
	// Level is the SARIF level for a vulnerable finding: "error" or "warning".
	Level string
	// Description explains the kind in a sentence or two (SARIF fullDescription).
	Description string
	// SecuritySeverity is the CVSS-style score code scanners sort by ("9.2").
	SecuritySeverity string
	CWEs             []string
}

// Manifest describes a detector.
type Manifest struct {
	ID         string
	Title      string
	CVEs       []string
	Advisories []string // URLs; the first is the SARIF help link
	Disclosed  string   // YYYY-MM-DD
	Targets    []TargetKind
	Kinds      []Kind
	Tags       []string
	// Archives asks the engine to unpack archives and packages (jar, whl, deb,
	// rpm, compressed files, PyInstaller executables) and hand every member to
	// Visit as "outer!/inner".
	Archives bool
	// Data identifies the detector's knowledge snapshot, for the report.
	Data string
}

// Supports reports whether the detector runs on kind.
func (m Manifest) Supports(kind TargetKind) bool {
	for _, k := range m.Targets {
		if k == kind {
			return true
		}
	}
	return false
}

// CVEResult is one CVE's verdict inside a finding that covers several.
type CVEResult struct {
	ID      string  `json:"id"`
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason,omitempty"`
}

// Finding is one proven fact about a target.
type Finding struct {
	Detector string  `json:"detector"`
	Kind     string  `json:"kind"`
	Path     string  `json:"path"`
	Line     int     `json:"line,omitempty"` // for findings in source files
	Verdict  Verdict `json:"verdict"`
	Reason   string  `json:"reason,omitempty"`
	// Message is the exact fact, in words.
	Message string `json:"message"`
	// Method says how it was found (pem, pkcs12, go-buildinfo, elf-strings...).
	Method string `json:"method,omitempty"`
	// Facts are short checkable values (hashes, versions), also written to SARIF.
	Facts map[string]string `json:"facts,omitempty"`
	CVEs  []CVEResult       `json:"cves,omitempty"`
	Fix   string            `json:"fix,omitempty"`
	// Severity, when set, overrides the kind's SARIF level for this finding:
	// critical and high are errors, medium and low warnings.
	Severity string `json:"severity,omitempty"`
	// Details is the detector's own record of the finding, kept whole.
	Details any `json:"details,omitempty"`
}

// File is one file handed to a detector. Path is absolute within the target;
// archive members are "outer!/inner".
type File struct {
	Path       string
	Data       []byte
	Executable bool
	// Member is true for a file found inside an archive or package.
	Member bool
}

// Skip records something a detector could not check, and why.
type Skip struct {
	Path   string
	Reason string
	failed bool // set by the engine when the detector panicked
}

// TargetContext is what a detector can ask about the rest of the target when
// it decides verdicts.
type TargetContext interface {
	Kind() TargetKind
	// Exists reports whether a regular file at that absolute path was scanned.
	Exists(path string) bool
	// Env is the image configuration's environment ("KEY=value"), nil otherwise.
	Env() []string
	// Aliases returns every path that names the same file as p (symlinks, hard
	// links), p included.
	Aliases(p string) []string
	// Links returns every symlink (path -> target as written) and hard link
	// (path -> path it names) seen in the walk, for detectors that resolve
	// them their own way.
	Links() (symlinks, hardlinks map[string]string)
	// SystemRoot is the OS path of the system root when a directory below it
	// was scanned, so a detector can read the root's package databases. It is
	// empty for images and for walks that start at the root.
	SystemRoot() string
	// Problem records something read only partly (a damaged package database).
	Problem(msg string)
	// Annotate records a fact about the whole target, such as its OS release.
	Annotate(key string, v any)
}

// Scan is one detector's work on one target. Visit sees every file the engine
// reads; a detector keeps the few file contents its verdicts need. Finish runs
// once, after the last file.
type Scan interface {
	Visit(f File) []Skip
	Finish(ctx TargetContext) []Finding
}

// Detector is a detector registered with the engine.
type Detector interface {
	Manifest() Manifest
	// Load parses and checks the detector's embedded data. An error means the
	// data contradicts itself and the engine refuses to run.
	Load() error
	// NewScan starts a scan of one filesystem or image target.
	NewScan(kind TargetKind) Scan
}

// Reader is implemented by detectors that only need some files read in full.
// A detector without it receives every file.
type Reader interface {
	Wants(path string, head []byte, executable bool) bool
}

// Prober is implemented by detectors that check live network hosts.
type Prober interface {
	// Probe connects to addr and returns the name it resolved to, how many items
	// it checked (certificates, responses) and what it found.
	Probe(ctx context.Context, addr string, timeout time.Duration) (target string, checked int, findings []Finding, err error)
}

var registry = map[string]Detector{}

// Register adds a detector. It panics on a duplicate ID, which is a build error.
func Register(d Detector) {
	id := d.Manifest().ID
	if _, dup := registry[id]; dup {
		panic("engine: detector registered twice: " + id)
	}
	registry[id] = d
}

// Detectors returns every registered detector, sorted by ID.
func Detectors() []Detector {
	out := make([]Detector, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest().ID < out[j].Manifest().ID })
	return out
}

// Select returns the detectors with the given IDs, or all of them when ids is
// empty, and loads each one.
func Select(ids []string) ([]Detector, error) {
	var out []Detector
	if len(ids) == 0 {
		out = Detectors()
	} else {
		for _, id := range ids {
			d, ok := registry[id]
			if !ok {
				return nil, fmt.Errorf("unknown detector %q", id)
			}
			out = append(out, d)
		}
	}
	for _, d := range out {
		if err := d.Load(); err != nil {
			return nil, fmt.Errorf("detector %s: %w", d.Manifest().ID, err)
		}
	}
	return out, nil
}

// check enforces the evidence rule on a detector's findings.
func check(id string, fs []Finding) []Finding {
	for i := range fs {
		f := &fs[i]
		f.Detector = id
		if f.Verdict == "" {
			f.Verdict = Unknown
			f.Reason = "the detector gave no verdict"
		}
		if f.Verdict.Cleared() && f.Reason == "" {
			f.Verdict = Unknown
			f.Reason = "the detector cleared this without saying why, so it is not counted as cleared"
		}
	}
	return fs
}
