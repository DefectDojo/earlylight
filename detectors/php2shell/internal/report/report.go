// Package report renders scan results as text, JSON or SARIF.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/source"
)

// RefFinding is the verdict for an image reference in source code (a Dockerfile
// FROM line, a Compose or Kubernetes image, a CI container).
type RefFinding struct {
	File      string        `json:"file"`
	Line      int           `json:"line"`
	Kind      string        `json:"kind"`
	Image     string        `json:"image"`
	Status    assess.Status `json:"status"`
	Severity  string        `json:"severity"`
	Reason    string        `json:"reason"`
	Platforms []string      `json:"platforms,omitempty"`
	Fix       string        `json:"fix,omitempty"`
}

// Target is one scanned thing: a directory, an image or a source repository.
type Target struct {
	Name     string               `json:"target"`
	Type     string               `json:"type"` // "filesystem", "image" or "repository"
	Digest   string               `json:"digest,omitempty"`
	Platform string               `json:"platform,omitempty"`
	Root     string               `json:"root,omitempty"` // SARIF paths are relative to it
	OS       *knowledge.OSRelease `json:"os,omitempty"`
	Files    int                  `json:"files_scanned"`
	Findings []assess.Finding     `json:"findings"`
	Refs     []RefFinding         `json:"references,omitempty"`
	// RefsChecked counts image references examined in a repository scan,
	// including those that are not PHP.
	RefsChecked int           `json:"references_checked,omitempty"`
	Skipped     []source.Skip `json:"skipped"`
	// Problems lists package databases that could not be read fully.
	Problems []string `json:"problems,omitempty"`
	// Incomplete says why the scan could not finish (a registry failed). The
	// results are shown but are not the whole picture, and the exit status is 2.
	Incomplete string `json:"incomplete,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Count returns how many findings and references have status st.
func (t *Target) Count(st assess.Status) int {
	n := 0
	for _, f := range t.Findings {
		if f.Status == st {
			n++
		}
	}
	for _, r := range t.Refs {
		if r.Status == st {
			n++
		}
	}
	return n
}

// Gaps counts skipped items that are real coverage gaps, not deliberate exclusions.
func (t *Target) Gaps() int {
	n := 0
	for _, s := range t.Skipped {
		if !s.Excluded {
			n++
		}
	}
	return n
}

// Report is the whole run.
type Report struct {
	Tool    string   `json:"tool"`
	Version string   `json:"version"`
	CVEs    []string `json:"cves"`
	// DataSnapshot is when the distribution fix data was collected.
	DataSnapshot string    `json:"data_snapshot"`
	Targets      []*Target `json:"targets"`
}

func tag(st assess.Status) string {
	switch st {
	case assess.Vulnerable:
		return "VULNERABLE"
	case assess.Unknown:
		return "UNKNOWN   "
	}
	return "fixed     "
}

// Text writes a human-readable report.
func Text(w io.Writer, r *Report, showFixed, showSkipped bool) {
	fmt.Fprintf(w, "%s %s  (%s; distribution data from %s)\n", r.Tool, r.Version, strings.Join(r.CVEs, ", "), r.DataSnapshot)
	for _, t := range r.Targets {
		fmt.Fprintf(w, "\n== %s (%s)", safe(t.Name), t.Type)
		if t.Platform != "" {
			fmt.Fprintf(w, " %s", safe(t.Platform))
		}
		if t.Digest != "" {
			fmt.Fprintf(w, " %s", safe(t.Digest))
		}
		fmt.Fprintln(w)
		if t.Error != "" {
			fmt.Fprintf(w, "   ERROR: %s\n", safe(t.Error))
			continue
		}
		if t.Incomplete != "" {
			fmt.Fprintf(w, "   INCOMPLETE: %s\n", safe(t.Incomplete))
		}
		vuln, unk, fixed := t.Count(assess.Vulnerable), t.Count(assess.Unknown), t.Count(assess.Fixed)
		what := fmt.Sprintf("%d PHP runtime(s) in %d files", len(t.Findings), t.Files)
		if t.Type == "repository" {
			what = fmt.Sprintf("%d PHP image reference(s) among %d image references", len(t.Refs), t.RefsChecked)
		}
		switch {
		case vuln > 0:
			fmt.Fprintf(w, "   VULNERABLE: %d vulnerable, %d unknown, %d fixed (%s)\n", vuln, unk, fixed, what)
		case unk > 0:
			fmt.Fprintf(w, "   UNKNOWN: %d could not be settled, %d fixed (%s)\n", unk, fixed, what)
		case len(t.Findings)+len(t.Refs) == 0:
			fmt.Fprintf(w, "   OK: no PHP found (%s)\n", what)
		default:
			fmt.Fprintf(w, "   OK: all fixed (%s)\n", what)
		}
		rank := map[assess.Status]int{assess.Vulnerable: 0, assess.Unknown: 1, assess.Fixed: 2}
		fs := append([]assess.Finding(nil), t.Findings...)
		sort.SliceStable(fs, func(i, j int) bool {
			if fs[i].Status != fs[j].Status {
				return rank[fs[i].Status] < rank[fs[j].Status]
			}
			return fs[i].Path < fs[j].Path
		})
		for _, f := range fs {
			if f.Status == assess.Fixed && !showFixed {
				continue
			}
			fmt.Fprintf(w, "   [%s] %s  PHP %s (%s)\n", tag(f.Status), safe(f.Path), safe(f.PHPVersion), safe(f.SAPI))
			fmt.Fprintf(w, "                %s\n", safe(f.Reason))
			if f.Fix != "" {
				fmt.Fprintf(w, "                Fix: %s\n", safe(f.Fix))
			}
		}
		rs := append([]RefFinding(nil), t.Refs...)
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].Status != rs[j].Status {
				return rank[rs[i].Status] < rank[rs[j].Status]
			}
			if rs[i].File != rs[j].File {
				return rs[i].File < rs[j].File
			}
			return rs[i].Line < rs[j].Line
		})
		for _, x := range rs {
			if x.Status == assess.Fixed && !showFixed {
				continue
			}
			fmt.Fprintf(w, "   [%s] %s:%d  %s\n", tag(x.Status), safe(x.File), x.Line, safe(x.Image))
			fmt.Fprintf(w, "                %s\n", safe(x.Reason))
			if x.Fix != "" {
				fmt.Fprintf(w, "                Fix: %s\n", safe(x.Fix))
			}
		}
		if fixed > 0 && !showFixed {
			fmt.Fprintf(w, "   %d fixed item(s) hidden (use --show-fixed)\n", fixed)
		}
		for _, p := range t.Problems {
			fmt.Fprintf(w, "   PROBLEM: %s\n", safe(p))
		}
		if len(t.Skipped) > 0 {
			fmt.Fprintf(w, "   NOTE: %d item(s) were not scanned (%d coverage gaps, the rest deliberate exclusions); they are not covered by this result", len(t.Skipped), t.Gaps())
			if showSkipped {
				fmt.Fprintln(w, ":")
				for _, s := range t.Skipped {
					fmt.Fprintf(w, "     %s: %s\n", safe(s.Path), safe(s.Reason))
				}
			} else {
				fmt.Fprintln(w, " (use --show-skipped)")
			}
		}
	}
}

// safe quotes text that contains control or other non-graphic characters, so file
// names from a scanned image cannot inject terminal escape sequences or forge
// extra report lines.
func safe(s string) string {
	// Invalid UTF-8 decodes to U+FFFD, which counts as graphic, so raw bytes such
	// as an 8-bit CSI (0x9b) would slip through the rune check below.
	if !utf8.ValidString(s) {
		return strconv.QuoteToGraphic(s)
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return strconv.QuoteToGraphic(s)
		}
	}
	return s
}

// JSON writes the full report. Empty lists are written as [] rather than null.
func JSON(w io.Writer, r *Report) error {
	for _, t := range r.Targets {
		if t.Findings == nil {
			t.Findings = []assess.Finding{}
		}
		if t.Skipped == nil {
			t.Skipped = []source.Skip{}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Rule IDs. Each starts with the first CVE so importers that take a CVE from the
// rule ID (DefectDojo does) record it; both CVEs are in every message and tag
// list. A runtime that serves web requests and an image reference rank critical,
// the CLI high, and an unknown verdict is informational: it asks for a check.
const (
	RuleRuntimeWeb     = "CVE-2026-109618/php-runtime-web"
	RuleRuntimeCLI     = "CVE-2026-109618/php-runtime-cli"
	RuleImage          = "CVE-2026-109618/php-image"
	RuleRuntimeUnknown = "php2shell/php-runtime-unknown"
	RuleImageUnknown   = "php2shell/php-image-unknown"
)

// SARIF writes vulnerable and unknown results as SARIF 2.1.0, which DefectDojo
// and most code-scanning tools import.
func SARIF(w io.Writer, r *Report) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		FullDescription  msg            `json:"fullDescription"`
		HelpURI          string         `json:"helpUri"`
		Properties       map[string]any `json:"properties"`
	}
	type region struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type physical struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *region `json:"region,omitempty"`
	}
	type location struct {
		PhysicalLocation physical `json:"physicalLocation"`
	}
	type fix struct {
		Description msg `json:"description"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations"`
		// Fingerprints identify a result across runs without its line or message,
		// which change when lines move or a registry finishes publishing.
		// DefectDojo deduplicates SARIF on the first fingerprint.
		Fingerprints map[string]string `json:"fingerprints"`
		Fixes        []fix             `json:"fixes,omitempty"`
		Properties   map[string]any    `json:"properties,omitempty"`
	}
	seen := map[string]int{}
	fingerprint := func(parts ...string) map[string]string {
		k := strings.Join(parts, "\x00")
		seen[k]++
		h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", k, seen[k])))
		return map[string]string{"php2shell/v1": hex.EncodeToString(h[:])}
	}
	cves := strings.Join(knowledge.CVEIDs(), " and ")
	tags := append([]string{"security", "php", "PHP2Shell"}, knowledge.CVEIDs()...)
	about := "PHP's October 21, 2026 security releases (8.2.35, 8.3.36, 8.4.27 and 8.5.12) fix " + cves +
		", two remote code execution flaws in the PHP engine reachable before any application code runs. " +
		"Advisories: " + knowledge.CVEs[0].URL + " and " + knowledge.CVEs[1].URL + "."
	mk := func(id, name, desc, sev string) rule {
		return rule{ID: id, Name: name, ShortDescription: msg{name}, FullDescription: msg{desc + " " + about}, HelpURI: knowledge.CVEs[0].URL,
			Properties: map[string]any{"tags": tags, "security-severity": sev, "cwe": []string{"CWE-416", "CWE-824"}}}
	}
	rules := []rule{
		mk(RuleRuntimeWeb, "PHP runtime serving web requests is vulnerable to "+cves, "A PHP runtime that serves web requests (PHP-FPM, CGI, the Apache module, LiteSpeed or FrankenPHP) without the fix.", "9.2"),
		mk(RuleRuntimeCLI, "PHP CLI or embedded runtime is vulnerable to "+cves, "A PHP command-line or embedded runtime without the fix. It is exposed when it serves requests (php -S, a worker) or handles untrusted input.", "7.5"),
		mk(RuleImage, "Container image with PHP vulnerable to "+cves, "An image reference that resolves to a PHP build without the fix. Images built from it, and containers running them, are vulnerable.", "9.2"),
		mk(RuleRuntimeUnknown, "PHP runtime whose fix status for "+cves+" could not be determined", "A PHP runtime this tool could not settle, usually one installed by a vendor package whose fix it has no data for. Check the vendor's advisory.", "Info"),
		mk(RuleImageUnknown, "Container image whose PHP fix status for "+cves+" could not be determined", "An image reference whose PHP version could not be settled.", "Info"),
	}
	results := []result{}
	var notes []map[string]any
	ok := true
	for _, t := range r.Targets {
		if t.Error != "" {
			ok = false
			notes = append(notes, map[string]any{"level": "error", "message": msg{t.Name + ": " + t.Error}})
		}
		if t.Incomplete != "" {
			ok = false
			notes = append(notes, map[string]any{"level": "error", "message": msg{t.Name + ": incomplete: " + t.Incomplete}})
		}
		if g := t.Gaps(); g > 0 {
			notes = append(notes, map[string]any{"level": "warning", "message": msg{fmt.Sprintf("%s: %d item(s) could not be scanned and are not covered", t.Name, g)}})
		}
		for _, p := range t.Problems {
			notes = append(notes, map[string]any{"level": "warning", "message": msg{t.Name + ": " + p}})
		}
		for _, f := range t.Findings {
			if f.Status == assess.Fixed {
				continue
			}
			id, level, verdict := RuleRuntimeCLI, "error", "vulnerable to "+cves
			switch {
			case f.Status == assess.Unknown:
				id, level, verdict = RuleRuntimeUnknown, "note", "fix status for "+cves+" unknown"
			case f.WebFacing:
				id = RuleRuntimeWeb
			}
			uri := f.Path
			if t.Type == "filesystem" && t.Root != "" {
				uri = strings.TrimPrefix(uri, t.Root)
			}
			var loc location
			loc.PhysicalLocation.ArtifactLocation.URI = strings.TrimPrefix(uri, "/")
			text := fmt.Sprintf("PHP %s (%s) at %s is %s. %s", f.PHPVersion, f.SAPI, f.Path, verdict, f.Reason)
			props := map[string]any{"target": t.Name, "php_version": f.PHPVersion, "sapi": f.SAPI, "cves": knowledge.CVEIDs(), "status": f.Status}
			if f.Package != nil {
				props["package"] = f.Package.Name + " " + f.Package.Version
			}
			res := result{RuleID: id, Level: level, Message: msg{text}, Locations: []location{loc}, Properties: props,
				Fingerprints: fingerprint(id, t.Type, t.Name, f.Path)}
			if f.Fix != "" {
				res.Fixes = []fix{{msg{f.Fix}}}
			}
			results = append(results, res)
		}
		for _, x := range t.Refs {
			if x.Status == assess.Fixed {
				continue
			}
			id, level, verdict := RuleImage, "error", "has PHP vulnerable to "+cves
			if x.Status == assess.Unknown {
				id, level, verdict = RuleImageUnknown, "note", "has PHP whose fix status for "+cves+" is unknown"
			}
			var loc location
			loc.PhysicalLocation.ArtifactLocation.URI = x.File
			if x.Line > 0 {
				loc.PhysicalLocation.Region = &region{StartLine: x.Line}
			}
			text := fmt.Sprintf("Image %s %s. %s", x.Image, verdict, x.Reason)
			props := map[string]any{"image": x.Image, "kind": x.Kind, "cves": knowledge.CVEIDs(), "status": x.Status}
			if len(x.Platforms) > 0 {
				props["platforms"] = x.Platforms
			}
			res := result{RuleID: id, Level: level, Message: msg{text}, Locations: []location{loc}, Properties: props,
				Fingerprints: fingerprint(id, x.File, x.Kind, x.Image)}
			if x.Fix != "" {
				res.Fixes = []fix{{msg{x.Fix}}}
			}
			results = append(results, res)
		}
	}
	inv := map[string]any{"executionSuccessful": ok}
	if len(notes) > 0 {
		inv["toolExecutionNotifications"] = notes
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": r.Tool, "version": r.Version, "informationUri": "https://github.com/DefectDojo/php2shell-scan", "rules": rules,
			}},
			"results":     results,
			"invocations": []any{inv},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
