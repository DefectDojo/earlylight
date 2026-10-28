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

	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/source"
)

// DetectorInfo is what the report says about each detector that ran.
type DetectorInfo struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CVEs       []string `json:"cves,omitempty"`
	Advisories []string `json:"advisories,omitempty"`
	Data       string   `json:"data,omitempty"`
}

// Report is the whole run.
type Report struct {
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	Detectors []DetectorInfo   `json:"detectors"`
	Targets   []*engine.Target `json:"targets"`

	manifests []engine.Manifest
}

// New starts a report for the detectors that will run.
func New(tool, version string, dets []engine.Detector) *Report {
	r := &Report{Tool: tool, Version: version}
	for _, d := range dets {
		m := d.Manifest()
		r.manifests = append(r.manifests, m)
		r.Detectors = append(r.Detectors, DetectorInfo{ID: m.ID, Title: m.Title, CVEs: m.CVEs, Advisories: m.Advisories, Data: m.Data})
	}
	return r
}

// Options control the text report.
type Options struct {
	ShowCleared bool // list fixed and inactive findings
	ShowSkipped bool // list every file that could not be scanned
}

var rank = map[engine.Verdict]int{engine.Vulnerable: 0, engine.Unknown: 1, engine.Managed: 2, engine.Inactive: 3, engine.Fixed: 4}

var tags = map[engine.Verdict]string{
	engine.Vulnerable: "VULNERABLE",
	engine.Unknown:    "unknown   ",
	engine.Managed:    "managed   ",
	engine.Inactive:   "inactive  ",
	engine.Fixed:      "fixed     ",
}

// Text writes a human-readable report.
func Text(w io.Writer, r *Report, o Options) {
	fmt.Fprintf(w, "%s %s\n", r.Tool, r.Version)
	for _, d := range r.Detectors {
		fmt.Fprintf(w, "detector %s: %s", d.ID, d.Title)
		if d.Data != "" {
			fmt.Fprintf(w, " (%s)", d.Data)
		}
		fmt.Fprintln(w)
	}
	for _, t := range r.Targets {
		fmt.Fprintf(w, "\n== %s (%s)", safe(t.Name), t.Type)
		if t.Digest != "" {
			fmt.Fprintf(w, " %s", safe(t.Digest))
		}
		if t.Platform != "" {
			fmt.Fprintf(w, " %s", safe(t.Platform))
		}
		fmt.Fprintln(w)
		if t.Error != "" {
			fmt.Fprintf(w, "   ERROR: %s\n", safe(t.Error))
			continue
		}
		if t.Incomplete != "" {
			fmt.Fprintf(w, "   INCOMPLETE: %s\n", safe(t.Incomplete))
		}
		unit := "files"
		switch t.Type {
		case engine.Host:
			unit = "items checked"
		case engine.Repository:
			unit = "image references and files"
		}
		vuln, unk := t.Count(engine.Vulnerable), t.Count(engine.Unknown)
		switch {
		case vuln > 0:
			fmt.Fprintf(w, "   AFFECTED: %d vulnerable finding(s) in %d %s\n", vuln, t.Files, unit)
		case unk > 0:
			fmt.Fprintf(w, "   UNKNOWN: nothing proven vulnerable in %d %s, but %d finding(s) could not be settled\n", t.Files, unit, unk)
		default:
			fmt.Fprintf(w, "   OK: no vulnerable findings in %d %s\n", t.Files, unit)
		}
		fs := append([]engine.Finding(nil), t.Findings...)
		sort.SliceStable(fs, func(i, j int) bool {
			if fs[i].Verdict != fs[j].Verdict {
				return rank[fs[i].Verdict] < rank[fs[j].Verdict]
			}
			return fs[i].Path < fs[j].Path
		})
		hidden := 0
		for _, f := range fs {
			if (f.Verdict == engine.Inactive || f.Verdict == engine.Fixed) && !o.ShowCleared {
				hidden++
				continue
			}
			where := safe(f.Path)
			if f.Line > 0 {
				where += fmt.Sprintf(":%d", f.Line)
			}
			fmt.Fprintf(w, "   [%s] %s\n               %s/%s: %s\n", tags[f.Verdict], where, f.Detector, f.Kind, safe(f.Message))
			if f.Reason != "" {
				fmt.Fprintf(w, "               (%s)\n", safe(f.Reason))
			}
			for _, c := range f.CVEs {
				fmt.Fprintf(w, "               %s: %s", c.ID, c.Verdict)
				if c.Reason != "" {
					fmt.Fprintf(w, " (%s)", safe(c.Reason))
				}
				fmt.Fprintln(w)
			}
			if f.Fix != "" {
				fmt.Fprintf(w, "               fix: %s\n", safe(f.Fix))
			}
		}
		if m := t.Count(engine.Managed); m > 0 {
			fmt.Fprintf(w, "   %d managed finding(s) listed but not counted: the OS or browser decides that trust with its own blocklist\n", m)
		}
		for _, p := range t.Problems {
			fmt.Fprintf(w, "   PROBLEM: %s\n", safe(p))
		}
		if hidden > 0 {
			fmt.Fprintf(w, "   %d cleared finding(s) hidden: proven fixed, or copies provably not used (use --show-cleared)\n", hidden)
		}
		if len(t.Skipped) > 0 {
			fmt.Fprintf(w, "   NOTE: %d item(s) were not scanned (%d coverage gaps, the rest deliberate exclusions or test fixtures); they are not covered by this result", len(t.Skipped), t.Gaps())
			if o.ShowSkipped {
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
// names and certificate fields from a scanned image cannot inject terminal escape
// sequences or forge extra report lines.
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
			t.Findings = []engine.Finding{}
		}
		if t.Skipped == nil {
			t.Skipped = []source.Skip{}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// SARIF writes vulnerable and unknown findings as SARIF 2.1.0, which DefectDojo
// and most code scanning tools import. Rule IDs are "<detector>/<kind>". Every
// result has a fingerprint that stays the same across runs (DefectDojo
// deduplicates on it) and does not depend on line numbers or wording.
func SARIF(w io.Writer, r *Report) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string         `json:"id"`
		Name             string         `json:"name"`
		ShortDescription msg            `json:"shortDescription"`
		FullDescription  *msg           `json:"fullDescription,omitempty"`
		HelpURI          string         `json:"helpUri,omitempty"`
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
		RuleID       string            `json:"ruleId"`
		Level        string            `json:"level"`
		Message      msg               `json:"message"`
		Locations    []location        `json:"locations"`
		Fingerprints map[string]string `json:"fingerprints"`
		Fixes        []fix             `json:"fixes,omitempty"`
		Properties   map[string]any    `json:"properties,omitempty"`
	}
	rules := []rule{}
	levels := map[string]string{}
	for _, m := range r.manifests {
		help := ""
		if len(m.Advisories) > 0 {
			help = m.Advisories[0]
		}
		for _, k := range m.Kinds {
			id := m.ID + "/" + k.ID
			props := map[string]any{}
			if len(m.Tags) > 0 {
				props["tags"] = append(append([]string{}, m.Tags...), m.CVEs...)
			}
			if k.SecuritySeverity != "" {
				props["security-severity"] = k.SecuritySeverity
			}
			if len(k.CWEs) > 0 {
				props["cwe"] = k.CWEs
			}
			ru := rule{ID: id, Name: k.Title, ShortDescription: msg{k.Title}, HelpURI: help, Properties: props}
			if k.Description != "" {
				ru.FullDescription = &msg{k.Description}
			}
			rules = append(rules, ru)
			levels[id] = k.Level
		}
	}
	seen := map[string]int{}
	fingerprint := func(parts ...string) map[string]string {
		k := strings.Join(parts, "\x00")
		seen[k]++
		h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", k, seen[k])))
		return map[string]string{"earlylight/v1": hex.EncodeToString(h[:])}
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
			notes = append(notes, map[string]any{"level": "warning", "message": msg{fmt.Sprintf("%s: %d file(s) could not be scanned and are not covered", t.Name, g)}})
		}
		for _, p := range t.Problems {
			notes = append(notes, map[string]any{"level": "warning", "message": msg{t.Name + ": " + p}})
		}
		for _, f := range t.Findings {
			if f.Verdict != engine.Vulnerable && f.Verdict != engine.Unknown {
				continue
			}
			id := f.Detector + "/" + f.Kind
			level := levels[id]
			switch f.Severity {
			case "critical", "high":
				level = "error"
			case "medium", "low":
				level = "warning"
			}
			if level == "" {
				level = "error"
			}
			text := f.Message
			if f.Reason != "" {
				text += ". " + f.Reason
			}
			if f.Verdict == engine.Unknown {
				level = "note"
				text = "Could not be settled: " + text
			}
			var loc location
			uri := f.Path
			switch t.Type {
			case engine.Filesystem:
				if t.Root != "" {
					uri = strings.TrimPrefix(strings.TrimPrefix(uri, t.Root), "/")
				} else {
					uri = strings.TrimPrefix(uri, "/")
				}
			case engine.Image:
				uri = strings.TrimPrefix(uri, "/")
			case engine.Host:
				uri = "https://" + t.Name + "/"
			}
			loc.PhysicalLocation.ArtifactLocation.URI = uri
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &region{StartLine: f.Line}
			}
			props := map[string]any{"target": t.Name, "verdict": string(f.Verdict)}
			keys := make([]string, 0, len(f.Facts))
			for k, v := range f.Facts {
				props[k] = v
				keys = append(keys, k+"="+v)
			}
			sort.Strings(keys)
			if len(f.CVEs) > 0 {
				cv := map[string]string{}
				for _, c := range f.CVEs {
					cv[c.ID] = string(c.Verdict)
				}
				props["cves"] = cv
			}
			res := result{RuleID: id, Level: level, Message: msg{text}, Locations: []location{loc}, Properties: props,
				Fingerprints: fingerprint(append([]string{id, string(t.Type), t.Name, f.Path}, keys...)...)}
			if f.Fix != "" {
				res.Fixes = []fix{{msg{f.Fix}}}
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
				"name": r.Tool, "version": r.Version, "informationUri": "https://github.com/DefectDojo/earlylight", "rules": rules,
			}},
			"results":     results,
			"invocations": []any{inv},
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
