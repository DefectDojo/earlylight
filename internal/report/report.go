// Package report renders scan results as text, JSON or SARIF.
package report

import (
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
	ids := make([]string, 0, len(r.Detectors))
	for _, d := range r.Detectors {
		ids = append(ids, d.ID)
	}
	fmt.Fprintf(w, "detectors: %s\n", strings.Join(ids, ", "))
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
		unit := "files"
		if t.Type == engine.Host {
			unit = "items checked"
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
			fmt.Fprintf(w, "   [%s] %s\n               %s/%s: %s\n", tags[f.Verdict], safe(f.Path), f.Detector, f.Kind, safe(f.Message))
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
// and most code scanning tools import. Rule IDs are "<detector>/<kind>".
func SARIF(w io.Writer, r *Report) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription msg    `json:"shortDescription"`
		HelpURI          string `json:"helpUri,omitempty"`
		Properties       struct {
			Tags []string `json:"tags,omitempty"`
			CVEs []string `json:"cves,omitempty"`
		} `json:"properties"`
	}
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation artifactLocation `json:"artifactLocation"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID     string            `json:"ruleId"`
		Level      string            `json:"level"`
		Message    msg               `json:"message"`
		Locations  []location        `json:"locations"`
		Properties map[string]string `json:"properties,omitempty"`
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
			ru := rule{ID: id, Name: k.Title, ShortDescription: msg{k.Title}, HelpURI: help}
			ru.Properties.Tags = m.Tags
			ru.Properties.CVEs = m.CVEs
			rules = append(rules, ru)
			levels[id] = k.Level
		}
	}
	results := []result{}
	var notes []map[string]any
	ok := true
	for _, t := range r.Targets {
		if t.Error != "" {
			ok = false
			notes = append(notes, map[string]any{"level": "error", "message": msg{t.Name + ": " + t.Error}})
		}
		if g := t.Gaps(); g > 0 {
			notes = append(notes, map[string]any{"level": "warning", "message": msg{fmt.Sprintf("%s: %d file(s) could not be scanned and are not covered", t.Name, g)}})
		}
		for _, f := range t.Findings {
			if f.Verdict != engine.Vulnerable && f.Verdict != engine.Unknown {
				continue
			}
			id := f.Detector + "/" + f.Kind
			level := levels[id]
			if level == "" {
				level = "error"
			}
			text := f.Message
			if f.Verdict == engine.Unknown {
				level = "note"
				text = "Could not be settled: " + f.Message
				if f.Reason != "" {
					text += " (" + f.Reason + ")"
				}
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
			props := map[string]string{"target": t.Name, "verdict": string(f.Verdict)}
			for k, v := range f.Facts {
				props[k] = v
			}
			for _, c := range f.CVEs {
				props[c.ID] = string(c.Verdict)
			}
			results = append(results, result{RuleID: id, Level: level, Message: msg{text}, Locations: []location{loc}, Properties: props})
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
