package cli

import (
	"github.com/DefectDojo/earlylight/internal/engine"
)

// CatalogSchema changes only when a field is removed or changes meaning. New
// fields are added without changing it.
const CatalogSchema = 1

// Catalog is what "earlylight detectors --format json" prints. Each release
// attaches it as detectors.json, so DefectDojo can tell which detectors a
// release contains without downloading and running a binary.
type Catalog struct {
	Schema    int            `json:"schema"`
	Tool      string         `json:"tool"`
	Version   string         `json:"version"`
	Detectors []CatalogEntry `json:"detectors"`
}

// CatalogEntry is one detector, taken from its manifest.
type CatalogEntry struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	CVEs       []string `json:"cves"`
	Advisories []string `json:"advisories"`
	Disclosed  string   `json:"disclosed"`
	// Modes are the commands that run the detector: fs, image, host, repo, fix.
	Modes []string      `json:"modes"`
	Kinds []CatalogKind `json:"kinds"`
	Tags  []string      `json:"tags"`
	Data  string        `json:"data,omitempty"`
}

// CatalogKind is one type of finding. Its SARIF rule ID is "<detector>/<id>".
type CatalogKind struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Level       string   `json:"level"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
}

// modeOf is the command for each target kind, in the order the usage text
// lists them.
var modeOf = []struct {
	kind engine.TargetKind
	mode string
}{{engine.Filesystem, "fs"}, {engine.Image, "image"}, {engine.Host, "host"}, {engine.Repository, "repo"}}

// catalog describes every registered detector. Lists are never null, so a
// reader can range over them without checking.
func (c Config) catalog() Catalog {
	out := Catalog{Schema: CatalogSchema, Tool: c.Tool, Version: c.version(), Detectors: []CatalogEntry{}}
	for _, d := range engine.Detectors() {
		m := d.Manifest()
		e := CatalogEntry{ID: m.ID, Title: m.Title, CVEs: nonNil(m.CVEs), Advisories: nonNil(m.Advisories),
			Disclosed: m.Disclosed, Modes: []string{}, Kinds: []CatalogKind{}, Tags: nonNil(m.Tags), Data: m.Data}
		for _, k := range modeOf {
			if m.Supports(k.kind) {
				e.Modes = append(e.Modes, k.mode)
			}
		}
		if _, ok := d.(engine.Fixer); ok && m.Supports(engine.Repository) {
			e.Modes = append(e.Modes, "fix")
		}
		for _, k := range m.Kinds {
			e.Kinds = append(e.Kinds, CatalogKind{ID: k.ID, Title: k.Title, Level: k.Level, Description: k.Description,
				Severity: k.SecuritySeverity, CWEs: k.CWEs})
		}
		out.Detectors = append(out.Detectors, e)
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
