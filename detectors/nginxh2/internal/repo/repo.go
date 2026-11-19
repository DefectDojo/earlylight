// Package repo finds what in a source tree selects an nginx exposed to
// CVE-2026-123007 and CVE-2026-123633, and plans the edits that fix it:
//
//   - image-pin: a Dockerfile, Compose, Kubernetes, Helm values or CI file
//     names an nginx image (the official image, nginx-unprivileged,
//     OpenResty, Bitnami, ingress-nginx, the F5 NGINX Ingress Controller,
//     Angie) whose tag is a release without the fix, or a Helm chart that
//     deploys ingress-nginx.
//   - os-package: a Dockerfile installs nginx, OpenResty or Angie with apt,
//     apk, dnf, yum, microdnf or zypper, pinned to a release without the
//     fix or from a distribution that had no fixed package.
//   - http2-config: an nginx configuration in the tree turns HTTP/2 on. A
//     setting, not a vulnerable build: it is what makes a vulnerable nginx
//     reachable.
//   - not-checked: what could not be read or decided without reading an
//     image (a moving tag, a digest, a variable).
//
// It knows nothing about the engine.
package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/conf"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// Rules.
const (
	RuleImage      = "image-pin"
	RulePackage    = "os-package"
	RuleHTTP2      = "http2-config"
	RuleNotChecked = "not-checked"
)

// CVEStatus is one CVE's status in a finding.
type CVEStatus struct {
	ID     string           `json:"id"`
	Status knowledge.Status `json:"status"`
	Reason string           `json:"reason"`
}

// Finding is one thing in the tree.
type Finding struct {
	Rule    string            `json:"rule"`
	File    string            `json:"file"`
	Line    int               `json:"line"`
	Level   string            `json:"level"` // error, warning, note
	Status  knowledge.Status  `json:"status"`
	Reason  string            `json:"reason,omitempty"`
	Message string            `json:"message"`
	Fix     string            `json:"fix,omitempty"`
	Fixable bool              `json:"fixable"`
	Props   map[string]string `json:"props,omitempty"`
	CVEs    []CVEStatus       `json:"cves,omitempty"`
	// Pull is set for an image reference only reading the image can
	// decide (a moving tag, a digest).
	Pull string `json:"pull,omitempty"`
	// Platform is the FROM --platform the reference is built for.
	Platform string `json:"platform,omitempty"`
	// Interim is the optional HTTP/2-off edit fix prints and never applies.
	Interim string `json:"interim,omitempty"`
	ref     *refs.Ref
	edit    *tagEdit
	pin     *pinEdit
}

// pinEdit is a package pin to move to the fixed package.
type pinEdit struct {
	old, repl string // "nginx=1.30.6-r0" -> "nginx=1.30.7-r0"
	branch    string
}

// tagEdit is a tag to move.
type tagEdit struct {
	image  string
	family Family
	tag    Tag
	target string // the fixed tag
}

// Skip is a file or reference that was not read, and why.
type Skip struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// Result is a scan of a tree.
type Result struct {
	Findings  []Finding
	Skips     []Skip
	Files     int
	Truncated bool
}

// Options control a scan.
type Options struct {
	// Overlay replaces file contents (repository-relative, slash paths),
	// so a plan can rescan an edit in memory.
	Overlay map[string][]byte
}

const (
	maxFileSize = 4 << 20
	maxFiles    = 200000
	maxFindings = 10000
)

// maxDocs bounds the YAML documents read from one file.
const maxDocs = 1024

var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true, "bower_components": true}

// Scan walks root.
func Scan(ctx context.Context, root string, opts Options) (Result, error) {
	var res Result
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	var list []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			rel, _ := filepath.Rel(root, p)
			res.Skips = append(res.Skips, Skip{File: filepath.ToSlash(rel), Reason: err.Error()})
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		k := kindOf(rel)
		if k == "" {
			return nil
		}
		if !d.Type().IsRegular() {
			if d.Type()&fs.ModeSymlink != 0 {
				res.Skips = append(res.Skips, Skip{File: rel, Reason: "a symbolic link, which is not followed: not checked"})
			}
			return nil
		}
		if len(list) >= maxFiles {
			res.Truncated = true
			return filepath.SkipAll
		}
		list = append(list, rel)
		return nil
	})
	if err != nil {
		return res, err
	}
	for rel := range opts.Overlay {
		if kindOf(rel) != "" && !contains(list, rel) {
			list = append(list, rel)
		}
	}
	sort.Strings(list)
	s := &scanner{root: root, opts: opts, fromImage: map[string]refs.Ref{}, seen: map[string]bool{}, stageMods: map[string]string{}}
	// Image references, with the place they are written.
	rs, rskips, err := refs.ScanFiles(root, list, refs.Options{Overlay: opts.Overlay})
	if err != nil {
		return res, err
	}
	for _, sk := range rskips {
		if mayBeNginx(sk.Text) || sk.Text == "" && sk.Line == 0 {
			res.Skips = append(res.Skips, Skip{File: sk.File, Line: sk.Line, Reason: refs.CleanText(sk.Reason, 300)})
		}
	}
	for i := range rs {
		r := rs[i]
		if r.Kind == refs.KindDockerfile && r.Context == "FROM" {
			s.fromImage[fmt.Sprintf("%s:%d", r.File, r.Line)] = r
		}
		s.seen[r.File+"|"+r.Image] = true
		s.image(&rs[i])
	}
	for _, rel := range list {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		b, ok := opts.Overlay[rel]
		if !ok {
			if b, err = readFile(root, rel); err != nil {
				res.Skips = append(res.Skips, Skip{File: rel, Reason: err.Error()})
				continue
			}
		}
		res.Files++
		switch kindOf(rel) {
		case "dockerfile":
			s.dockerfile(rel, b)
		case "nginx-conf":
			s.config(rel, b)
		case "yaml":
			s.yamlFile(rel, b)
		}
	}
	s.deployments(root)
	res.Findings = append(res.Findings, s.findings...)
	res.Skips = append(res.Skips, s.skips...)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res, nil
}

// deploymentKeys are what a Compose service or Kubernetes container sets
// that changes what the image runs or the configuration it loads.
var deploymentKeys = []string{"command", "entrypoint", "args", "volumes", "volumeMounts", "configs", "environment", "env", "env_file", "envFrom",
	"extends", "volumes_from", "variables"}

// composeOverrides are the files Compose merges into a file of the same
// directory by default.
var composeOverrides = []string{"docker-compose.override.yml", "docker-compose.override.yaml", "compose.override.yml", "compose.override.yaml"}

// deployments records, on each image reference that is read from its
// registry, what the deployment or build changes about it: the image's
// own command and configuration are then not what runs.
func (s *scanner) deployments(root string) {
	docs := map[string][]*yaml.Node{}
	for i := range s.findings {
		f := &s.findings[i]
		if f.Pull == "" || f.ref == nil {
			continue
		}
		r := f.ref
		if r.Kind == refs.KindDockerfile {
			if why := s.stageMods[fmt.Sprintf("%s:%d", r.File, r.Line)]; why != "" {
				f.Props["deployment"] = why
			}
			continue
		}
		if r.Kind == refs.KindHelmValues {
			if why := s.helmTemplates(root, r.File); why != "" {
				f.Props["deployment"] = why
			}
			continue
		}
		if r.Kind != refs.KindCompose && r.Kind != refs.KindKubernetes && r.Kind != refs.KindGitLabCI {
			continue
		}
		load := func(file string) ([]*yaml.Node, bool) {
			if ds, ok := docs[file]; ok {
				return ds, true
			}
			b, found := s.opts.Overlay[file]
			if !found {
				var err error
				if b, err = readFile(root, file); err != nil {
					return nil, false
				}
			}
			var ds []*yaml.Node
			dec := yaml.NewDecoder(strings.NewReader(string(b)))
			for len(ds) < maxDocs {
				var d yaml.Node
				if dec.Decode(&d) != nil {
					break
				}
				ds = append(ds, &d)
			}
			docs[file] = ds
			return ds, true
		}
		ds, ok := load(r.File)
		if !ok {
			f.Props["deployment"] = "the file could not be read again to see what it sets for the image"
			continue
		}
		if r.Kind == refs.KindCompose {
			if why := s.composeOverride(root, r, load); why != "" {
				f.Props["deployment"] = why
				continue
			}
		}
		for _, d := range ds {
			if m := mappingWithImageAt(d, r.Line, 0); m != nil {
				var set []string
				for _, k := range deploymentKeys {
					if mapGet(m, k) != nil {
						set = append(set, k)
					}
				}
				if len(set) > 0 {
					f.Props["deployment"] = fmt.Sprintf("the deployment sets %s for this image, so it may load another configuration or command", strings.Join(set, ", "))
				}
				break
			}
		}
	}
}

// composeOverride reports a Compose override file of the same directory
// (docker-compose.override.yml and the like) that changes the service.
func (s *scanner) composeOverride(root string, r *refs.Ref, load func(string) ([]*yaml.Node, bool)) string {
	parts := strings.Split(r.Context, ".")
	if len(parts) < 3 || parts[0] != "services" {
		return ""
	}
	svc := parts[1]
	dir := path.Dir(r.File)
	for _, o := range composeOverrides {
		file := path.Join(dir, o)
		if file == r.File {
			continue
		}
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(file))); err != nil {
			if _, inOverlay := s.opts.Overlay[file]; !inOverlay {
				continue
			}
		}
		ds, ok := load(file)
		if !ok {
			return fmt.Sprintf("%s could not be read, and Compose merges it into %s", file, r.File)
		}
		for _, d := range ds {
			if len(d.Content) == 0 {
				continue
			}
			m := mapGet(mapGet(d.Content[0], "services"), svc)
			if m == nil {
				continue
			}
			for _, k := range deploymentKeys {
				if mapGet(m, k) != nil {
					return fmt.Sprintf("%s sets %s for the service, so it may load another configuration or command", file, k)
				}
			}
		}
	}
	return ""
}

// helmTemplates reports a Helm chart whose templates may set the
// container's command or mount configuration: the templates next to the
// values file that set them, or no templates there to read (a chart from
// elsewhere).
func (s *scanner) helmTemplates(root, values string) string {
	dir := path.Join(path.Dir(values), "templates")
	full, err := refs.SafePath(root, dir)
	if err != nil {
		return "the chart's templates could not be read, so what they set for the image is not known"
	}
	if fi, err := os.Stat(full); err != nil || !fi.IsDir() {
		return "the values are for a chart whose templates are not in this tree, so what they set for the image (command, mounted configuration) is not known"
	}
	// Every template, in every subdirectory, as Helm renders them.
	why, seen := "", 0
	err = filepath.WalkDir(full, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			why = "a chart template directory could not be read (" + err.Error() + ")"
			return filepath.SkipAll
		}
		if d.IsDir() || !d.Type().IsRegular() {
			if d.Type()&fs.ModeSymlink != 0 {
				why = "the chart template " + p + " is a symbolic link, which is not followed"
				return filepath.SkipAll
			}
			return nil
		}
		if seen++; seen > 4096 {
			why = "the chart has more templates than the detector reads"
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		b, err := readFile(root, rel)
		if err != nil {
			why = "the chart template " + rel + " could not be read"
			return filepath.SkipAll
		}
		for _, k := range []string{"volumeMounts", "command:", "args:", "envFrom", "env:"} {
			if strings.Contains(string(b), k) {
				why = fmt.Sprintf("the chart template %s sets %s, so the image may load another configuration or command", rel, strings.TrimSuffix(k, ":"))
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil && why == "" {
		why = "the chart's templates could not be read"
	}
	return why
}

// mappingWithImageAt finds the mapping whose image key's value is on line.
func mappingWithImageAt(n *yaml.Node, line, depth int) *yaml.Node {
	if n == nil || depth > 64 {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		v := mapGet(n, "image")
		if v == nil {
			v = mapGet(n, "name") // a GitLab CI service
		}
		if v != nil && v.Kind == yaml.ScalarNode && v.Line == line {
			return n
		}
	}
	for _, c := range n.Content {
		if m := mappingWithImageAt(c, line, depth+1); m != nil {
			return m
		}
	}
	return nil
}

// mayBeNginx reports whether an unresolved reference could be an nginx
// image: it names one, or it is all variable.
func mayBeNginx(text string) bool {
	low := strings.ToLower(text)
	if strings.Contains(low, "nginx") || strings.Contains(low, "openresty") || strings.Contains(low, "angie") || strings.Contains(low, "tengine") {
		return true
	}
	t := strings.TrimSpace(text)
	return strings.HasPrefix(t, "$") || strings.HasPrefix(t, "{{")
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// kindOf classifies a repository path.
func kindOf(rel string) string {
	base := path.Base(rel)
	low := strings.ToLower(base)
	switch {
	case low == "dockerfile" || low == "containerfile" || strings.HasPrefix(low, "dockerfile.") || strings.HasSuffix(low, ".dockerfile") || strings.HasPrefix(low, "containerfile."):
		return "dockerfile"
	case strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml"):
		return "yaml"
	case low == "nginx.conf" || strings.HasPrefix(low, "nginx.conf.") || strings.HasSuffix(low, ".conf") || strings.HasSuffix(low, ".conf.template") || strings.HasSuffix(low, ".nginx") || strings.HasSuffix(low, ".vhost"):
		return "nginx-conf"
	case strings.HasSuffix(low, ".template") || strings.HasSuffix(low, ".tmpl"):
		if strings.Contains(strings.ToLower(rel), "nginx") || strings.Contains(low, ".conf") {
			return "nginx-conf"
		}
	}
	if strings.Contains(strings.ToLower(path.Dir(rel)), "sites-enabled") || strings.Contains(strings.ToLower(path.Dir(rel)), "sites-available") {
		return "nginx-conf"
	}
	// refs reads Compose .env files and CI files of its own; those are
	// handed to it through the list.
	if low == ".env" || strings.HasSuffix(low, ".env") {
		return "env"
	}
	return ""
}

func readFile(root, rel string) ([]byte, error) {
	p, err := refs.SafePath(root, rel)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("larger than %d MiB: not checked", maxFileSize>>20)
	}
	return os.ReadFile(p)
}

type scanner struct {
	root      string
	opts      Options
	findings  []Finding
	skips     []Skip
	fromImage map[string]refs.Ref // "file:line" of a FROM -> its reference
	seen      map[string]bool     // "file|image" judged
	stageMods map[string]string   // "file:line" of a FROM -> what its stage changes
}

func (s *scanner) add(f Finding) {
	if len(s.findings) < maxFindings {
		s.findings = append(s.findings, f)
	}
}

// worst is the status a finding takes from its CVEs: vulnerable before
// unknown before the rest.
func worst(cs []CVEStatus) knowledge.Status {
	st := knowledge.Fixed
	for _, c := range cs {
		switch c.Status {
		case knowledge.Vulnerable:
			return knowledge.Vulnerable
		case knowledge.Unknown:
			st = knowledge.Unknown
		}
	}
	return st
}

func cveList(v map[string]Verdict) []CVEStatus {
	var out []CVEStatus
	for _, c := range knowledge.CVEs {
		x := v[c.ID]
		out = append(out, CVEStatus{ID: c.ID, Status: x.Status, Reason: x.Reason})
	}
	return out
}

func reasons(cs []CVEStatus) string {
	var parts []string
	for _, c := range cs {
		parts = append(parts, fmt.Sprintf("%s %s (%s)", c.ID, c.Status, c.Reason))
	}
	return strings.Join(parts, "; ")
}

// splitImage reads repository, tag and digest from a reference.
func splitImage(image string) (repo, tag, digest string) {
	base, dg, _ := strings.Cut(image, "@")
	digest = dg
	slash := strings.LastIndexByte(base, '/')
	if c := strings.LastIndexByte(base, ':'); c > slash {
		return base[:c], base[c+1:], digest
	}
	return base, "", digest
}

// image judges one image reference.
func (s *scanner) image(r *refs.Ref) {
	fam, ok := Classify(r.Image)
	if !ok {
		if NginxShaped(r.Image) {
			s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: knowledge.Unknown,
				Reason:  "an image that may hold nginx, from a repository whose tags the detector does not read",
				Message: fmt.Sprintf("%s may hold nginx (a mirror, or a product built on nginx or OpenResty): not judged from its name; it is read from its registry unless the run is offline", r.Image),
				Fix:     "Read the image (earlylight scan image " + r.Image + ").",
				Props:   map[string]string{"image": r.Image, "context": r.Context}, Pull: r.Image, Platform: r.Platform, ref: r})
		}
		return
	}
	repoName, tag, digest := splitImage(r.Image)
	props := map[string]string{"image": r.Image, "family": fam.ID, "context": r.Context}
	t, exact := fam.ParseTag(tag)
	if exact && digest != "" && worst(cveList(fam.Judge(t))) == knowledge.Vulnerable {
		// The tag names a release without the fix; whatever the digest
		// holds, the reference asks for that release. Moving it means
		// moving the digest too.
		v := fam.Judge(t)
		cs := cveList(v)
		props["tag"], props["version"], props["digest"] = tag, t.Version, digest
		f := Finding{Rule: RuleImage, File: r.File, Line: r.Line, Level: "error", Status: knowledge.Vulnerable, Props: props, CVEs: cs, Platform: r.Platform, ref: r}
		f.Reason = reasons(cs)
		f.Message = fmt.Sprintf("%s names %s %s: %s", r.Image, fam.Vendor, t.Version, f.Reason)
		if target := fam.FixedTag(t); target != "" {
			f.Fix = fmt.Sprintf("Move to %s:%s and its digest (the reference is pinned by digest, so fix does not change it), then rebuild and redeploy.", repoName, target)
		} else {
			f.Fix = fam.LineText(t) + "."
		}
		s.add(f)
		return
	}
	if !exact || digest != "" {
		why := "its tag does not name one release (a moving tag)"
		if digest != "" {
			why = "it is pinned by digest, which decides what it holds"
		}
		if tag == "" && digest == "" {
			why = "it has no tag (latest), which moves"
		}
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: knowledge.Unknown,
			Reason:  "only reading the image says which nginx it holds",
			Message: fmt.Sprintf("%s (%s) is not judged from its name: %s; it is read from its registry unless the run is offline", r.Image, fam.Vendor, why),
			Fix:     "Read the image (earlylight scan image " + r.Image + ") or pin a tag of a fixed release.",
			Props:   props, Pull: r.Image, Platform: r.Platform, ref: r})
		return
	}
	v := fam.Judge(t)
	cs := cveList(v)
	st := worst(cs)
	if st == knowledge.Fixed || st == knowledge.NotAffected {
		return
	}
	props["tag"] = tag
	props["version"] = t.Version
	f := Finding{Rule: RuleImage, File: r.File, Line: r.Line, Level: "error", Status: st, Props: props, CVEs: cs, Platform: r.Platform, ref: r}
	f.Reason = reasons(cs)
	f.Message = fmt.Sprintf("%s names %s %s: %s", r.Image, fam.Vendor, t.Version, f.Reason)
	if st == knowledge.Unknown {
		f.Level = "note"
		f.Rule = RuleNotChecked
	}
	if target := fam.FixedTag(t); target != "" {
		f.Fixable = true
		f.edit = &tagEdit{image: r.Image, family: fam, tag: t, target: target}
		f.Fix = fmt.Sprintf("Move to %s:%s, %s, then rebuild and redeploy.", repoName, target, fam.MoveText(t))
	} else {
		f.Fix = fam.LineText(t) + "."
	}
	f.Interim = "Until then, turn HTTP/2 off in the configuration the image runs (\"http2 off;\" and no \"http2\" on any listen): an interim step, not a fix."
	s.add(f)
}

// config reports where an nginx configuration in the tree turns HTTP/2
// on.
func (s *scanner) config(rel string, b []byte) {
	s.configText(rel, 0, string(b))
}

// configText analyses one configuration text; base is added to its line
// numbers (a ConfigMap value starts below its key).
func (s *scanner) configText(rel string, base int, text string) {
	ds, err := conf.Parse(rel, text)
	if err != nil {
		// Not every *.conf is nginx's. A file that names HTTP/2 and does
		// not parse is not checked.
		if strings.Contains(text, "http2") {
			s.skips = append(s.skips, Skip{File: rel, Reason: "names http2 but could not be read as an nginx configuration (" + refs.CleanText(err.Error(), 120) + "): not checked"})
		}
		return
	}
	// A conf.d or sites-enabled snippet holds server blocks (or server
	// directives): read it inside http, where nginx includes it.
	wrapped := ds
	top := false
	for _, d := range ds {
		if d.Name == "http" || d.Name == "events" {
			top = true
		}
	}
	if !top {
		wrapped = []conf.Directive{{Name: "http", HasBlock: true, Block: ds}}
		if !hasServer(ds) {
			wrapped[0].Block = []conf.Directive{{Name: "server", HasBlock: true, Block: ds, File: rel, Line: 1}}
		}
	}
	e := conf.Analyze(&conf.Config{Main: rel, Root: wrapped, Files: []string{rel}})
	if e.HTTP2 != "on" {
		return
	}
	for _, w := range e.Where {
		file, line := splitWhere(w)
		if file != rel {
			continue
		}
		over := "over TLS"
		if e.Flow != conf.Exposed {
			over = "without TLS"
		}
		proxy := "in front of a proxy"
		if e.Reuse != conf.Exposed {
			proxy = "with no proxy directive in this file"
		}
		s.add(Finding{Rule: RuleHTTP2, File: rel, Line: base + line, Level: "note", Status: knowledge.NotAffected,
			Reason:  "a setting, not a vulnerable build: it makes a vulnerable nginx reachable",
			Message: fmt.Sprintf("turns HTTP/2 on (%s, %s): an nginx before 1.31.9 or 1.30.7 that loads it is exposed to %s and %s", over, proxy, knowledge.Flow, knowledge.Reuse),
			Fix:     "Run nginx 1.31.9 or 1.30.7 or later. " + knowledge.Interim,
			Interim: fmt.Sprintf("%s: on line %d, remove \"http2\" from the listen parameters and add \"http2 off;\" to the server (nginx 1.25.1 and later; older releases have only the listen parameter)", rel, base+line),
			Props:   map[string]string{"http2": "on", "flow": string(e.Flow), "reuse": string(e.Reuse)}})
	}
}

func hasServer(ds []conf.Directive) bool {
	for _, d := range ds {
		if d.Name == "server" && d.HasBlock {
			return true
		}
	}
	return false
}

func splitWhere(w string) (string, int) {
	i := strings.LastIndexByte(w, ':')
	if i < 0 {
		return w, 0
	}
	n := 0
	fmt.Sscanf(w[i+1:], "%d", &n)
	return w[:i], n
}

// yamlFile reads Helm charts that deploy ingress-nginx and ConfigMaps that
// carry an nginx configuration.
func (s *scanner) yamlFile(rel string, b []byte) {
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	for i := 0; ; i++ {
		if i >= maxDocs {
			s.skips = append(s.skips, Skip{File: rel, Reason: fmt.Sprintf("more than %d YAML documents: the rest are not checked for nginx configurations and charts", maxDocs)})
			return
		}
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if !errors.Is(err, io.EOF) {
				s.skips = append(s.skips, Skip{File: rel, Reason: fmt.Sprintf("could not be read as YAML after %d documents (%s): the rest is not checked for nginx configurations and charts", i, refs.CleanText(err.Error(), 120))})
			}
			return
		}
		if len(doc.Content) == 0 {
			continue
		}
		m := doc.Content[0]
		if m.Kind != yaml.MappingNode {
			continue
		}
		if path.Base(rel) == "Chart.yaml" {
			s.chart(rel, m)
		}
		s.helmImages(rel, m, 0)
		if v := mapGet(m, "kind"); v != nil && v.Value == "ConfigMap" {
			if data := mapGet(m, "data"); data != nil && data.Kind == yaml.MappingNode {
				for j := 0; j+1 < len(data.Content); j += 2 {
					k, val := data.Content[j], data.Content[j+1]
					if strings.Contains(val.Value, "server") && strings.Contains(val.Value, "listen") {
						// A block scalar's text starts on the line after
						// its key; a plain or quoted one on the key's line.
						base := val.Line - 1
						if val.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
							base = val.Line
						}
						s.configText(rel+"#"+k.Value, base, val.Value)
					}
				}
			}
		}
	}
}

// helmImages finds images Helm values write as separate registry, image
// and tag keys (the ingress-nginx chart's controller.image), which the
// image reference scan does not assemble.
func (s *scanner) helmImages(rel string, m *yaml.Node, depth int) {
	if m == nil || depth > 32 {
		return
	}
	switch m.Kind {
	case yaml.SequenceNode:
		for _, c := range m.Content {
			s.helmImages(rel, c, depth+1)
		}
		return
	case yaml.MappingNode:
	default:
		return
	}
	img, tag := mapGet(m, "image"), mapGet(m, "tag")
	if img != nil && tag != nil && img.Kind == yaml.ScalarNode && tag.Kind == yaml.ScalarNode && img.Value != "" && tag.Value != "" && !strings.ContainsAny(img.Value+tag.Value, ":@${}") {
		ref := img.Value
		if reg := mapGet(m, "registry"); reg != nil && reg.Kind == yaml.ScalarNode && reg.Value != "" && !strings.ContainsAny(reg.Value, "${}") {
			ref = reg.Value + "/" + ref
		}
		ref += ":" + tag.Value
		if d := mapGet(m, "digest"); d != nil && d.Kind == yaml.ScalarNode && strings.HasPrefix(d.Value, "sha256:") {
			ref += "@" + d.Value
		}
		if _, ok := Classify(ref); ok && !s.seen[rel+"|"+ref] {
			s.seen[rel+"|"+ref] = true
			s.image(&refs.Ref{File: rel, Line: tag.Line, Kind: refs.KindHelmValues, Context: "image.tag", Text: ref, Image: ref})
		}
	}
	for i := 1; i < len(m.Content); i += 2 {
		s.helmImages(rel, m.Content[i], depth+1)
	}
}

// chart reports a Helm chart dependency on ingress-nginx.
func (s *scanner) chart(rel string, m *yaml.Node) {
	deps := mapGet(m, "dependencies")
	if deps == nil || deps.Kind != yaml.SequenceNode {
		return
	}
	for _, d := range deps.Content {
		n := mapGet(d, "name")
		if n == nil || n.Value != "ingress-nginx" {
			continue
		}
		ver := ""
		if v := mapGet(d, "version"); v != nil {
			ver = v.Value
		}
		s.add(Finding{Rule: RuleImage, File: rel, Line: n.Line, Level: "error", Status: knowledge.Vulnerable,
			Reason:  Ingress.NoFix,
			Message: fmt.Sprintf("the chart depends on the ingress-nginx chart %s, whose controller runs nginx without the fix for %s and %s and turns HTTP/2 on by default: %s", ver, knowledge.Flow, knowledge.Reuse, Ingress.NoFix),
			Fix:     "Replace ingress-nginx (for example with a maintained controller on nginx 1.31.9 or 1.30.7, or Gateway API); until then set use-http2: \"false\" in the controller's ConfigMap (an interim step, not a fix).",
			Props:   map[string]string{"chart": "ingress-nginx", "version": ver},
			CVEs: []CVEStatus{{ID: knowledge.Flow, Status: knowledge.Vulnerable, Reason: Ingress.NoFix},
				{ID: knowledge.Reuse, Status: knowledge.Vulnerable, Reason: Ingress.NoFix}}})
	}
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
