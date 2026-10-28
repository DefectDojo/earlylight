// Package brotlipin finds the places a repository pins Node.js, .NET or Bun
// to a release whose bundled Brotli decoder lacks the fix for CVE-2026-111497
// (Node2Shell, Broccoli2Shell: an out-of-bounds write in Brotli 1.0.3 through
// 1.2.0), and plans the deterministic one-line edit to the fixed release of the
// same line: Node.js 22.23.4, 24.22.1 and 26.12.1, .NET 8.0.33, 9.0.22 and
// 10.0.14, Bun 1.4.4.
//
// A pin is a value that decides which release runs the code:
//
//   - node, .NET runtime and ASP.NET Core, and Bun container images with a
//     version tag (everything internal/php2shell/refs finds: Dockerfile FROM,
//     ARG-resolved too, Compose, Kubernetes, Helm values, CI images);
//   - .nvmrc, .node-version, .bun-version, .tool-versions (nodejs, node, bun)
//     and mise.toml [tools] node and bun;
//   - package.json volta.node, engines.node and packageManager bun@, when they
//     name one exact release (a range such as ">=22" is not a pin);
//   - actions/setup-node node-version and oven-sh/setup-bun bun-version
//     literals in GitHub Actions workflows and composite actions.
//
// Floating values (24, 24.22, lts/*, node:24-slim, dotnet/aspnet:8.0,
// oven/bun:1.4) move to the fixed release by themselves and are fine, except
// on release lines with no fixed release (Node.js 20, 21, 23, 25 and older,
// .NET 7 and older, Bun minors before 1.4), which are reported with manual
// steps. .NET SDK images, global.json and setup-dotnet name SDK releases and
// are judged by the SDK that ships the fixed runtime in each feature band.
// Images pinned by digest only are listed as not checked. Pins under testdata/ and fixtures/ directories are
// notes and never changed automatically. Nothing in the repository is
// executed, and Python's Brotli and brotlicffi packages are left to the
// dependency scanner (PYSEC-2026-4322 and PYSEC-2026-4323).
package pins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// Rule IDs (SARIF ruleId, DefectDojo vuln_id_from_tool).
const (
	RuleNode       = "brotli/node"
	RuleDotnet     = "brotli/dotnet"
	RuleBun        = "brotli/bun"
	RuleNotChecked = "brotli/not-checked"
	// The image check's rules (internal/brotliimage), here so one SARIF
	// writer serves both scanners.
	RuleImage        = "brotli/image"
	RuleImageUnknown = "brotli/image-unknown"
)

// CVE is the vulnerability.
const CVE = "CVE-2026-111497"

// TitlePrefix starts every result message, so DefectDojo's titles identify a
// finding of this scanner even when its rule ID is missing.
const TitlePrefix = "Brotli " + CVE + ": "

// Finding is one pinned runtime that lacks the fix.
type Finding struct {
	Rule    string            // a Rule constant
	File    string            // repository-relative, slash-separated
	Line    int               // 1-based
	Level   string            // "error" or "note"
	Message string            // one plain sentence
	Fix     string            // what the automatic fix does, or the manual steps
	Fixable bool              // an automatic, verified fix is expected
	Props   map[string]string // current, fixed, source; image, column, edit_file, edit_line
}

// Skip is a file or value that was not checked, with the reason.
type Skip struct {
	File   string
	Line   int
	Reason string
}

// Result is the outcome of a scan.
type Result struct {
	Findings []Finding
	Skips    []Skip
	// Files is how many files were read.
	Files int
	// Truncated is true when the walk stopped at Options.MaxFiles. Findings
	// missing from a truncated scan are not fixed.
	Truncated bool
}

// Options control a scan.
type Options struct {
	// MaxFileSize is the largest file read, in bytes (default 4 MiB).
	MaxFileSize int64
	// MaxFiles bounds the directory entries a whole-repository walk visits
	// (default 200,000).
	MaxFiles int
	// IncludeDependencyDirs scans node_modules and bower_components, which hold
	// other projects' files and are skipped by default.
	IncludeDependencyDirs bool
	// Overlay replaces the content of repository-relative paths for this scan,
	// so a plan can re-scan an edited file in memory.
	Overlay map[string][]byte
}

const (
	defaultMaxFileSize = 4 << 20
	defaultMaxFiles    = 200_000
	maxMessage         = 400
)

func (o Options) maxSize() int64 {
	if o.MaxFileSize > 0 {
		return o.MaxFileSize
	}
	return defaultMaxFileSize
}

func (o Options) maxFiles() int {
	if o.MaxFiles > 0 {
		return o.MaxFiles
	}
	return defaultMaxFiles
}

func clean(s string, max int) string { return refs.CleanText(s, max) }

// pin is one place a runtime release is chosen, judged.
type pin struct {
	prod   product
	source string // Props["source"]: node-image, nvmrc, setup-node, ...
	desc   string // starts the message
	file   string
	line   int
	// editFile and editLine say where the version text is written (for an
	// ARG-resolved FROM, the ARG default); col is its 0-based byte offset there,
	// -1 when it cannot be edited verbatim.
	editFile string
	editLine int
	col      int
	j        judgement
	image    string // the image reference, for image pins
	notes    string // why the edit is not possible, when col < 0
	dep      *depInfo
	// imgOff is where a line image's release line sits in image (0: in its
	// tag, found by the version text).
	imgOff int
}

// fixtureDirs name directories of test fixtures, which are inputs to tests,
// not deployed code.
var fixtureDirs = map[string]bool{"testdata": true, "fixtures": true, "__fixtures__": true, "test-fixtures": true, "test_fixtures": true}

func fixtureDir(rel string) string {
	segs := strings.Split(rel, "/")
	for _, s := range segs[:len(segs)-1] {
		if fixtureDirs[strings.ToLower(s)] {
			return clean(s, 60)
		}
	}
	return ""
}

func (p pin) finding() Finding {
	props := map[string]string{"current": p.j.current, "fixed": p.j.fixed, "source": p.source}
	if p.image != "" {
		props["image"] = clean(p.image, 300)
	}
	if p.col >= 0 && p.editFile == p.file && p.editLine == p.line {
		props["column"] = strconv.Itoa(p.col + 1)
	}
	if p.editFile != "" && (p.editFile != p.file || p.editLine != p.line) {
		props["edit_file"] = p.editFile
		props["edit_line"] = strconv.Itoa(p.editLine)
	}
	if p.dep != nil {
		return p.depFinding(props)
	}
	name := p.prod.name()
	f := Finding{Rule: p.prod.rule(), File: p.file, Line: p.line, Level: "error", Props: props}
	if p.j.vd == noFixLine {
		f.Message = clean(fmt.Sprintf("%s pins %s %s, whose bundled Brotli decoder lacks the %s fix, on a release line with no fixed release (fixed in %s).",
			p.desc, name, p.j.current, CVE, p.prod.fixedText()), maxMessage)
	} else {
		f.Message = clean(fmt.Sprintf("%s pins %s %s, whose bundled Brotli decoder lacks the %s fix; %s has it.",
			p.desc, name, p.j.current, CVE, p.j.fixed), maxMessage)
	}
	if d := fixtureDir(p.file); d != "" {
		f.Level = "note"
		f.Fix = clean(fmt.Sprintf("Test fixture (under a %s/ directory): not changed automatically. If something runs with it, move it to %s %s by hand.", d, name, p.j.fixed), 1000)
		return f
	}
	switch {
	case p.j.vd == noFixLine:
		up, kind := upgrade(p)
		if up == "" || p.col < 0 {
			f.Fix = manual(p.prod, p.j.current)
			break
		}
		f.Fixable = true
		props["upgrade"] = kind
		props["upgrade_to"] = up
		f.Fix = clean(fmt.Sprintf("Moves %s %s to %s, the nearest release line with the fix. This is a %s upgrade, which can change behaviour: review it and run your tests before you merge, then rebuild and redeploy.", name, p.j.current, up, kind), 1000)
		if p.image != "" {
			f.Fix += " The new image is used only once it is pulled and scanned clean on every platform the current one has."
		}
	case p.col < 0:
		f.Fix = clean(fmt.Sprintf("Change %s %s to %s by hand: %s.", name, p.j.current, p.j.fixed, p.notes), 1000)
	case p.image != "":
		f.Fixable = true
		f.Fix = clean(fmt.Sprintf("Change the image tag from %s %s to %s on this line, once the new image is pulled and scanned clean on every platform the current one has. Rebuild and redeploy.", name, p.j.current, p.j.fixed), 1000)
	default:
		f.Fixable = true
		f.Fix = clean(fmt.Sprintf("Change %s %s to %s on this line, the fixed release of the same line; the rest of the line is kept.", name, p.j.current, p.j.fixed), 1000)
	}
	return f
}

// depFinding is the finding for a dependency that bundles the decoder.
func (p pin) depFinding(props map[string]string) Finding {
	d := p.dep
	props["ecosystem"], props["package"] = d.eco, d.name
	f := Finding{Rule: RuleDependency, File: p.file, Line: p.line, Level: "error", Props: props}
	if d.bundler.level != "" {
		f.Level = d.bundler.level
	}
	what := "a Brotli decoder without the " + CVE + " fix"
	if d.bundler.note != "" {
		what += " (" + d.bundler.note + ")"
	}
	shown := p.j.current
	if d.eco == "Go" {
		shown = "v" + shown
	}
	if p.j.vd == bump {
		fixed := p.j.fixed
		if d.eco == "Go" {
			fixed = "v" + fixed
		}
		f.Message = clean(fmt.Sprintf("%s pins %s %s (%s), which bundles %s; %s has it.", p.desc, d.name, shown, d.eco, what, fixed), maxMessage)
		switch {
		case fixtureDir(p.file) != "":
			f.Level, f.Fix = "note", "Test fixture: not changed automatically."
		case p.col < 0:
			f.Fix = clean(fmt.Sprintf("Upgrade %s to %s: %s.", d.name, fixed, p.notes), 1000)
		default:
			f.Fixable = true
			f.Fix = clean(fmt.Sprintf("Change %s %s to %s on this line; the rest of the line is kept.", d.name, shown, fixed), 1000)
		}
		return f
	}
	f.Message = clean(fmt.Sprintf("%s pins %s %s (%s), which bundles %s, and no release of it has the fix.", p.desc, d.name, shown, d.eco, what), maxMessage)
	f.Fix = clean(fmt.Sprintf("Replace %s with %s.", d.name, d.bundler.replace), 1000)
	if fixtureDir(p.file) != "" {
		f.Level = "note"
	}
	return f
}

// Scan finds every vulnerable Node.js, .NET and Bun pin, and every dependency
// that bundles the decoder without the fix. files nil scans the
// whole repository; otherwise only those repository-relative paths (forward
// slashes) are read.
//
// .git, .hg and .svn are skipped, and so are node_modules and
// bower_components unless Options.IncludeDependencyDirs. Symbolic links are
// never followed.
func Scan(ctx context.Context, root string, files []string, opts Options) (Result, error) {
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	fi, err := os.Stat(root)
	if err != nil {
		return Result{}, err
	}
	if !fi.IsDir() {
		return Result{}, fmt.Errorf("%s is not a directory", root)
	}
	s := &scanner{ctx: ctx, root: root, opts: opts}
	list := files
	if list == nil {
		if list, err = s.walk(); err != nil {
			return Result{}, err
		}
	}
	for _, rel := range list {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		rel = strings.TrimPrefix(path.Clean(filepath.ToSlash(rel)), "./")
		if k := kindOf(rel); k != kindNone || textCandidate(rel) || dependencyFile(rel) {
			s.parseFile(rel, k)
		}
	}
	if err := s.images(files); err != nil {
		return Result{}, err
	}
	return s.result(), nil
}

type scanner struct {
	ctx       context.Context
	root      string
	opts      Options
	pins      []pin
	skips     []Skip
	files     int
	truncated bool
	lines     map[string][]string // files split once per scan, for columns
}

// exists reports a regular file in the repository (or the overlay).
func (s *scanner) exists(rel string) bool {
	if _, ok := s.opts.Overlay[rel]; ok {
		return true
	}
	p, err := refs.SafePath(s.root, rel)
	if err != nil {
		return false
	}
	fi, err := os.Lstat(p)
	return err == nil && fi.Mode().IsRegular()
}

// fileLines returns rel's lines, read and split once per scan.
func (s *scanner) fileLines(rel string) []string {
	if l, ok := s.lines[rel]; ok {
		return l
	}
	if s.lines == nil {
		s.lines = map[string][]string{}
	}
	var b []byte
	if o, ok := s.opts.Overlay[rel]; ok {
		b = o
	} else if p, err := refs.SafePath(s.root, rel); err == nil {
		if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() && fi.Size() <= s.opts.maxSize() {
			b, _ = os.ReadFile(p)
		}
	}
	l := splitLines(b)
	s.lines[rel] = l
	return l
}

func (s *scanner) add(p pin) {
	if p.j.vd == bump || p.j.vd == noFixLine {
		s.pins = append(s.pins, p)
	}
}

func (s *scanner) result() Result {
	r := Result{Skips: s.skips, Files: s.files, Truncated: s.truncated}
	// An image pin owns the line it edits (an ARG default its FROM reads):
	// a text pattern on that same line would edit it without the image
	// verification.
	imageEdits := map[string]bool{}
	for _, p := range s.pins {
		if p.image != "" {
			imageEdits[fmt.Sprint(p.editFile, "\x00", p.editLine)] = true
		}
	}
	seen := map[string]bool{}
	for _, p := range s.pins {
		if p.image == "" && p.dep == nil && imageEdits[fmt.Sprint(p.file, "\x00", p.line)] {
			continue
		}
		// One pin per place: a value two readers find (an env value that
		// setup-node reads and a NODE_VERSION pattern) is reported once, by
		// the first, structured one.
		k := fmt.Sprint(p.file, "\x00", p.line, "\x00", p.prod.rule(), "\x00", p.j.current, "\x00", p.image)
		if seen[k] {
			continue
		}
		seen[k] = true
		r.Findings = append(r.Findings, p.finding())
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	sort.SliceStable(r.Skips, func(i, j int) bool {
		if r.Skips[i].File != r.Skips[j].File {
			return r.Skips[i].File < r.Skips[j].File
		}
		return r.Skips[i].Line < r.Skips[j].Line
	})
	return r
}

type fileKind int

const (
	kindNone fileKind = iota
	kindNvmrc
	kindNodeVersion
	kindBunVersion
	kindToolVersions
	kindMise
	kindPackageJSON
	kindWorkflow
	kindAzurePipelines
	kindCircleCI
	kindGlobalJSON
	kindDotnetProject
	kindNetlify
)

func kindOf(rel string) fileKind {
	base := path.Base(rel)
	lower := strings.ToLower(rel)
	switch base {
	case ".nvmrc":
		return kindNvmrc
	case ".node-version":
		return kindNodeVersion
	case ".bun-version":
		return kindBunVersion
	case ".tool-versions":
		return kindToolVersions
	case "package.json":
		return kindPackageJSON
	case "mise.toml", ".mise.toml", "mise.local.toml", ".mise.local.toml":
		return kindMise
	case "action.yml", "action.yaml":
		return kindWorkflow
	case "global.json":
		return kindGlobalJSON
	case "netlify.toml":
		return kindNetlify
	case "Directory.Build.props", "Directory.Build.targets", "Directory.Packages.props":
		return kindDotnetProject
	}
	switch path.Ext(lower) {
	case ".csproj", ".fsproj", ".vbproj":
		return kindDotnetProject
	}
	if strings.HasSuffix(lower, ".circleci/config.yml") || strings.HasSuffix(lower, ".circleci/config.yaml") {
		return kindCircleCI
	}
	if isYAML(lower) && (strings.HasPrefix(path.Base(lower), "azure-pipelines") || strings.Contains(lower, ".azure-pipelines/") ||
		strings.Contains(lower, ".azuredevops/") || strings.Contains(lower, ".pipelines/")) {
		return kindAzurePipelines
	}
	if strings.HasSuffix(lower, ".mise/config.toml") || strings.HasSuffix(lower, ".config/mise.toml") ||
		strings.HasSuffix(lower, ".config/mise/config.toml") || strings.HasSuffix(lower, "mise/config.toml") {
		return kindMise
	}
	if (strings.HasPrefix(lower, ".github/workflows/") || strings.Contains(lower, "/.github/workflows/")) &&
		(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")) {
		return kindWorkflow
	}
	return kindNone
}

func vcsDir(base string) bool { return base == ".git" || base == ".hg" || base == ".svn" }

var errStop = errors.New("stop")

// walk lists the candidate files of the whole repository.
func (s *scanner) walk() ([]string, error) {
	var out []string
	n := 0
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			rel, _ := filepath.Rel(s.root, p)
			s.skips = append(s.skips, Skip{File: filepath.ToSlash(rel), Reason: "could not be read: " + clean(err.Error(), 200)})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		n++
		if n > s.opts.maxFiles() {
			s.truncated = true
			return errStop
		}
		rel, _ := filepath.Rel(s.root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p == s.root {
				return nil
			}
			base := d.Name()
			if vcsDir(base) || (!s.opts.IncludeDependencyDirs && (base == "node_modules" || base == "bower_components")) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() && (kindOf(rel) != kindNone || textCandidate(rel) || dependencyFile(rel)) {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	return out, nil
}

// readQuiet reads like read but records no skip.
func (s *scanner) readQuiet(rel string) ([]byte, bool) {
	n := len(s.skips)
	b, ok := s.read(rel)
	s.skips = s.skips[:n]
	return b, ok
}

// read returns a repository file's content, or the overlay's.
func (s *scanner) read(rel string) ([]byte, bool) {
	if b, ok := s.opts.Overlay[rel]; ok {
		s.files++
		return b, true
	}
	p, err := refs.SafePath(s.root, rel)
	if err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: clean(err.Error(), 200)})
		return nil, false
	}
	fi, err := os.Lstat(p)
	if err != nil {
		if !os.IsNotExist(err) {
			s.skips = append(s.skips, Skip{File: rel, Reason: "could not be read: " + clean(err.Error(), 200)})
		}
		return nil, false
	}
	if !fi.Mode().IsRegular() {
		return nil, false // a symbolic link or special file is never followed
	}
	if fi.Size() > s.opts.maxSize() {
		s.skips = append(s.skips, Skip{File: rel, Reason: fmt.Sprintf("larger than %d bytes, not read", s.opts.maxSize())})
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: "could not be read: " + clean(err.Error(), 200)})
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, s.opts.maxSize()+1))
	if err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: "could not be read: " + clean(err.Error(), 200)})
		return nil, false
	}
	s.files++
	return b, true
}

func splitLines(b []byte) []string {
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

func (s *scanner) parseFile(rel string, k fileKind) {
	var b []byte
	var ok bool
	if k == kindNone && !dependencyFile(rel) {
		b, ok = s.readQuiet(rel) // a text candidate only: not reading it is no gap
	} else {
		b, ok = s.read(rel)
	}
	if !ok {
		return
	}
	switch k {
	case kindNvmrc:
		s.versionFile(rel, b, node, "nvmrc", ".nvmrc")
	case kindNodeVersion:
		s.versionFile(rel, b, node, "node-version-file", ".node-version")
	case kindBunVersion:
		s.versionFile(rel, b, bun, "bun-version-file", ".bun-version")
	case kindToolVersions:
		s.toolVersions(rel, b)
	case kindMise:
		s.mise(rel, b)
	case kindPackageJSON:
		s.packageJSON(rel, b)
	case kindWorkflow:
		s.workflow(rel, b)
	case kindAzurePipelines:
		s.azurePipelines(rel, b)
	case kindCircleCI:
		s.circleCI(rel, b)
	case kindGlobalJSON:
		s.globalJSON(rel, b)
	case kindDotnetProject:
		s.dotnetProject(rel, b)
	case kindNetlify:
		s.netlify(rel, b)
	}
	if textCandidate(rel) {
		s.textPatterns(rel, b)
	}
	if dependencyFile(rel) {
		s.dependencies(rel, b)
	}
}

// textPin judges value written at byte col of line and adds the pin.
func (s *scanner) textPin(prod product, source, desc, rel string, line, col int, value string) {
	j := judgeValue(prod, value, false)
	if j.vd == notJudged {
		return
	}
	at := col
	if j.current != "" {
		if k := strings.Index(value, j.current); k >= 0 {
			at = col + k
		}
	}
	s.add(pin{prod: prod, source: source, desc: desc, file: rel, line: line, editFile: rel, editLine: line, col: at, j: j})
}

// versionFile reads the first value line of .nvmrc, .node-version or
// .bun-version. Comments (#) and blank lines are skipped.
func (s *scanner) versionFile(rel string, b []byte, prod product, source, name string) {
	for i, l := range splitLines(b) {
		t := l
		if k := strings.IndexByte(t, '#'); k >= 0 {
			t = t[:k]
		}
		v := strings.TrimSpace(t)
		if v == "" {
			continue
		}
		s.textPin(prod, source, name, rel, i+1, strings.Index(l, v), v)
		return
	}
}

// toolVersions reads asdf's .tool-versions: "nodejs 24.22.0", "bun 1.4.3".
// asdf uses the first version listed.
func (s *scanner) toolVersions(rel string, b []byte) {
	for i, l := range splitLines(b) {
		t := l
		if k := strings.IndexByte(t, '#'); k >= 0 {
			t = t[:k]
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			continue
		}
		var prod product
		switch f[0] {
		case "nodejs", "node":
			prod = node
		case "bun":
			prod = bun
		default:
			continue
		}
		col := strings.Index(l[len(f[0]):], f[1]) + len(f[0])
		s.textPin(prod, "tool-versions", ".tool-versions "+f[0], rel, i+1, col, f[1])
	}
}

// mise reads node = "24.22.0" and bun = "1.4.3" in a [tools] table. A list
// value names the first version.
func (s *scanner) mise(rel string, b []byte) {
	inTools := false
	for i, l := range splitLines(b) {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			inTools = t == "[tools]"
			continue
		}
		if !inTools || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `"'`)
		var prod product
		switch key {
		case "node", "nodejs":
			prod = node
		case "bun":
			prod = bun
		default:
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.TrimPrefix(val, "[")
		q := strings.IndexAny(val, `"'`)
		if q != 0 {
			continue
		}
		e := strings.IndexByte(val[1:], val[0])
		if e < 0 {
			continue
		}
		v := val[1 : 1+e]
		eq := strings.IndexByte(l, '=')
		col := strings.Index(l[eq:], v) + eq
		s.textPin(prod, "mise", "mise.toml [tools] "+key, rel, i+1, col, v)
	}
}

// packageJSON reads volta.node, engines.node and packageManager bun@X. Only a
// value that names one exact release is a pin: a range (">=22", "^24.0.0")
// only limits which release runs.
func (s *scanner) packageJSON(rel string, b []byte) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: "not valid JSON: " + clean(err.Error(), 200)})
		return
	}
	// Each field is read on its own: an old-style "engines" array or any
	// other unexpected shape skips only that field.
	var doc struct {
		Volta          map[string]any
		Engines        map[string]any
		PackageManager any
	}
	_ = json.Unmarshal(raw["volta"], &doc.Volta)
	_ = json.Unmarshal(raw["engines"], &doc.Engines)
	_ = json.Unmarshal(raw["packageManager"], &doc.PackageManager)
	// raw is the JSON string as written; value is the version in it.
	check := func(source, desc, parent, key, raw, value string, prod product) {
		j := judgeValue(prod, value, false)
		if j.vd == notJudged || len(strings.Split(j.current, ".")) != 3 {
			return // not one exact release
		}
		line, col, ok := locateJSON(b, parent, key, raw)
		p := pin{prod: prod, source: source, desc: desc, file: rel, line: line, editFile: rel, editLine: line, col: -1, j: j}
		if ok {
			p.col = col + strings.Index(raw, j.current)
		} else {
			p.line, p.editLine = 1, 1
			p.notes = "the value could not be located in the file as written"
		}
		s.add(p)
	}
	if v, ok := doc.Volta["node"].(string); ok {
		check("volta", "package.json volta.node", "volta", "node", v, v, node)
	}
	if v, ok := doc.Engines["node"].(string); ok {
		check("engines", "package.json engines.node", "engines", "node", v, v, node)
		s.enginesRange(rel, b, v)
	}
	if v, ok := doc.Engines["bun"].(string); ok {
		check("engines", "package.json engines.bun", "engines", "bun", v, v, bun)
	}
	if v, ok := doc.PackageManager.(string); ok && strings.HasPrefix(v, "bun@") {
		ver, _, _ := strings.Cut(strings.TrimPrefix(v, "bun@"), "+") // bun@1.4.3+sha512.abc
		check("package-manager", "package.json packageManager", "", "packageManager", v, ver, bun)
	}
}

// locateJSON finds "key": "value" (inside the "parent" object when parent is
// set) and returns the 1-based line and the 0-based byte column of value on
// it. It reads the text as written, so a value that appears only escaped is
// not found.
func locateJSON(b []byte, parent, key, value string) (int, int, bool) {
	if value == "" {
		return locateKey(b, parent, key)
	}
	from := 0
	if parent != "" {
		i := bytes.Index(b, []byte(`"`+parent+`"`))
		if i < 0 {
			return 0, 0, false
		}
		from = i
	}
	k := bytes.Index(b[from:], []byte(`"`+key+`"`))
	if k < 0 {
		return 0, 0, false
	}
	at := from + k + len(key) + 2
	rest := b[at:]
	t := bytes.TrimLeft(rest, " \t\r\n")
	if len(t) == 0 || t[0] != ':' {
		return 0, 0, false
	}
	t2 := bytes.TrimLeft(t[1:], " \t\r\n")
	if !bytes.HasPrefix(t2, []byte(`"`+value+`"`)) {
		return 0, 0, false
	}
	off := len(b) - len(t2) + 1 // the value, after its opening quote
	line := 1 + bytes.Count(b[:off], []byte("\n"))
	col := off - (bytes.LastIndexByte(b[:off], '\n') + 1)
	return line, col, true
}

// imageRepos are the official images of each runtime and the public mirrors
// that serve them under the same tags. .NET SDK images are left out: their
// tags name SDK releases, not runtimes.
var imageRepos = map[string]product{
	"index.docker.io/library/node":          node,
	"mirror.gcr.io/library/node":            node,
	"public.ecr.aws/docker/library/node":    node,
	"mcr.microsoft.com/dotnet/runtime":      dotnet,
	"mcr.microsoft.com/dotnet/aspnet":       dotnet,
	"mcr.microsoft.com/dotnet/core/runtime": dotnet,
	"mcr.microsoft.com/dotnet/core/aspnet":  dotnet,
	"index.docker.io/oven/bun":              bun,
	"mirror.gcr.io/oven/bun":                bun,
	// Node.js images whose tags are Node.js versions too.
	"index.docker.io/cimg/node":     node,
	"mirror.gcr.io/cimg/node":       node,
	"index.docker.io/bitnami/node":  node,
	"mirror.gcr.io/bitnami/node":    node,
	"public.ecr.aws/bitnami/node":   node,
	"index.docker.io/circleci/node": node,
	"mcr.microsoft.com/dotnet/sdk":  dotnetSDK,
}

// lineRepos are images whose repository name or tag names only a release
// line (gcr.io/distroless/nodejs22-debian12, ubi9/nodejs-20,
// public.ecr.aws/lambda/nodejs:20, azure-functions/node:4-node20). They are
// judged by that line: fine on a line with a fixed release (the image is
// rebuilt with it), reported on one without.
var lineRepos = []struct {
	re     *regexp.Regexp // on registry/path:tag; group 1 is the major
	prod   product
	source string
}{
	{regexp.MustCompile(`^gcr\.io/distroless/nodejs(\d+)-debian\d+:`), node, "node-image"},
	{regexp.MustCompile(`^registry\.(?:access\.redhat\.com|redhat\.io)/ubi\d+/nodejs-(\d+)(?:-minimal)?:`), node, "node-image"},
	{regexp.MustCompile(`^public\.ecr\.aws/lambda/nodejs:(\d+)(?:[.-]|$)`), node, "node-image"},
	{regexp.MustCompile(`^mcr\.microsoft\.com/azure-functions/node:\d+-node(\d+)(?:-|$)`), node, "node-image"},
	{regexp.MustCompile(`^mcr\.microsoft\.com/devcontainers/(?:javascript|typescript)-node:(?:[\d.]+-|dev-)?(\d{2})(?:-|$)`), node, "node-image"},
	{regexp.MustCompile(`^public\.ecr\.aws/lambda/dotnet:(\d+)(?:[.-]|$)`), dotnet, "dotnet-image"},
	{regexp.MustCompile(`^public\.ecr\.aws/lambda/dotnet:core(\d+)\.\d+$`), dotnet, "dotnet-image"},
	{regexp.MustCompile(`^mcr\.microsoft\.com/azure-functions/dotnet-isolated:\d+-dotnet-isolated(\d+)\.0(?:-|$)`), dotnet, "dotnet-image"},
}

var refKindNames = map[refs.Kind]string{
	refs.KindDockerfile: "Dockerfile", refs.KindCompose: "Compose", refs.KindKubernetes: "Kubernetes",
	refs.KindHelmValues: "Helm values", refs.KindGitHubActions: "GitHub Actions", refs.KindGitLabCI: "GitLab CI",
	refs.KindBitbucket: "Bitbucket Pipelines",
}

// images judges every runtime image the repository references.
func (s *scanner) images(files []string) error {
	ro := refs.Options{MaxFileSize: s.opts.MaxFileSize, IncludeDependencyDirs: s.opts.IncludeDependencyDirs, Overlay: s.opts.Overlay}
	var rs []refs.Ref
	var sk []refs.Skip
	var err error
	if files == nil {
		rs, sk, err = refs.Scan(s.root, ro)
	} else {
		rs, sk, err = refs.ScanFiles(s.root, files, ro)
	}
	if err != nil {
		return err
	}
	for _, k := range sk {
		s.skips = append(s.skips, Skip{File: k.File, Line: k.Line, Reason: clean(k.Reason, 200)})
	}
	for _, r := range rs {
		s.judgeImage(r)
	}
	return nil
}

func (s *scanner) judgeImage(r refs.Ref) {
	ref, err := parseReference(r.Image)
	if err != nil {
		return
	}
	desc := strings.TrimSpace(refKindNames[r.Kind] + " " + r.Context + " image " + clean(r.Image, 200))
	prod, ok := imageRepos[ref.Registry+"/"+ref.Path]
	if !ok {
		s.judgeLineImage(r, ref, desc)
		return
	}
	if ref.Tag == "" && ref.Digest != "" {
		s.skips = append(s.skips, Skip{File: r.File, Line: r.Line, Reason: clean(fmt.Sprintf("%s is pinned by digest only; its %s release is checked by the brotli-images scan, which reads the image", r.Image, prod.name()), 300)})
		return
	}
	// A tag@digest pin is judged by its tag; its fix moves both.
	j := judgeValue(prod, ref.Tag, true)
	if j.vd == notJudged || j.current == "" {
		return
	}
	p := pin{prod: prod, source: map[product]string{node: "node-image", dotnet: "dotnet-image", bun: "bun-image", dotnetSDK: "dotnet-sdk-image"}[prod], desc: desc,
		file: r.File, line: r.Line, editFile: r.EditFile, editLine: r.EditLine, col: -1, j: j, image: r.Image}
	if p.editFile == "" {
		p.editFile, p.editLine = r.File, r.Line
	}
	// The tag's version must be written verbatim, once, in the edited part.
	if r.EditText != "" && strings.Count(r.EditText, j.current) == 1 {
		p.col = columnOf(s.fileLines(p.editFile), p.editLine, r.EditText, j.current)
	}
	if p.col < 0 {
		p.notes = "the tag's version is not written verbatim on one line (it is built from variables, or appears more than once)"
	}
	s.add(p)
}

// judgeLineImage judges an image whose name or tag names only a release line.
func (s *scanner) judgeLineImage(r refs.Ref, ref reference, desc string) {
	key := ref.Registry + "/" + ref.Path + ":" + ref.Tag
	key = strings.TrimPrefix(key, "index.docker.io/")
	for _, lr := range lineRepos {
		m := lr.re.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		j := judgeLine(lr.prod, parsed{parts: []int{atoi(m[1])}, text: m[1]})
		if j.vd != noFixLine {
			return
		}
		p := pin{prod: lr.prod, source: lr.source, desc: desc, file: r.File, line: r.Line, editFile: r.EditFile, editLine: r.EditLine, col: -1, j: j, image: r.Image,
			notes: "the image names its release line, not a version"}
		if p.editFile == "" {
			p.editFile, p.editLine = r.File, r.Line
		}
		// The line's number, where it sits in the reference as written (a
		// reference written without a tag reads as :latest).
		w := strings.TrimPrefix(r.Image, "docker.io/")
		if i := strings.Index(w, "@"); i >= 0 {
			w = w[:i]
		}
		if !strings.Contains(w[strings.LastIndex(w, "/")+1:], ":") {
			w += ":"
		}
		if mi := lr.re.FindStringSubmatchIndex(w); mi != nil && r.EditText == r.Image {
			p.col = columnOf(s.fileLines(p.editFile), p.editLine, r.EditText, "")
			if p.col >= 0 {
				p.imgOff = mi[2] + len(r.Image) - len(strings.TrimPrefix(r.Image, "docker.io/"))
				p.col += p.imgOff
			}
		}
		s.add(p)
		return
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// columnOf returns the 0-based byte offset of version inside part on line, or -1.
func columnOf(ls []string, line int, part, version string) int {
	if line < 1 || line > len(ls) {
		return -1
	}
	l := ls[line-1]
	i := strings.Index(l, part)
	if i < 0 || strings.Count(l, part) != 1 {
		return -1
	}
	return i + strings.Index(part, version)
}

// ImageBump returns image with its tag moved to the fixed release of the same
// line, when image is an official Node.js, .NET or Bun image whose tag pins a
// release without the fix (node:24.22.0-slim becomes node:24.22.1-slim). A
// digest is dropped: the caller resolves the new tag's own.
func ImageBump(image string) (string, bool) {
	ref, err := parseReference(image)
	if err != nil || ref.Tag == "" {
		return "", false
	}
	prod, ok := imageRepos[ref.Registry+"/"+ref.Path]
	if !ok {
		return "", false
	}
	j := judgeValue(prod, ref.Tag, true)
	if j.vd != bump {
		return "", false
	}
	base := image
	if i := strings.Index(base, "@"); i >= 0 {
		base = base[:i]
	}
	i := strings.LastIndex(base, ":"+ref.Tag)
	if i < 0 {
		return "", false
	}
	return base[:i] + ":" + strings.Replace(ref.Tag, j.current, j.fixed, 1), true
}

// locateKey finds "key" (inside the "parent" object when parent is set) and
// returns its 1-based line.
func locateKey(b []byte, parent, key string) (int, int, bool) {
	from := 0
	if parent != "" {
		i := bytes.Index(b, []byte(`"`+parent+`"`))
		if i < 0 {
			return 0, 0, false
		}
		from = i
	}
	k := bytes.Index(b[from:], []byte(`"`+key+`"`))
	if k < 0 {
		return 0, 0, false
	}
	off := from + k
	return 1 + bytes.Count(b[:off], []byte("\n")), -1, true
}

// ImageUpgrade returns image moved to the nearest Node.js or Bun line with
// the fix, when image is an official Node.js or Bun image on a line with no
// fixed release (node:20-alpine becomes node:22-alpine), and the kind of
// upgrade. A digest is dropped.
func ImageUpgrade(image string) (string, string, bool) {
	ref, err := parseReference(image)
	if err != nil || ref.Tag == "" {
		return "", "", false
	}
	prod, ok := imageRepos[ref.Registry+"/"+ref.Path]
	if !ok || (prod != node && prod != bun) {
		return "", "", false
	}
	j := judgeValue(prod, ref.Tag, true)
	if j.vd != noFixLine {
		return "", "", false
	}
	up, kind := upgrade(pin{prod: prod, j: j, image: image})
	if up == "" {
		return "", "", false
	}
	base := image
	if i := strings.Index(base, "@"); i >= 0 {
		base = base[:i]
	}
	i := strings.LastIndex(base, ":"+ref.Tag)
	if i < 0 {
		return "", "", false
	}
	return base[:i] + ":" + strings.Replace(ref.Tag, j.current, up, 1), kind, true
}
