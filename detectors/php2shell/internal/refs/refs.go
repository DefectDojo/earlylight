// Package refs finds container image references in a source repository:
// Dockerfiles and Containerfiles, Compose files, Kubernetes, OpenShift and
// Knative manifests (including rendered Helm output), Helm values files, and CI
// configuration (GitHub Actions, GitLab CI, Bitbucket Pipelines).
//
// Every reference records exactly where it was written, byte by byte (see
// Part), so a fix can edit the one place that determines the part of the
// reference it changes: the FROM line, the ARG default that feeds it, the
// Compose default or .env value, the values.yaml tag line.
//
// The scanner never guesses. A reference whose value is decided outside the
// repository (an ARG with no default, a Compose variable with no default and no
// .env value, a Helm template, a CI expression) is reported as a Skip with the
// reason, not as a Ref.
//
// Known limits: Kustomize images: transformers (newName/newTag) are not
// applied, so a base manifest is reported as written; Kubernetes manifests in
// JSON are not read; GitLab CI files pulled in with include: are read only when
// named *.gitlab-ci.yml; Compose files read the .env file of their own
// directory (not one chosen with --project-directory or --env-file); a Helm
// chart may assemble repository and tag differently from
// registry/repository:tag; Dockerfiles are parsed with heredocs enabled (the
// BuildKit default since Dockerfile frontend 1.4).
package refs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/name"
)

// Kind is the kind of file a reference was found in.
type Kind string

const (
	KindDockerfile    Kind = "dockerfile"
	KindCompose       Kind = "compose"
	KindKubernetes    Kind = "kubernetes"
	KindHelmValues    Kind = "helm-values"
	KindGitHubActions Kind = "github-actions"
	KindGitLabCI      Kind = "gitlab-ci"
	KindBitbucket     Kind = "bitbucket-pipelines"
)

// Ref is one image reference.
type Ref struct {
	// File is the repository-relative path, with forward slashes.
	File string `json:"file"`
	// Line is the 1-based line of the reference: the FROM instruction's first
	// line, or the line of the YAML scalar (for Helm values, the repository
	// line).
	Line int `json:"line"`
	// Column is the 1-based byte column of Text on Line, when it starts there.
	Column int  `json:"column,omitempty"`
	Kind   Kind `json:"kind"`
	// Context says where in the file the reference sits, for example
	// "FROM", "services.web.image", "spec.template.spec.containers[0].image",
	// "jobs.test.services.db.image".
	Context string `json:"context,omitempty"`
	// Text is the reference as written, before variable substitution.
	Text string `json:"text"`
	// Image is the resolved reference string.
	Image string `json:"image"`
	// Platform is the literal value of FROM --platform, if any.
	Platform string `json:"platform,omitempty"`
	// Stage is the build stage name a FROM declares (FROM image AS name).
	Stage string `json:"stage,omitempty"`
	// Vars lists the variables the resolved reference depends on.
	Vars []VarUse `json:"vars,omitempty"`
	// Parts locate every byte of Image.
	Parts []Part `json:"parts"`
	// EditFile, EditLine and EditText say where a fix of the tag would edit:
	// the Part holding the start of the tag (or, without a tag, the end of the
	// name). EditText is that Part's text.
	EditFile string `json:"edit_file,omitempty"`
	EditLine int    `json:"edit_line,omitempty"`
	EditText string `json:"edit_text,omitempty"`
}

// VarUse is a variable a reference depends on and where its value was set.
type VarUse struct {
	Name string `json:"name"`
	// File and Line locate the definition that supplied the value (the ARG
	// instruction, the .env line); Line is 0 when the variable was not set and
	// a default written in the reference was used.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Default is true when the value came from a ${VAR:-default} written in
	// the reference rather than from the variable.
	Default bool `json:"default,omitempty"`
}

// Skip is a file or reference the scanner could not resolve, with the reason.
type Skip struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Kind   Kind   `json:"kind,omitempty"`
	Text   string `json:"text,omitempty"`
	Reason string `json:"reason"`
}

// Options control a scan.
type Options struct {
	// MaxFileSize is the largest file parsed, in bytes (default 4 MiB). Larger
	// candidate files are skipped with a reason.
	MaxFileSize int64
	// IncludeDependencyDirs scans node_modules, bower_components and
	// Composer/Go vendor directories, which are skipped by default.
	IncludeDependencyDirs bool
	// Overlay replaces the content of repository-relative paths (forward
	// slashes) for this scan. A fix uses it to re-scan an edited file in
	// memory.
	Overlay map[string][]byte
}

const defaultMaxFileSize = 4 << 20

// maxDockerfileSize caps Dockerfiles separately: the parser keeps the source
// position of every byte, and no real Dockerfile comes near this.
const maxDockerfileSize = 1 << 20

func (o Options) maxSize() int64 {
	if o.MaxFileSize > 0 {
		return o.MaxFileSize
	}
	return defaultMaxFileSize
}

// fileKind classifies a repository-relative path. ok is false for files the
// scanner does not read.
func fileKind(rel string) (Kind, bool) {
	base := path.Base(rel)
	lower := strings.ToLower(base)
	dir := path.Dir(rel)
	yamlExt := strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
	switch {
	case isDockerfileName(lower):
		return KindDockerfile, true
	case strings.HasSuffix(lower, ".json"):
		// Read only when it looks like a Kubernetes manifest (scanFile).
		return KindKubernetes, true
	case !yamlExt:
		return "", false
	case isComposeName(lower):
		return KindCompose, true
	case path.Base(dir) == "workflows" && path.Base(path.Dir(dir)) == ".github":
		return KindGitHubActions, true
	case lower == "action.yml" || lower == "action.yaml":
		return KindGitHubActions, true
	case lower == ".gitlab-ci.yml" || lower == ".gitlab-ci.yaml" || strings.HasSuffix(lower, ".gitlab-ci.yml") || strings.HasSuffix(lower, ".gitlab-ci.yaml"):
		return KindGitLabCI, true
	case lower == "bitbucket-pipelines.yml" || lower == "bitbucket-pipelines.yaml":
		return KindBitbucket, true
	case strings.HasPrefix(lower, "values") || strings.Contains(lower, "-values.") || strings.Contains(lower, "_values.") || strings.Contains(lower, ".values."):
		return KindHelmValues, true
	default:
		return KindKubernetes, true
	}
}

// notDockerfileExt are extensions of files named like Dockerfiles that are
// something else: BuildKit's per-Dockerfile ignore file, documentation, data
// and scripts about the Dockerfile.
var notDockerfileExt = []string{
	".dockerignore", ".md", ".rst", ".txt", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".xml", ".html",
	".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".js", ".ts", ".go", ".rb", ".php", ".pl",
	".lock", ".orig", ".rej", ".bak", ".swp", ".patch", ".diff",
}

// isDockerfileName matches the names docker build -f is commonly given,
// case-insensitively: Dockerfile, Containerfile, Dockerfile.<x>,
// Dockerfile-<x>, Dockerfile_<x> (not when <x> ends in a documentation, data
// or script extension) and <x>.Dockerfile.
func isDockerfileName(lower string) bool {
	for _, n := range []string{"dockerfile", "containerfile"} {
		switch {
		case lower == n:
			return true
		case strings.HasPrefix(lower, n+"."), strings.HasPrefix(lower, n+"-"), strings.HasPrefix(lower, n+"_"):
			for _, ext := range notDockerfileExt {
				if strings.HasSuffix(lower, ext) {
					return false
				}
			}
			return true
		case strings.HasSuffix(lower, "."+n):
			return true
		}
	}
	return false
}

// isComposeName matches Compose and Swarm stack files: docker-compose*.yml,
// compose*.yml (not composer*), docker-stack*.yml and *stack*.yml. A file
// that turns out to have no services: is read as Kubernetes YAML.
func isComposeName(lower string) bool {
	if !(strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")) {
		return false
	}
	switch {
	case strings.HasPrefix(lower, "docker-compose"), strings.HasPrefix(lower, "compose") && !strings.HasPrefix(lower, "composer"):
		return true
	case strings.Contains(lower, "stack"):
		return true
	}
	return false
}

// dependencyDir reports whether a directory holds third-party dependencies
// that are not the repository's own deployment configuration: node_modules and
// bower_components always; vendor only when it is a Composer (autoload.php) or
// Go (modules.txt) vendor directory, since a directory named "vendor" can also
// hold a project's own files.
func dependencyDir(abs, base string) (string, bool) {
	switch base {
	case "node_modules", "bower_components":
		return "third-party JavaScript packages", true
	case "vendor":
		if _, err := os.Lstat(filepath.Join(abs, "autoload.php")); err == nil {
			return "Composer vendor directory (third-party PHP packages)", true
		}
		if _, err := os.Lstat(filepath.Join(abs, "modules.txt")); err == nil {
			return "Go vendor directory (third-party modules)", true
		}
	}
	return "", false
}

// Scan walks root without following symbolic links and returns every image
// reference it can resolve, and a Skip for everything it could not.
//
// Skipped directories: .git, .hg and .svn (version control metadata), and,
// unless opts.IncludeDependencyDirs, third-party dependency directories (see
// dependencyDir). Each skipped dependency directory is recorded as a Skip.
func Scan(root string, opts Options) ([]Ref, []Skip, error) {
	// Walk the real directory when root itself is a symbolic link (nothing
	// below it is followed).
	if real, err := filepath.EvalSymlinks(root); err == nil {
		root = real
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", root)
	}
	var files []string
	var skips []Skip
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if err != nil {
			if rel == "." {
				return err
			}
			skips = append(skips, Skip{File: rel, Reason: "unreadable: " + err.Error()})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel == "." {
			return nil
		}
		base := d.Name()
		if d.IsDir() {
			switch base {
			case ".git", ".hg", ".svn":
				return fs.SkipDir
			}
			if !opts.IncludeDependencyDirs {
				if why, ok := dependencyDir(p, base); ok {
					skips = append(skips, Skip{File: rel, Reason: "not scanned: " + why})
					return fs.SkipDir
				}
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if k, ok := fileKind(rel); ok {
				skips = append(skips, Skip{File: rel, Kind: k, Reason: "symbolic link, not followed (a target inside the repository is scanned at its own path)"})
			} else if target, err := os.Stat(p); err == nil && target.IsDir() {
				skips = append(skips, Skip{File: rel, Reason: "symbolic link to a directory, not followed"})
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if _, ok := fileKind(rel); ok {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	refs, more, err := ScanFiles(root, files, opts)
	if err != nil {
		return nil, nil, err
	}
	skips = append(skips, more...)
	sortSkips(skips)
	return refs, skips, nil
}

// ScanFiles scans the given repository-relative files (forward slashes), as
// Scan would, reading opts.Overlay instead of the disk where it has content.
// A path whose kind the scanner does not recognise is ignored.
func ScanFiles(root string, files []string, opts Options) ([]Ref, []Skip, error) {
	s := &scanner{root: root, opts: opts}
	seen := map[string]bool{}
	var list []string
	add := func(rel string) {
		if !seen[rel] {
			seen[rel] = true
			list = append(list, rel)
		}
	}
	for _, rel := range files {
		rel = path.Clean(filepath.ToSlash(rel))
		if path.Base(rel) == ".env" {
			// A changed .env changes the Compose files beside it.
			for _, c := range s.composeFilesIn(path.Dir(rel)) {
				add(c)
			}
			continue
		}
		add(rel)
	}
	for _, rel := range list {
		k, ok := fileKind(rel)
		if !ok {
			continue
		}
		if why, skip := s.excluded(rel); skip {
			if why != "" {
				s.skip(Skip{File: rel, Kind: k, Reason: "not scanned: " + why})
			}
			continue
		}
		if err := s.scanFile(rel, k); err != nil {
			return nil, nil, err
		}
	}
	sort.SliceStable(s.refs, func(i, j int) bool {
		a, b := s.refs[i], s.refs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Column < b.Column
	})
	sortSkips(s.skips)
	return s.refs, s.skips, nil
}

func sortSkips(skips []Skip) {
	sort.SliceStable(skips, func(i, j int) bool {
		if skips[i].File != skips[j].File {
			return skips[i].File < skips[j].File
		}
		return skips[i].Line < skips[j].Line
	})
}

// excluded applies Scan's directory rules to one path: inside version
// control metadata (silently), or inside a dependency directory (with the
// reason) unless IncludeDependencyDirs.
func (s *scanner) excluded(rel string) (string, bool) {
	elems := strings.Split(rel, "/")
	for i, e := range elems[:len(elems)-1] {
		switch e {
		case ".git", ".hg", ".svn":
			return "", true
		}
		if s.opts.IncludeDependencyDirs {
			continue
		}
		dir := strings.Join(elems[:i+1], "/")
		abs, err := SafePath(s.root, dir)
		if err != nil {
			abs = filepath.Join(s.root, filepath.FromSlash(dir))
		}
		if why, ok := dependencyDir(abs, e); ok {
			return why + " (" + dir + ")", true
		}
	}
	return "", false
}

// composeFilesIn lists the Compose files in a repository directory, on disk
// and in the overlay.
func (s *scanner) composeFilesIn(dir string) []string {
	var out []string
	if abs, err := SafePath(s.root, path.Join(dir, ".env")); err == nil {
		ents, _ := os.ReadDir(filepath.Dir(abs))
		for _, e := range ents {
			if e.Type().IsRegular() && isComposeName(strings.ToLower(e.Name())) {
				out = append(out, path.Join(dir, e.Name()))
			}
		}
	}
	for rel := range s.opts.Overlay {
		if path.Dir(rel) == dir && isComposeName(strings.ToLower(path.Base(rel))) {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

type scanner struct {
	root  string
	opts  Options
	refs  []Ref
	skips []Skip
}

var errTooLarge = errors.New("too large")

// errNotRegular means the path is not a regular file (a symlink, a device).
var errNotRegular = errors.New("not a regular file")

// read returns a file's content: the overlay's, or the disk's. Paths that
// leave root or pass through a symbolic link are refused.
func (s *scanner) read(rel string) ([]byte, error) {
	if b, ok := s.opts.Overlay[rel]; ok {
		if int64(len(b)) > s.opts.maxSize() {
			return nil, errTooLarge
		}
		return b, nil
	}
	p, err := SafePath(s.root, rel)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if fi.Size() > s.opts.maxSize() {
		return nil, errTooLarge
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, s.opts.maxSize()+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > s.opts.maxSize() {
		return nil, errTooLarge
	}
	return b, nil
}

// SafePath joins a repository-relative path to root, refusing paths that are
// absolute, leave root, or pass through a symbolic link (checked with Lstat on
// every directory component). The final component may not exist.
func SafePath(root, rel string) (string, error) {
	if rel == "" || path.IsAbs(rel) || filepath.IsAbs(rel) || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("%q is not a repository-relative path", rel)
	}
	clean := path.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%q leaves the repository", rel)
	}
	elems := strings.Split(clean, "/")
	cur := root
	for i, e := range elems {
		cur = filepath.Join(cur, e)
		if i == len(elems)-1 {
			break
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("%q passes through a symbolic link", rel)
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("%q: %s is not a directory", rel, path.Join(elems[:i+1]...))
		}
	}
	return cur, nil
}

// skip records a Skip; its Reason and Text are made single-line and bounded,
// since both can carry file content and registry or parser messages.
func (s *scanner) skip(sk Skip) {
	sk.Reason = CleanText(sk.Reason, 500)
	sk.Text = CleanText(sk.Text, 300)
	s.skips = append(s.skips, sk)
}

// CleanText makes text safe for a one-line message: control characters
// (including newlines) become spaces, runs of spaces collapse, and the result
// is cut to max bytes on a rune boundary, with "..." appended when cut.
func CleanText(s string, max int) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u2028' || r == '\u2029' || r == utf8.RuneError {
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		if b.Len()+utf8.RuneLen(r) > max {
			return strings.TrimSpace(b.String()) + "..."
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func (s *scanner) scanFile(rel string, k Kind) error {
	b, err := s.read(rel)
	isJSON := strings.HasSuffix(strings.ToLower(rel), ".json")
	switch {
	case isJSON && errors.Is(err, errTooLarge):
		// Most large JSON files are lock files and data; report only one that
		// looks like a Kubernetes manifest.
		if s.jsonLooksKubernetes(rel) {
			s.skip(Skip{File: rel, Kind: k, Reason: fmt.Sprintf("larger than %d bytes, not parsed", s.opts.maxSize())})
		}
		return nil
	case isJSON && err == nil && !looksKubernetesJSON(b):
		return nil
	case errors.Is(err, errTooLarge):
		s.skip(Skip{File: rel, Kind: k, Reason: fmt.Sprintf("larger than %d bytes, not parsed", s.opts.maxSize())})
		return nil
	case errors.Is(err, errNotRegular):
		s.skip(Skip{File: rel, Kind: k, Reason: "not a regular file, not read"})
		return nil
	case err != nil:
		s.skip(Skip{File: rel, Kind: k, Reason: "unreadable: " + err.Error()})
		return nil
	}
	if k == KindDockerfile {
		if len(b) > maxDockerfileSize {
			s.skip(Skip{File: rel, Kind: k, Reason: fmt.Sprintf("larger than %d bytes, not parsed as a Dockerfile", maxDockerfileSize)})
			return nil
		}
		s.dockerfile(rel, b)
		return nil
	}
	s.yamlFile(rel, k, b)
	return nil
}

func looksKubernetesJSON(b []byte) bool {
	return bytes.Contains(b, []byte(`"apiVersion"`)) && bytes.Contains(b, []byte(`"kind"`))
}

func (s *scanner) jsonLooksKubernetes(rel string) bool {
	p, err := SafePath(s.root, rel)
	if err != nil {
		return false
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	return looksKubernetesJSON(head)
}

// addRef validates the resolved reference and records it (or a Skip).
func (s *scanner) addRef(r Ref, t ptext, vars []VarUse) {
	r.Image = t.String()
	r.Parts = t.parts()
	r.Vars = vars
	if r.Image == "" {
		s.skip(Skip{File: r.File, Line: r.Line, Kind: r.Kind, Text: r.Text, Reason: "the reference resolves to an empty string"})
		return
	}
	if _, err := name.ParseReference(r.Image); err != nil {
		s.skip(Skip{File: r.File, Line: r.Line, Kind: r.Kind, Text: r.Text, Reason: fmt.Sprintf("%q is not a valid image reference: %v", r.Image, err)})
		return
	}
	// The edit point: the Part holding the first byte of the tag, or the
	// digest, or the last byte of the name.
	at := len(r.Image) - 1
	if i := TagStart(r.Image); i >= 0 {
		at = i
	} else if i := strings.IndexByte(r.Image, '@'); i >= 0 {
		at = i + 1
	}
	off := 0
	for _, p := range r.Parts {
		if at < off+len(p.Text) {
			r.EditFile, r.EditLine, r.EditText = p.File, p.Line, p.Text
			break
		}
		off += len(p.Text)
	}
	s.refs = append(s.refs, r)
}

// TagStart returns the index of the first byte of the tag in an image
// reference string, or -1 when it has none.
func TagStart(ref string) int {
	end := len(ref)
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		end = i
	}
	slash := strings.LastIndexByte(ref[:end], '/')
	if i := strings.LastIndexByte(ref[:end], ':'); i > slash {
		return i + 1
	}
	return -1
}
