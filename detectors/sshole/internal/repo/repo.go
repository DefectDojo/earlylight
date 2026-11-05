// Package repo finds what in a source tree builds or configures an OpenSSH
// server exposed to *sshole, and plans the edits that fix it:
//
//   - apk-pin: a Dockerfile on Alpine installs an OpenSSH server package
//     pinned to a release without the fix.
//   - apk-unpinned: a Dockerfile on Alpine installs one with no floor, so an
//     image built before the fix (or from a cached layer) keeps the
//     vulnerable package.
//   - eol-base: the Alpine release has no fixed package at all.
//   - star-account: a Dockerfile, script or Ansible task sets an account's
//     password field to "*", the field the bypass logs in to.
//   - password-config: something turns PasswordAuthentication on (a note).
//   - not-checked: what could not be read or resolved.
package repo

import (
	"archive/tar"
	"context"
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

	"github.com/DefectDojo/earlylight/detectors/sshole/internal/assess"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// Rules.
const (
	RulePin        = "apk-pin"
	RuleUnpinned   = "apk-unpinned"
	RuleEOL        = "eol-base"
	RuleStar       = "star-account"
	RulePassword   = "password-config"
	RuleNotChecked = "not-checked"
)

// Finding is one thing in the tree.
type Finding struct {
	Rule    string            `json:"rule"`
	File    string            `json:"file"`
	Line    int               `json:"line"`
	Level   string            `json:"level"` // error, warning, note
	Message string            `json:"message"`
	Fix     string            `json:"fix,omitempty"`
	Fixable bool              `json:"fixable"`
	Props   map[string]string `json:"props,omitempty"`
	// edit is the planned replacement, kept for Plan.
	edit *Edit
}

// Skip is a file that was not read, and why.
type Skip struct {
	File   string `json:"file"`
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
	// Overlay replaces file contents (repository-relative, slash paths), so
	// a plan can rescan an edit in memory.
	Overlay map[string][]byte
	// Base resolves an image the tree builds on: whether it is Alpine and
	// which branch ("3.22", "edge"). nil: only what the name says.
	Base func(ctx context.Context, image string) (alpine bool, branch string, err error)
	// Files, when set, limits the scan to these repository-relative paths
	// (a pull request's changed files).
	Files []string
}

const (
	maxFileSize = 4 << 20
	maxFiles    = 200000
)

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "__pycache__": true, ".tox": true, "bower_components": true}

// Scan walks root.
func Scan(ctx context.Context, root string, opts Options) (Result, error) {
	var res Result
	var list []string
	if opts.Files != nil {
		for _, rel := range opts.Files {
			rel = path.Clean(strings.ReplaceAll(rel, "\\", "/"))
			if kindOf(rel) != "" && !contains(list, rel) && rel != ".." && !strings.HasPrefix(rel, "../") && !path.IsAbs(rel) {
				list = append(list, rel)
			}
		}
		return scanList(ctx, root, list, opts, res)
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			rel, _ := filepath.Rel(root, p)
			res.Skips = append(res.Skips, Skip{File: filepath.ToSlash(rel), Reason: err.Error()})
			return nil
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if kindOf(rel) == "" {
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
	return scanList(ctx, root, list, opts, res)
}

func scanList(ctx context.Context, root string, list []string, opts Options, res Result) (Result, error) {
	for rel := range opts.Overlay {
		if kindOf(rel) != "" && !contains(list, rel) {
			list = append(list, rel)
		}
	}
	sort.Strings(list)
	s := &scanner{ctx: ctx, root: root, opts: opts, bases: map[string]baseInfo{}}
	for _, rel := range list {
		b, ok := opts.Overlay[rel]
		if !ok {
			var err error
			b, err = readFile(root, rel)
			if errors.Is(err, fs.ErrNotExist) && opts.Files != nil {
				continue // a changed file the pull request deleted
			}
			if err != nil {
				res.Skips = append(res.Skips, Skip{File: rel, Reason: err.Error()})
				continue
			}
		}
		res.Files++
		switch kindOf(rel) {
		case "dockerfile":
			res.Findings = append(res.Findings, s.dockerfile(rel, string(b))...)
		case "shell":
			res.Findings = append(res.Findings, s.script(rel, string(b))...)
		case "yaml":
			res.Findings = append(res.Findings, s.yaml(rel, string(b))...)
		case "sshd_config":
			res.Findings = append(res.Findings, s.sshdConfig(rel, string(b))...)
		}
	}
	return res, nil
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
	name := path.Base(rel)
	lower := strings.ToLower(name)
	switch {
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") ||
		lower == "containerfile" || strings.HasPrefix(lower, "containerfile.") || strings.HasSuffix(lower, ".containerfile"):
		return "dockerfile"
	case strings.HasSuffix(lower, ".sh") || strings.HasSuffix(lower, ".bash") || strings.HasSuffix(lower, ".ash") ||
		strings.HasPrefix(lower, "entrypoint") || strings.HasPrefix(lower, "docker-entrypoint"):
		return "shell"
	case strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml"):
		return "yaml"
	case strings.Contains(lower, "sshd_config"):
		return "sshd_config"
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
		return nil, fmt.Errorf("larger than %d MiB", maxFileSize>>20)
	}
	return os.ReadFile(p)
}

type baseInfo struct {
	alpine, known bool
	branch        string
	why           string
}

type scanner struct {
	ctx   context.Context
	root  string
	opts  Options
	bases map[string]baseInfo
}

// span is a piece of shell text from a file: Text, and the file line each
// byte offset starts on.
type span struct {
	text  string
	lines []int // lines[i] is the 1-based line of byte i
	cols  []int // cols[i] is the 0-based byte column of byte i on its line
}

func newSpan(physical []string, firstLine, firstCol int) span {
	var b strings.Builder
	var lines, cols []int
	for i, l := range physical {
		col0 := 0
		if i == 0 {
			col0 = firstCol
		}
		for j := 0; j < len(l); j++ {
			lines = append(lines, firstLine+i)
			cols = append(cols, col0+j)
		}
		b.WriteString(l)
		if i < len(physical)-1 {
			b.WriteByte('\n')
			lines = append(lines, firstLine+i)
			cols = append(cols, col0+len(l))
		}
	}
	return span{text: b.String(), lines: lines, cols: cols}
}

// at locates a word: its line and column, and false when it spans lines.
func (sp span) at(w word) (int, int, bool) {
	if w.start >= len(sp.lines) || w.end-1 >= len(sp.lines) || w.end <= w.start {
		return 0, 0, false
	}
	l := sp.lines[w.start]
	return l, sp.cols[w.start], sp.lines[w.end-1] == l
}

// Edit replaces Old with New at Col on Line (1-based line, 0-based byte).
type Edit struct {
	Line int
	Col  int
	Old  string
	New  string
	// Insert, when set, is a whole line inserted after Line instead.
	Insert string
}

// ---- Dockerfiles

var fromRE = regexp.MustCompile(`(?i)^\s*FROM\s+`)

type instr struct {
	cmd      string // upper case
	args     span
	line     int
	physical []string
}

func parseDockerfile(text string) []instr {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []instr
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimLeft(l, " \t")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		start := i
		phys := []string{l}
		for strings.HasSuffix(strings.TrimRight(lines[i], " \t"), "\\") && i+1 < len(lines) {
			i++
			nt := strings.TrimLeft(lines[i], " \t")
			if strings.HasPrefix(nt, "#") {
				phys = append(phys, "") // Docker drops comment lines inside an instruction
				continue
			}
			phys = append(phys, lines[i])
		}
		kw := t
		if j := strings.IndexAny(t, " \t"); j >= 0 {
			kw = t[:j]
		}
		cmd := strings.ToUpper(kw)
		off := len(l) - len(t) + len(kw)
		first := phys[0][off:]
		trim := len(first) - len(strings.TrimLeft(first, " \t"))
		phys[0] = first[trim:]
		in := instr{cmd: cmd, line: start + 1}
		// A heredoc body (RUN <<EOF) is part of the command.
		if cmd == "RUN" {
			if m := heredocRE.FindStringSubmatch(phys[len(phys)-1]); m != nil {
				term := m[1]
				for i+1 < len(lines) {
					i++
					if strings.TrimSpace(lines[i]) == term {
						break
					}
					phys = append(phys, lines[i])
				}
			}
		}
		in.physical = phys
		in.args = newSpan(phys, start+1, off+trim)
		out = append(out, in)
	}
	return out
}

var heredocRE = regexp.MustCompile(`<<-?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*$`)

func (s *scanner) dockerfile(rel, text string) []Finding {
	var out []Finding
	args := map[string]string{}
	stages := map[string]baseInfo{}
	var cur baseInfo
	curImage := ""
	for _, in := range parseDockerfile(text) {
		switch in.cmd {
		case "ARG":
			for _, a := range strings.Fields(in.args.text) {
				k, v, ok := strings.Cut(a, "=")
				if ok {
					args[k] = strings.Trim(v, `"'`)
				} else if _, set := args[k]; !set {
					args[k] = ""
				}
			}
		case "FROM":
			f := strings.Fields(in.args.text)
			var img, as string
			for i := 0; i < len(f); i++ {
				if strings.HasPrefix(f[i], "--") {
					continue
				}
				if img == "" {
					img = expand(f[i], args)
				} else if strings.EqualFold(f[i], "as") && i+1 < len(f) {
					as = f[i+1]
					break
				}
			}
			if b, ok := stages[strings.ToLower(img)]; ok {
				cur = b
			} else {
				cur = s.base(img)
			}
			curImage = img
			if as != "" {
				stages[strings.ToLower(as)] = cur
			}
		case "RUN":
			out = append(out, s.shell(rel, in.args, cur, curImage, true)...)
		}
	}
	return out
}

var varRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

func expand(s string, args map[string]string) string {
	return varRE.ReplaceAllStringFunc(s, func(m string) string {
		sm := varRE.FindStringSubmatch(m)
		name := sm[1]
		if name == "" {
			name = sm[3]
		}
		if v, ok := args[name]; ok && v != "" {
			return v
		}
		return sm[2]
	})
}

var alpineTagRE = regexp.MustCompile(`(?:^|[-_.])alpine(\d+\.\d+)`)

// base decides whether an image is Alpine and which branch, from its name
// and, when a resolver is set, from the image itself.
func (s *scanner) base(img string) baseInfo {
	if b, ok := s.bases[img]; ok {
		return b
	}
	b := baseFromName(img)
	if (!b.known || b.alpine && b.branch == "") && s.opts.Base != nil && img != "" && img != "scratch" && !strings.Contains(img, "$") {
		if alpine, branch, err := s.opts.Base(s.ctx, img); err == nil {
			b = baseInfo{alpine: alpine, known: true, branch: branch}
		} else if !b.known {
			b.why = err.Error()
		}
	}
	s.bases[img] = b
	return b
}

func baseFromName(img string) baseInfo {
	if img == "" || img == "scratch" {
		return baseInfo{known: true}
	}
	name, tag := img, ""
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	if i := strings.LastIndexByte(name, ':'); i > strings.LastIndexByte(name, '/') {
		name, tag = name[:i], name[i+1:]
	}
	repo := path.Base(name)
	switch {
	case repo == "alpine":
		switch {
		case tag == "" || tag == "latest":
			return baseInfo{alpine: true, known: true} // branch moves: resolve it
		case tag == "edge" || strings.HasPrefix(tag, "20"):
			return baseInfo{alpine: true, known: true, branch: "edge"}
		}
		if br := assess.BranchFromRelease(tag); br != "" {
			return baseInfo{alpine: true, known: true, branch: br}
		}
		return baseInfo{alpine: true, known: true}
	case strings.Contains(tag, "alpine"):
		if m := alpineTagRE.FindStringSubmatch(tag); m != nil {
			return baseInfo{alpine: true, known: true, branch: m[1]}
		}
		return baseInfo{alpine: true, known: true}
	}
	for _, glibc := range []string{"wolfi", "chainguard", "debian", "ubuntu", "fedora", "centos", "rockylinux", "almalinux", "amazonlinux", "ubi", "distroless"} {
		if strings.Contains(name, glibc) {
			return baseInfo{known: true}
		}
	}
	return baseInfo{}
}

// sshPackages are the Alpine packages that install sshd.
var sshPackages = map[string]bool{"openssh": true, "openssh-server": true, "openssh-server-pam": true, "openssh-server-krb5": true}

// apk options that take a value.
var apkValueOpts = map[string]bool{"-t": true, "--virtual": true, "-X": true, "--repository": true, "--root": true, "-p": true,
	"--arch": true, "--cache-dir": true, "--keys-dir": true, "--repositories-file": true, "--cache-max-age": true, "--timeout": true}

var specRE = regexp.MustCompile(`^([a-z0-9][a-z0-9._+-]*?)(?:@[A-Za-z0-9_-]+)?(?:(>=|<=|=~|~|=|<|>)(.*))?$`)

// shell finds apk installs, "*" password fields and PasswordAuthentication
// switches in a piece of shell text.
func (s *scanner) shell(rel string, sp span, b baseInfo, image string, dockerfile bool) []Finding {
	var out []Finding
	cmds := splitShell(sp.text)
	for ci, c := range cmds {
		prog, at := c.program()
		if at < 0 {
			continue
		}
		args := c.words[at+1:]
		// PasswordAuthentication yes, written by sed or echo into a config.
		for _, w := range args {
			if pwYes.MatchString(w.val) {
				l, _, _ := sp.at(w)
				out = append(out, Finding{Rule: RulePassword, File: rel, Line: l, Level: "note",
					Message: "turns PasswordAuthentication on; with an OpenSSH server on musl that lacks the *sshole fix, accounts with the password field \"*\" are exposed",
					Fix:     "Use key logins (PasswordAuthentication no) unless passwords are required, and install an OpenSSH package with the fix",
				})
			}
		}
		switch prog {
		case "apk":
			out = append(out, s.apk(rel, sp, args, b, image, dockerfile)...)
		case "usermod", "useradd":
			for i := 0; i < len(args); i++ {
				v := args[i].val
				var pw *word
				switch {
				case (v == "-p" || v == "--password") && i+1 < len(args):
					pw = &args[i+1]
				case strings.HasPrefix(v, "--password="):
					if strings.TrimPrefix(v, "--password=") == "*" {
						w := args[i]
						out = append(out, s.star(rel, sp, w, "--password=*", "--password='*NP*'", prog)...)
					}
				}
				if pw != nil && !pw.dynamic && pw.val == "*" {
					out = append(out, s.star(rel, sp, *pw, sp.text[pw.start:pw.end], "'*NP*'", prog)...)
				}
			}
		case "chpasswd":
			if !hasFlag(args, "-e", "--encrypted") || !c.piped || ci == 0 {
				continue
			}
			for _, w := range feederWords(cmds[ci-1]) {
				if starEntry.MatchString(w.val) && !w.dynamic {
					raw := sp.text[w.start:w.end]
					out = append(out, s.star(rel, sp, w, raw, strings.Replace(raw, ":*", ":*NP*", 1), "chpasswd -e")...)
				}
			}
		case "sed":
			if !touchesShadow(args) {
				continue
			}
			for _, w := range args {
				if w.dynamic || strings.HasPrefix(w.val, "-") && !strings.HasPrefix(w.val, "-e") {
					continue
				}
				if repl, ok := sedStarReplacement(w.val); ok {
					raw := sp.text[w.start:w.end]
					fixed := strings.Replace(raw, repl, strings.Replace(repl, "*", "*NP*", 1), 1)
					if fixed != raw {
						out = append(out, s.star(rel, sp, w, raw, fixed, "sed on /etc/shadow")...)
					}
				}
			}
		case "echo", "printf":
			for _, r := range c.redirs {
				if strings.HasSuffix(r.target.val, "/etc/shadow") && (r.op == ">" || r.op == ">>") {
					for _, w := range args {
						if shadowLine.MatchString(strings.TrimSuffix(w.val, `\n`)) && !w.dynamic {
							raw := sp.text[w.start:w.end]
							out = append(out, s.star(rel, sp, w, raw, strings.Replace(raw, ":*:", ":*NP*:", 1), "a line written to /etc/shadow")...)
						}
					}
				}
			}
		}
	}
	return out
}

var (
	starEntry  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*\$?:\*(\\n)?$`)
	shadowLine = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*\$?:\*:`)
	pwYes      = regexp.MustCompile(`(?i)(^|[^A-Za-z])PasswordAuthentication\s+yes\b`)
)

func hasFlag(ws []word, flags ...string) bool {
	for _, w := range ws {
		for _, f := range flags {
			if w.val == f {
				return true
			}
		}
	}
	return false
}

// feederWords returns the words of a command that writes chpasswd's input.
func feederWords(c command) []word {
	prog, at := c.program()
	if prog != "echo" && prog != "printf" {
		return nil
	}
	return c.words[at+1:]
}

func touchesShadow(ws []word) bool {
	for _, w := range ws {
		if strings.HasSuffix(w.val, "/etc/shadow") || strings.HasSuffix(w.val, "/etc/tcb") {
			return true
		}
	}
	return false
}

// sedStarReplacement finds an s command whose replacement writes a password
// field of exactly "*" (":*:" or ":*" at the end), and returns that
// replacement.
func sedStarReplacement(script string) (string, bool) {
	script = strings.TrimPrefix(script, "-e")
	i := strings.Index(script, "s")
	for i >= 0 && i+1 < len(script) {
		delim := script[i+1]
		if delim == '\\' || delim == '\n' || delim == ' ' {
			break
		}
		parts := splitUnescaped(script[i+2:], delim)
		if len(parts) >= 2 {
			repl := parts[1]
			r := strings.ReplaceAll(repl, `\*`, "*")
			if strings.Contains(r, ":*:") || strings.HasSuffix(r, ":*") {
				return repl, true
			}
		}
		next := strings.Index(script[i+1:], "s")
		if next < 0 {
			break
		}
		i += next + 1
	}
	return "", false
}

func splitUnescaped(s string, d byte) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i])
			b.WriteByte(s[i+1])
			i++
			continue
		}
		if s[i] == d {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(s[i])
	}
	return append(out, b.String())
}

func (s *scanner) star(rel string, sp span, w word, raw, fixed, how string) []Finding {
	l, col, ok := sp.at(w)
	f := Finding{Rule: RuleStar, File: rel, Line: l, Level: "error",
		Message: fmt.Sprintf("sets an account's password field to \"*\" (%s); on an OpenSSH server on musl without the *sshole fix, a crafted password logs in to that account", how),
		Fix:     "Use \"*NP*\" instead of \"*\": it still allows key logins, and no password matches it on any OpenSSH build",
		Props:   map[string]string{"how": how}}
	if ok && raw != fixed && strings.Count(raw, "\n") == 0 {
		f.Fixable = true
		f.edit = &Edit{Line: l, Col: col, Old: raw, New: fixed}
	}
	return []Finding{f}
}

func (s *scanner) apk(rel string, sp span, args []word, b baseInfo, image string, dockerfile bool) []Finding {
	var out []Finding
	sub := -1
	for i := 0; i < len(args); i++ {
		v := args[i].val
		if strings.HasPrefix(v, "-") {
			if apkValueOpts[v] {
				i++
			}
			continue
		}
		sub = i
		break
	}
	if sub < 0 || args[sub].val != "add" {
		return nil
	}
	for i := sub + 1; i < len(args); i++ {
		w := args[i]
		if strings.HasPrefix(w.val, "-") {
			if apkValueOpts[w.val] {
				i++
			}
			continue
		}
		if w.dynamic {
			continue
		}
		m := specRE.FindStringSubmatch(w.val)
		if m == nil || !sshPackages[m[1]] {
			continue
		}
		if f, ok := s.judgeSpec(rel, sp, w, m[1], m[2], m[3], b, image, dockerfile); ok {
			out = append(out, f)
		}
	}
	return out
}

// judgeSpec decides an apk dependency on an OpenSSH server package.
func (s *scanner) judgeSpec(rel string, sp span, w word, pkg, op, ver string, b baseInfo, image string, dockerfile bool) (Finding, bool) {
	l, col, sameLine := sp.at(w)
	raw := sp.text[w.start:w.end]
	props := map[string]string{"package": pkg, "spec": w.val}
	if image != "" {
		props["image"] = image
	}
	if b.branch != "" {
		props["branch"] = b.branch
	}
	f := Finding{File: rel, Line: l, Props: props}
	if !b.known {
		f.Rule, f.Level = RuleNotChecked, "note"
		why := "the base image could not be identified"
		if b.why != "" {
			why += " (" + b.why + ")"
		}
		f.Message = fmt.Sprintf("installs %s with apk, but %s, so whether it is Alpine (musl) is not known", w.val, why)
		f.Fix = "If this image is Alpine, require " + pkg + " at the fixed release for its branch (" + fixedTable() + ")"
		return f, true
	}
	if !b.alpine {
		return f, false // apk on glibc (Wolfi, Chainguard): not affected
	}
	fixed, haveFixed := assess.AlpineFixedFor(b.branch)
	if b.branch != "" && !haveFixed {
		f.Rule, f.Level = RuleEOL, "error"
		f.Message = fmt.Sprintf("installs %s on Alpine %s (%s), which has no OpenSSH package with the *sshole fix", w.val, b.branch, image)
		f.Fix = "Move the base image to an Alpine release with a fixed package (" + fixedTable() + "), or set PasswordAuthentication no and change every \"*\" password field to \"*NP*\""
		return f, true
	}
	ok, decided := satisfiesFix(op, ver, fixed, haveFixed)
	if decided && ok {
		return f, false
	}
	switch {
	case op == "" || op == "~" || op == ">=" || op == ">":
		f.Rule, f.Level = RuleUnpinned, "warning"
		f.Message = fmt.Sprintf("installs %s with no floor at the fixed release; images built before 2026-11-05, or from a cached layer, keep the vulnerable OpenSSH server", w.val)
	default:
		f.Rule, f.Level = RulePin, "error"
		f.Message = fmt.Sprintf("pins %s to a release without the *sshole fix", w.val)
	}
	if !haveFixed {
		f.Fix = "Require " + pkg + " at the fixed release for this image's Alpine branch (" + fixedTable() + ")"
		return f, true
	}
	newSpec := pkg + ">=" + fixed
	if op == "=" {
		newSpec = pkg + "=" + fixed
	}
	quoted := "'" + newSpec + "'"
	f.Fix = fmt.Sprintf("Require %s (Alpine %s), which rebuilds the layer with the fixed package", newSpec, branchName(b.branch))
	props["fixed"] = fixed
	if sameLine && !strings.Contains(raw, "\n") {
		f.Fixable = true
		f.edit = &Edit{Line: l, Col: col, Old: raw, New: quoted}
	}
	return f, true
}

func branchName(b string) string {
	if b == "edge" {
		return "edge"
	}
	return b
}

func fixedTable() string {
	var parts []string
	for _, br := range assess.AlpineBranches() {
		v, _ := assess.AlpineFixedFor(br)
		parts = append(parts, br+": "+v)
	}
	return strings.Join(parts, ", ")
}

// satisfiesFix says whether every version an apk constraint allows has the
// fix. decided is false when the constraint cannot be judged.
func satisfiesFix(op, ver, fixed string, haveFixed bool) (ok, decided bool) {
	if op == "" || !haveFixed {
		return false, op == ""
	}
	c := compareAPK(ver, fixed)
	switch op {
	case "=":
		if st, _, known := apkFixed(ver); known {
			return st, true
		}
		return c >= 0, c != 2
	case ">=":
		return c >= 0 && c != 2, c != 2
	case ">":
		return c >= 0 && c != 2, c != 2
	case "~", "=~":
		return false, true // a fuzzy match still allows older releases from a cache
	}
	return false, true // < and <= never guarantee the fix
}

func apkFixed(v string) (bool, string, bool) {
	fixed, why, ok := assess.APKFixed(v)
	return fixed, why, ok
}

// compareAPK compares two openssh apk versions: -1, 0, 1, or 2 when either
// cannot be read.
func compareAPK(a, b string) int {
	pa, oka := parseV(a)
	pb, okb := parseV(b)
	if !oka || !okb {
		return 2
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

var apkVerRE = regexp.MustCompile(`^(\d+)\.(\d+)(?:_p(\d+))?(?:-r(\d+))?$`)

func parseV(v string) ([4]int, bool) {
	m := apkVerRE.FindStringSubmatch(v)
	if m == nil {
		return [4]int{}, false
	}
	var out [4]int
	for i := 1; i <= 4; i++ {
		if m[i] != "" {
			out[i-1], _ = strconv.Atoi(m[i])
		}
	}
	return out, true
}

// ---- scripts, YAML and sshd_config

func (s *scanner) script(rel, text string) []Finding {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	sp := newSpan(lines, 1, 0)
	return s.shell(rel, sp, baseInfo{}, "", false)
}

var yamlStar = regexp.MustCompile(`^(\s*-?\s*(?:password|passwd)\s*:\s*)(["']?)\*(["']?)\s*$`)
var yamlStarInline = regexp.MustCompile(`\bpassword=(["']?)\*(["']?)(\s|$)`)

func (s *scanner) yaml(rel, text string) []Finding {
	var out []Finding
	for i, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if m := yamlStar.FindStringSubmatchIndex(l); m != nil {
			old := l[m[2]:]
			newl := l[m[2]:m[3]] + `"*NP*"`
			out = append(out, Finding{Rule: RuleStar, File: rel, Line: i + 1, Level: "error", Fixable: true,
				Message: "sets an account's password field to \"*\" (Ansible or cloud-init); on an OpenSSH server on musl without the *sshole fix, a crafted password logs in to that account",
				Fix:     "Use \"*NP*\" instead of \"*\": it still allows key logins, and no password matches it",
				Props:   map[string]string{"how": "yaml"},
				edit:    &Edit{Line: i + 1, Col: m[2], Old: old, New: newl}})
			continue
		}
		if m := yamlStarInline.FindStringSubmatchIndex(l); m != nil {
			old := l[m[0]:m[1]]
			newl := strings.Replace(old, "*", "*NP*", 1)
			out = append(out, Finding{Rule: RuleStar, File: rel, Line: i + 1, Level: "error", Fixable: true,
				Message: "sets an account's password field to \"*\" (Ansible); on an OpenSSH server on musl without the *sshole fix, a crafted password logs in to that account",
				Fix:     "Use \"*NP*\" instead of \"*\"",
				Props:   map[string]string{"how": "yaml"},
				edit:    &Edit{Line: i + 1, Col: m[0], Old: old, New: newl}})
		}
	}
	return out
}

func (s *scanner) sshdConfig(rel, text string) []Finding {
	var out []Finding
	for i, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if pwYes.MatchString(t) {
			out = append(out, Finding{Rule: RulePassword, File: rel, Line: i + 1, Level: "note",
				Message: "sshd_config turns PasswordAuthentication on; with an OpenSSH server on musl that lacks the *sshole fix, accounts with the password field \"*\" are exposed",
				Fix:     "Use key logins (PasswordAuthentication no) unless passwords are required, and install an OpenSSH package with the fix"})
		}
	}
	return out
}

// ---- base image resolution

// AlpineOf reads an image's filesystem for /etc/alpine-release. open
// returns the flattened filesystem as a tar stream.
func AlpineOf(open func() (io.ReadCloser, error)) (bool, string, error) {
	rc, err := open()
	if err != nil {
		return false, "", err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	musl := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, "", err
		}
		name := path.Clean("/" + h.Name)
		switch {
		case name == "/etc/alpine-release" && h.Typeflag == tar.TypeReg:
			b, err := io.ReadAll(io.LimitReader(tr, 256))
			if err != nil {
				return false, "", err
			}
			return true, assess.BranchFromRelease(string(b)), nil
		case strings.HasPrefix(name, "/lib/ld-musl-"):
			musl = true
		}
	}
	if musl {
		return true, "", nil // musl without Alpine's release file
	}
	return false, "", nil
}
