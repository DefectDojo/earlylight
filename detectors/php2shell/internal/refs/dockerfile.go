package refs

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The Dockerfile parser follows BuildKit's frontend/dockerfile/parser and
// instructions packages (Dockerfile frontend 1.x, heredocs enabled, as in every
// current BuildKit):
//
//   - parser directives (# syntax=, # escape=, # check=) are read only before
//     the first line that is not a directive; "escape" may be \ or `.
//   - a line ending in the escape character, optionally followed by spaces or
//     tabs, continues on the next line; comment lines and blank lines inside a
//     continuation are dropped.
//   - instruction words are case-insensitive.
//   - RUN, COPY and ADD (also under ONBUILD), when not in JSON form, may open
//     heredocs (<<EOF, <<-EOF, <<"EOF"); their bodies are consumed verbatim and
//     never parsed as instructions.
//   - FROM [--platform=...] image [AS name]: the image word is expanded with
//     BuildKit's shell word rules ($VAR, ${VAR}, ${VAR:-word}, ${VAR-word},
//     ${VAR:+word}, ${VAR+word}, ${VAR:?msg}, ${VAR?msg}, quotes, escapes)
//     against the ARGs declared before the first FROM only. ARG defaults are
//     expanded the same way against the ARGs before them.
//
// Where BuildKit would expand an unset variable to an empty string, the scanner
// records a Skip instead of a reference built on an empty value. Variables
// whose value depends on the build platform (TARGETARCH, BUILDPLATFORM, ...)
// are not resolvable. The image named by "# syntax=" is the frontend, not a
// runtime image, and is not reported.

var (
	reDirective = regexp.MustCompile(`^#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$`)
	reHeredoc   = regexp.MustCompile(`^(\d*)<<(-?)([^<]*)$`)
	validStage  = regexp.MustCompile(`^[a-z][a-z0-9-_.]*$`)
)

var allowedDirectives = map[string]bool{"syntax": true, "escape": true, "check": true}

// platformArgs are BuildKit's automatic global ARGs; their values depend on the
// platform being built.
var platformArgs = map[string]bool{
	"BUILDPLATFORM": true, "BUILDOS": true, "BUILDARCH": true, "BUILDVARIANT": true,
	"TARGETPLATFORM": true, "TARGETOS": true, "TARGETARCH": true, "TARGETVARIANT": true,
}

func isReWhitespace(b byte) bool {
	switch b {
	case '\t', '\v', '\f', '\r', ' ':
		return true
	}
	return false
}

type dfInstr struct {
	cmd  string // lowercased
	line int
	full ptext // the whole instruction after joining continuations, trimmed
	rest ptext // text after the instruction word and its whitespace
}

type dockerfileParse struct {
	escape byte
	instrs []dfInstr
}

func trimLeftSpace(t ptext) ptext {
	for len(t) > 0 {
		r, n := t.runeAt(0)
		if !unicode.IsSpace(r) {
			break
		}
		t = t[n:]
	}
	return t
}

func trimSpace(t ptext) ptext {
	t = trimLeftSpace(t)
	for len(t) > 0 {
		// Walk back to the start of the last rune.
		i := len(t) - 1
		for i > 0 && !utf8.RuneStart(t[i].b) {
			i--
		}
		r, _ := t.runeAt(i)
		if !unicode.IsSpace(r) {
			break
		}
		t = t[:i]
	}
	return t
}

func isCommentLine(s string) bool {
	return strings.HasPrefix(strings.TrimLeftFunc(s, unicode.IsSpace), "#")
}

// trimContinuation strips a trailing escape character (plus spaces and tabs)
// and reports whether the line continues.
func trimContinuation(t ptext, escape byte) (ptext, bool) {
	i := len(t)
	for i > 0 && (t[i-1].b == ' ' || t[i-1].b == '\t') {
		i--
	}
	if i > 0 && t[i-1].b == escape {
		return t[:i-1], true
	}
	return t, false
}

func parseDockerfile(file string, b []byte) (*dockerfileParse, error) {
	lines := splitLines(b)
	p := &dockerfileParse{escape: '\\'}
	seen := map[string]bool{}
	directivesDone := false
	lineText := func(l srcLine) ptext { return newPText(file, l.num, l.off, l.text) }

	for i := 0; i < len(lines); {
		l := lines[i]
		i++
		tok := strings.TrimLeftFunc(l.text, unicode.IsSpace)
		if !directivesDone {
			m := reDirective.FindStringSubmatch(tok)
			if m == nil || !allowedDirectives[strings.ToLower(m[1])] {
				directivesDone = true
			} else {
				k := strings.ToLower(m[1])
				if seen[k] {
					return nil, fmt.Errorf("line %d: only one %s parser directive can be used", l.num, k)
				}
				seen[k] = true
				if k == "escape" {
					switch m[2] {
					case "\\":
						p.escape = '\\'
					case "`":
						p.escape = '`'
					default:
						return nil, fmt.Errorf("line %d: invalid escape token %q does not match ` or \\", l.num, m[2])
					}
				}
			}
		}
		if strings.HasPrefix(tok, "#") {
			continue
		}
		t := trimLeftSpace(lineText(l))
		joined, cont := trimContinuation(t, p.escape)
		if !cont && len(joined) == 0 {
			continue
		}
		start := l.num
		for cont && i < len(lines) {
			c := lines[i]
			i++
			if isCommentLine(c.text) {
				continue
			}
			if strings.TrimSpace(c.text) == "" {
				continue
			}
			var part ptext
			part, cont = trimContinuation(lineText(c), p.escape)
			// joined owns its backing array (lineText allocates), so
			// appending in place is safe and keeps long continuations linear.
			joined = append(joined, part...)
		}
		full := trimSpace(joined)
		if len(full) == 0 {
			continue
		}
		cmdEnd := 0
		for cmdEnd < len(full) && !isReWhitespace(full[cmdEnd].b) {
			cmdEnd++
		}
		restStart := cmdEnd
		for restStart < len(full) && isReWhitespace(full[restStart].b) {
			restStart++
		}
		in := dfInstr{
			cmd:  strings.ToLower(full[:cmdEnd].String()),
			line: start,
			full: full,
			rest: full[restStart:],
		}
		p.instrs = append(p.instrs, in)

		if canContainHeredoc(in) && strings.Contains(full.String(), "<<") {
			docs, err := heredocsFromLine(full)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", start, err)
			}
			for _, doc := range docs {
				terminated := false
				for i < len(lines) {
					c := lines[i]
					i++
					cand := strings.TrimRight(c.text, "\r\n")
					if doc.chomp {
						cand = strings.TrimLeft(cand, "\t")
					}
					if cand == doc.name {
						terminated = true
						break
					}
				}
				if !terminated {
					return nil, fmt.Errorf("line %d: unterminated heredoc %q", start, doc.name)
				}
			}
		}
	}
	return p, nil
}

type heredoc struct {
	name  string
	chomp bool
}

var heredocCmds = map[string]bool{"run": true, "copy": true, "add": true}

func canContainHeredoc(in dfInstr) bool {
	cmd, rest := in.cmd, in.rest
	if cmd == "onbuild" {
		sub := trimSpace(rest)
		end := 0
		for end < len(sub) && !isReWhitespace(sub[end].b) {
			end++
		}
		cmd = strings.ToLower(sub[:end].String())
		for end < len(sub) && isReWhitespace(sub[end].b) {
			end++
		}
		rest = sub[end:]
	}
	if !heredocCmds[cmd] {
		return false
	}
	args, _, _ := extractBuilderFlags(rest.String())
	return !isJSONArgs(args)
}

// isJSONArgs reports whether instruction arguments are in JSON (exec) form.
func isJSONArgs(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return false
	}
	var v []string
	return json.Unmarshal([]byte(s), &v) == nil
}

// heredocsFromLine finds heredoc openers the way BuildKit does: split the line
// into words keeping quotes and escapes, then match <<[-]WORD.
func heredocsFromLine(line ptext) ([]heredoc, error) {
	lx := &shellLexer{in: line, escape: '\\', rawQuotes: true, rawEsc: true, env: func(string) varInfo { return varInfo{} }}
	words, err := lx.processWords()
	if err != nil {
		// BuildKit ignores the error here: no heredocs.
		return nil, nil
	}
	var docs []heredoc
	for _, w := range words {
		m := reHeredoc.FindStringSubmatch(w.String())
		if m == nil || m[3] == "" {
			continue
		}
		rest := newPText("", 0, -1, m[3])
		nl := &shellLexer{in: rest, escape: '\\', env: func(string) varInfo { return varInfo{} }}
		nameT, err := nl.processWord()
		if err != nil {
			return nil, err
		}
		if len(nameT) == 0 {
			continue
		}
		docs = append(docs, heredoc{name: nameT.String(), chomp: m[2] == "-"})
	}
	return docs, nil
}

// extractBuilderFlags is BuildKit's: it peels leading --flag words off an
// instruction's arguments, returning the rest (a suffix of line) and the flags
// with quotes removed.
func extractBuilderFlags(line string) (string, []string, error) {
	const (
		inSpaces = iota
		inWord
		inQuote
	)
	var words []string
	phase := inSpaces
	var word strings.Builder
	var quote byte
	blankOK := false
	var ch byte
	for pos := 0; pos <= len(line); pos++ {
		if pos != len(line) {
			ch = line[pos]
		}
		if phase == inSpaces {
			if pos == len(line) {
				break
			}
			if unicode.IsSpace(rune(ch)) {
				continue
			}
			if ch != '-' || pos+1 == len(line) || line[pos+1] != '-' {
				return line[pos:], words, nil
			}
			phase = inWord
		}
		if (phase == inWord || phase == inQuote) && pos == len(line) {
			if word.String() != "--" && (blankOK || word.Len() > 0) {
				words = append(words, word.String())
			}
			break
		}
		if phase == inWord {
			if unicode.IsSpace(rune(ch)) {
				phase = inSpaces
				if word.String() == "--" {
					return line[pos:], words, nil
				}
				if blankOK || word.Len() > 0 {
					words = append(words, word.String())
				}
				word.Reset()
				blankOK = false
				continue
			}
			if ch == '\'' || ch == '"' {
				quote = ch
				blankOK = true
				phase = inQuote
				continue
			}
			if ch == '\\' {
				if pos+1 == len(line) {
					continue
				}
				pos++
				ch = line[pos]
			}
			word.WriteByte(ch)
			continue
		}
		if phase == inQuote {
			if ch == quote {
				phase = inWord
				continue
			}
			if ch == '\\' {
				if pos+1 == len(line) {
					phase = inWord
					continue
				}
				pos++
				ch = line[pos]
			}
			word.WriteByte(ch)
		}
	}
	return "", words, nil
}

// span is a [start, end) range of a ptext.
type span struct{ start, end int }

// parseWords is BuildKit's parseWords (used for ARG): split on whitespace,
// keeping quotes and escapes in the words. Every word is a contiguous range
// of the input.
func parseWords(t ptext, escape byte) []span {
	const (
		inSpaces = iota
		inWord
		inQuote
	)
	var words []span
	phase := inSpaces
	start, end := 0, 0
	var quote rune
	blankOK := false
	n := len(t)
	for pos := 0; pos <= n; {
		var ch rune
		w := 0
		if pos != n {
			ch, w = t.runeAt(pos)
		}
		if phase == inSpaces {
			if pos == n {
				break
			}
			if unicode.IsSpace(ch) {
				pos += w
				continue
			}
			phase = inWord
			start, end = pos, pos
		}
		if (phase == inWord || phase == inQuote) && pos == n {
			if blankOK || end > start {
				words = append(words, span{start, end})
			}
			break
		}
		if phase == inWord {
			if unicode.IsSpace(ch) {
				phase = inSpaces
				if blankOK || end > start {
					words = append(words, span{start, end})
				}
				blankOK = false
				pos += w
				continue
			}
			if ch == '\'' || ch == '"' {
				quote = ch
				blankOK = true
				phase = inQuote
			}
			if ch == rune(escape) {
				if pos+w == n {
					pos += w
					continue
				}
				pos += w
				_, w = t.runeAt(pos)
			}
			pos += w
			end = pos
			continue
		}
		if phase == inQuote {
			if ch == quote {
				phase = inWord
			}
			if ch == rune(escape) && quote != '\'' {
				if pos+w == n {
					phase = inWord
					pos += w
					continue
				}
				pos += w
				_, w = t.runeAt(pos)
			}
			pos += w
			end = pos
		}
	}
	return words
}

type metaArg struct {
	name string
	line int
	val  ptext
	set  bool
	err  error
	deps []VarUse
}

func (s *scanner) dockerfile(rel string, b []byte) {
	p, err := parseDockerfile(rel, b)
	if err != nil {
		s.skip(Skip{File: rel, Kind: KindDockerfile, Reason: "Dockerfile does not parse: " + err.Error()})
		return
	}
	meta := map[string]*metaArg{}
	lookup := func(name string) varInfo {
		if platformArgs[name] {
			return varInfo{hardErr: fmt.Errorf("$%s depends on the platform being built", name)}
		}
		a, ok := meta[name]
		if !ok {
			return varInfo{plainErr: fmt.Errorf("$%s is not declared by an ARG before the first FROM (BuildKit expands it to an empty string)", name)}
		}
		if a.err != nil {
			return varInfo{hardErr: fmt.Errorf("ARG %s (line %d): %v", name, a.line, a.err)}
		}
		if !a.set {
			return varInfo{plainErr: fmt.Errorf("ARG %s (line %d) has no default; its value must be passed with --build-arg", name, a.line)}
		}
		return varInfo{val: a.val, set: true}
	}
	uses := func(used []string) []VarUse {
		var out []VarUse
		seen := map[string]bool{}
		var add func(name string)
		add = func(name string) {
			if seen[name] {
				return
			}
			seen[name] = true
			a, ok := meta[name]
			switch {
			case !ok:
				out = append(out, VarUse{Name: name, Default: true})
			case !a.set:
				out = append(out, VarUse{Name: name, File: rel, Line: a.line, Default: true})
			default:
				out = append(out, VarUse{Name: name, File: rel, Line: a.line})
				for _, d := range a.deps {
					add(d.Name)
				}
			}
		}
		for _, u := range used {
			add(u)
		}
		return out
	}

	// stages holds the names declared by earlier FROMs only: BuildKit
	// resolves "FROM name" to a stage only when a previous FROM declared it
	// ("FROM wordpress AS wordpress" pulls the wordpress image).
	stages := map[string]bool{}
	seenFrom := false
	for _, in := range p.instrs {
		switch in.cmd {
		case "arg":
			if seenFrom {
				continue
			}
			for _, w := range parseWords(in.rest, p.escape) {
				word := in.rest[w.start:w.end]
				ws := word.String()
				eq := strings.IndexByte(ws, '=')
				if eq == 0 {
					s.skip(Skip{File: rel, Line: in.line, Kind: KindDockerfile, Reason: "ARG with a blank name; the Dockerfile does not build"})
					return
				}
				a := &metaArg{line: in.line}
				if eq < 0 {
					a.name = ws
				} else {
					a.name = ws[:eq]
					lx := &shellLexer{in: word[eq+1:], escape: p.escape, env: lookup}
					v, err := lx.processWord()
					a.deps = uses(lx.used)
					if err != nil {
						a.err = err
					} else {
						a.val = v.withVar(a.name)
						a.set = true
					}
				}
				meta[a.name] = a
			}
		case "from":
			seenFrom = true
			s.dockerfileFrom(rel, in, p.escape, lookup, uses, stages)
			rest, _, _ := extractBuilderFlags(in.rest.String())
			words := strings.FieldsFunc(rest, func(r rune) bool { return r < utf8.RuneSelf && isReWhitespace(byte(r)) })
			if len(words) == 3 && strings.EqualFold(words[1], "as") {
				stages[strings.ToLower(words[2])] = true
			}
		}
	}
}

func (s *scanner) dockerfileFrom(rel string, in dfInstr, escape byte, lookup lookupFunc, uses func([]string) []VarUse, stages map[string]bool) {
	restStr := in.rest.String()
	remainder, flags, _ := extractBuilderFlags(restStr)
	off := len(restStr) - len(remainder)
	skip := func(text, reason string) {
		s.skip(Skip{File: rel, Line: in.line, Kind: KindDockerfile, Text: text, Reason: reason})
	}
	platform := ""
	for _, f := range flags {
		if !strings.HasPrefix(f, "--") {
			skip(in.full.String(), fmt.Sprintf("FROM flag %q does not start with --", f))
			return
		}
		k, v, hasV := strings.Cut(f[2:], "=")
		if k != "platform" {
			skip(in.full.String(), fmt.Sprintf("unknown FROM flag --%s; the Dockerfile does not build", k))
			return
		}
		if !hasV {
			skip(in.full.String(), "FROM --platform has no value; the Dockerfile does not build")
			return
		}
		if !strings.Contains(v, "$") {
			platform = v
		}
	}
	// Split the remainder on BuildKit's whitespace, keeping positions.
	var words []span
	rt := in.rest[off:]
	for i := 0; i < len(rt); {
		for i < len(rt) && isReWhitespace(rt[i].b) {
			i++
		}
		j := i
		for j < len(rt) && !isReWhitespace(rt[j].b) {
			j++
		}
		if j > i {
			words = append(words, span{i, j})
		}
		i = j
	}
	stage := ""
	switch {
	case len(words) == 3 && strings.EqualFold(rt[words[1].start:words[1].end].String(), "as"):
		stage = strings.ToLower(rt[words[2].start:words[2].end].String())
		if !validStage.MatchString(stage) {
			skip(in.full.String(), fmt.Sprintf("invalid stage name %q; the Dockerfile does not build", stage))
			return
		}
	case len(words) != 1:
		skip(in.full.String(), "FROM requires either one or three arguments; the Dockerfile does not build")
		return
	}
	word := rt[words[0].start:words[0].end]
	text := word.String()
	lx := &shellLexer{in: word, escape: escape, env: lookup}
	img, err := lx.processWord()
	if err != nil {
		skip(text, "cannot resolve the FROM image: "+err.Error())
		return
	}
	resolved := img.String()
	if resolved == "" {
		skip(text, "the FROM image resolves to an empty name")
		return
	}
	if strings.EqualFold(resolved, "scratch") || stages[strings.ToLower(resolved)] {
		return
	}
	r := Ref{
		File:     rel,
		Line:     in.line,
		Kind:     KindDockerfile,
		Context:  "FROM",
		Text:     text,
		Platform: platform,
		Stage:    stage,
	}
	if word[0].s.line == in.line {
		r.Column = word[0].s.col + 1
	}
	s.addRef(r, img, uses(lx.used))
}
