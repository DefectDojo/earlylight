// Package conf reads an nginx configuration the way nginx does (tokens,
// blocks, includes with globs) and says whether it turns HTTP/2 on, over
// TLS, in front of a proxy. It reads only what it is given; anything it
// cannot read or settle makes the answer unknown, never off. It knows
// nothing about the engine.
package conf

import (
	"fmt"
	"strings"
)

// Directive is one directive, with its block when it has one.
type Directive struct {
	Name  string      `json:"name"`
	Args  []string    `json:"args,omitempty"`
	Block []Directive `json:"block,omitempty"`
	// HasBlock is set for a directive with braces, even empty ones.
	HasBlock bool   `json:"-"`
	File     string `json:"file"`
	Line     int    `json:"line"`
}

// Limits on one file's parse.
const (
	maxDepth  = 64
	maxTokens = 1 << 20
	maxArgs   = 256
	maxToken  = 64 << 10
)

// ParseError is a configuration nginx would refuse, or one past a limit.
type ParseError struct {
	File string
	Line int
	Msg  string
}

func (e *ParseError) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

type tokenizer struct {
	file   string
	s      string
	i      int
	line   int
	tokens int
}

// tok kinds
const (
	tWord = iota
	tSemi
	tOpen
	tClose
	tEOF
)

type token struct {
	kind   int
	text   string
	line   int
	quoted bool
}

func (t *tokenizer) errf(format string, a ...any) error {
	return &ParseError{File: t.file, Line: t.line, Msg: fmt.Sprintf(format, a...)}
}

// next reads one token as ngx_conf_read_token does: whitespace separates,
// ";", "{" and "}" end a word, "#" starts a comment at the start of a
// word, quotes group, and a backslash escapes the next character.
func (t *tokenizer) next() (token, error) {
	t.tokens++
	if t.tokens > maxTokens {
		return token{}, t.errf("more than %d tokens", maxTokens)
	}
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c == '\n':
			t.line++
			t.i++
		case c == ' ' || c == '\t' || c == '\r':
			t.i++
		case c == '#':
			for t.i < len(t.s) && t.s[t.i] != '\n' {
				t.i++
			}
		case c == ';':
			t.i++
			return token{kind: tSemi, line: t.line}, nil
		case c == '{':
			t.i++
			return token{kind: tOpen, line: t.line}, nil
		case c == '}':
			t.i++
			return token{kind: tClose, line: t.line}, nil
		case c == '"' || c == '\'':
			return t.quoted(c)
		default:
			return t.word()
		}
	}
	return token{kind: tEOF, line: t.line}, nil
}

func (t *tokenizer) quoted(q byte) (token, error) {
	start := t.line
	t.i++
	var b strings.Builder
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c == '\\' && t.i+1 < len(t.s):
			n := t.s[t.i+1]
			switch n {
			case '"', '\'', '\\':
				b.WriteByte(n)
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'n':
				b.WriteByte('\n')
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			if n == '\n' {
				t.line++
			}
			t.i += 2
		case c == q:
			t.i++
			// nginx wants whitespace or ; { } after a closing quote.
			if t.i < len(t.s) && !strings.ContainsRune(" \t\r\n;{}", rune(t.s[t.i])) {
				return token{}, t.errf("unexpected %q after a quoted string", t.s[t.i])
			}
			return token{kind: tWord, text: b.String(), line: start, quoted: true}, nil
		default:
			if c == '\n' {
				t.line++
			}
			b.WriteByte(c)
			t.i++
		}
		if b.Len() > maxToken {
			return token{}, t.errf("a quoted string longer than %d bytes", maxToken)
		}
	}
	return token{}, &ParseError{File: t.file, Line: start, Msg: "unterminated quoted string"}
}

func (t *tokenizer) word() (token, error) {
	start := t.line
	var b strings.Builder
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c == '\\' && t.i+1 < len(t.s):
			b.WriteByte(c)
			b.WriteByte(t.s[t.i+1])
			if t.s[t.i+1] == '\n' {
				t.line++
			}
			t.i += 2
			continue
		case c == '$' && t.i+1 < len(t.s) && t.s[t.i+1] == '{':
			// ${name}: the braces belong to the word.
			j := strings.IndexByte(t.s[t.i:], '}')
			if j < 0 || strings.ContainsAny(t.s[t.i:t.i+j], " \t\r\n;") {
				return token{}, t.errf("unterminated ${...}")
			}
			b.WriteString(t.s[t.i : t.i+j+1])
			t.i += j + 1
			continue
		case c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '{' || c == '}':
			return token{kind: tWord, text: b.String(), line: start}, nil
		}
		b.WriteByte(c)
		t.i++
		if b.Len() > maxToken {
			return token{}, t.errf("a word longer than %d bytes", maxToken)
		}
	}
	return token{kind: tWord, text: b.String(), line: start}, nil
}

// Parse reads one file's directives. Includes are left as directives; the
// loader expands them.
func Parse(file, text string) ([]Directive, error) {
	t := &tokenizer{file: file, s: text, line: 1}
	ds, end, err := parseBlock(t, 0)
	if err != nil {
		return nil, err
	}
	if end != tEOF {
		return nil, t.errf("unexpected \"}\"")
	}
	return ds, nil
}

func parseBlock(t *tokenizer, depth int) ([]Directive, int, error) {
	if depth > maxDepth {
		return nil, 0, t.errf("blocks nested more than %d deep", maxDepth)
	}
	var out []Directive
	var cur *Directive
	for {
		tk, err := t.next()
		if err != nil {
			return nil, 0, err
		}
		switch tk.kind {
		case tEOF, tClose:
			if cur != nil {
				return nil, 0, t.errf("unexpected end of block after %q", cur.Name)
			}
			if tk.kind == tEOF && depth > 0 {
				return nil, 0, t.errf("unexpected end of file, expecting \"}\"")
			}
			return out, tk.kind, nil
		case tWord:
			if cur == nil {
				cur = &Directive{Name: tk.text, File: t.file, Line: tk.line}
				continue
			}
			if len(cur.Args) >= maxArgs {
				return nil, 0, t.errf("more than %d arguments", maxArgs)
			}
			cur.Args = append(cur.Args, tk.text)
		case tSemi:
			if cur == nil {
				return nil, 0, t.errf("unexpected \";\"")
			}
			out = append(out, *cur)
			cur = nil
		case tOpen:
			if cur == nil {
				return nil, 0, t.errf("unexpected \"{\"")
			}
			if strings.HasSuffix(cur.Name, "_by_lua_block") || cur.Name == "lua_block" {
				// OpenResty: the block is Lua, not nginx syntax.
				if err := skipLua(t); err != nil {
					return nil, 0, err
				}
				cur.HasBlock = true
				out = append(out, *cur)
				cur = nil
				continue
			}
			body, end, err := parseBlock(t, depth+1)
			if err != nil {
				return nil, 0, err
			}
			if end != tClose {
				return nil, 0, t.errf("unexpected end of file, expecting \"}\"")
			}
			cur.Block, cur.HasBlock = body, true
			out = append(out, *cur)
			cur = nil
		}
	}
}

// skipLua passes over a Lua block: braces counted outside Lua strings and
// comments, as OpenResty's own block reader does.
func skipLua(t *tokenizer) error {
	depth := 1
	start := t.line
	for t.i < len(t.s) {
		c := t.s[t.i]
		switch {
		case c == '\n':
			t.line++
			t.i++
		case c == '-' && strings.HasPrefix(t.s[t.i:], "--"):
			t.i += 2
			if n, ok := longBracket(t.s[t.i:]); ok {
				if !t.skipLong(n) {
					return &ParseError{File: t.file, Line: start, Msg: "unterminated Lua comment"}
				}
				continue
			}
			for t.i < len(t.s) && t.s[t.i] != '\n' {
				t.i++
			}
		case c == '[':
			if n, ok := longBracket(t.s[t.i:]); ok {
				if !t.skipLong(n) {
					return &ParseError{File: t.file, Line: start, Msg: "unterminated Lua long string"}
				}
				continue
			}
			t.i++
		case c == '"' || c == '\'':
			t.i++
			for t.i < len(t.s) && t.s[t.i] != c && t.s[t.i] != '\n' {
				if t.s[t.i] == '\\' {
					t.i++
				}
				t.i++
			}
			t.i++
		case c == '{':
			depth++
			t.i++
		case c == '}':
			depth--
			t.i++
			if depth == 0 {
				return nil
			}
		default:
			t.i++
		}
	}
	return &ParseError{File: t.file, Line: start, Msg: "unterminated Lua block"}
}

// longBracket reports a Lua long bracket "[[" or "[==[" at s and its level.
func longBracket(s string) (int, bool) {
	if len(s) < 2 || s[0] != '[' {
		return 0, false
	}
	n := 1
	for n < len(s) && s[n] == '=' {
		n++
	}
	if n < len(s) && s[n] == '[' {
		return n - 1, true
	}
	return 0, false
}

func (t *tokenizer) skipLong(level int) bool {
	closer := "]" + strings.Repeat("=", level) + "]"
	t.i += level + 2
	j := strings.Index(t.s[t.i:], closer)
	if j < 0 {
		return false
	}
	t.line += strings.Count(t.s[t.i:t.i+j], "\n")
	t.i += j + len(closer)
	return true
}
