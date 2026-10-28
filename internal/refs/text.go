package refs

import (
	"strings"
	"unicode/utf8"
)

// src is where one byte of resolved text was written.
type src struct {
	file string
	line int // 1-based; 0 when the byte has no single place in a file
	col  int // 0-based byte offset in the line; -1 when not written verbatim
	vr   string
}

// pchar is one byte of text with its source.
type pchar struct {
	b byte
	s src
}

// ptext is text that remembers, byte by byte, where it was written. Expanding
// variables copies the bytes of the variable's value, so a resolved image
// reference knows which file, line and column each of its bytes came from.
type ptext []pchar

func (t ptext) String() string {
	var b strings.Builder
	b.Grow(len(t))
	for _, c := range t {
		b.WriteByte(c.b)
	}
	return b.String()
}

// newPText makes text written verbatim at file:line starting at byte col.
func newPText(file string, line, col int, s string) ptext {
	t := make(ptext, len(s))
	for i := 0; i < len(s); i++ {
		c := col + i
		if col < 0 {
			c = -1
		}
		t[i] = pchar{b: s[i], s: src{file: file, line: line, col: c}}
	}
	return t
}

// withVar marks every byte as supplied by variable name (keeping inner marks).
func (t ptext) withVar(name string) ptext {
	out := make(ptext, len(t))
	for i, c := range t {
		if c.s.vr == "" {
			c.s.vr = name
		}
		out[i] = c
	}
	return out
}

// runeAt decodes the rune starting at t[i].
func (t ptext) runeAt(i int) (rune, int) {
	var buf [utf8.UTFMax]byte
	n := 0
	for j := i; j < len(t) && n < utf8.UTFMax; j++ {
		buf[n] = t[j].b
		n++
	}
	return utf8.DecodeRune(buf[:n])
}

// Part is a piece of a resolved image reference and where it was written.
// Concatenating the Text of a Ref's Parts gives its Image.
type Part struct {
	Text string `json:"text"`
	// File and Line locate the text; Line is 0 for text with no single
	// location (a separator the scanner added, such as the ":" between a Helm
	// values repository and tag).
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Column is the 1-based byte column at which Text appears verbatim on Line,
	// or 0 when it does not (it was quoted with escapes, folded, ...). Only a
	// Part with a Column can be edited.
	Column int `json:"column,omitempty"`
	// Var names the variable (Dockerfile ARG, Compose or .env variable) whose
	// value supplied the text, or "" for text written in the reference itself
	// (including a ${VAR:-default} default written there).
	Var string `json:"var,omitempty"`
}

// parts groups resolved text into runs written contiguously on one line.
func (t ptext) parts() []Part {
	var out []Part
	for i := 0; i < len(t); {
		c := t[i]
		j := i + 1
		for j < len(t) {
			d := t[j]
			if d.s.file != c.s.file || d.s.line != c.s.line || d.s.vr != c.s.vr {
				break
			}
			verbatimRun := c.s.col >= 0 && d.s.col == c.s.col+(j-i)
			opaqueRun := c.s.col < 0 && d.s.col < 0
			if !verbatimRun && !opaqueRun {
				break
			}
			j++
		}
		p := Part{Text: t[i:j].String(), File: c.s.file, Line: c.s.line, Var: c.s.vr}
		if c.s.line > 0 && c.s.col >= 0 {
			p.Column = c.s.col + 1
		}
		out = append(out, p)
		i = j
	}
	return out
}

// srcLine is one line of a file without its terminator.
type srcLine struct {
	text string
	num  int // 1-based
	off  int // bytes dropped from the start (a byte-order mark on line 1)
}

// splitLines splits like bufio.ScanLines: on "\n", dropping one "\r" before it
// (and at the end of a final unterminated line). A UTF-8 byte-order mark at the
// start of the file is dropped from line 1.
func splitLines(b []byte) []srcLine {
	s := string(b)
	var out []srcLine
	num := 0
	for len(s) > 0 {
		num++
		var line string
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			line, s = s[:i], s[i+1:]
		} else {
			line, s = s, ""
		}
		line = strings.TrimSuffix(line, "\r")
		l := srcLine{text: line, num: num}
		if num == 1 && strings.HasPrefix(line, "\uFEFF") {
			l.text = line[3:]
			l.off = 3
		}
		out = append(out, l)
	}
	return out
}

// rawLines splits content into lines exactly as stored, without terminators,
// keeping any byte-order mark (used to check verbatim columns).
func rawLines(b []byte) []string {
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}
