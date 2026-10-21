package refs

import (
	"errors"
	"fmt"
	"unicode"
)

// varInfo is what a variable lookup found.
type varInfo struct {
	val ptext
	set bool
	// plainErr is returned when the variable is used without a default
	// operator ($X, ${X}) and is not set. nil means "expand to empty", which is
	// what BuildKit does; the scanner sets it so that it never guesses a value.
	plainErr error
	// hardErr is returned for any use at all (a value that depends on the build
	// platform, an ARG whose own default could not be resolved).
	hardErr error
}

type lookupFunc func(name string) varInfo

// shellLexer is a port of BuildKit's frontend/dockerfile/shell word processing
// (shell_parser.go), keeping track of where each output byte was written.
type shellLexer struct {
	in        ptext
	i         int
	escape    byte
	rawQuotes bool
	rawEsc    bool
	env       lookupFunc
	used      []string
	depth     int
}

const maxSubstDepth = 64

// maxExpansion caps a word's expanded length. Image references are at most a
// few hundred bytes, and without a cap a chain of ARGs that each double the
// last (ARG B=$A$A, ARG C=$B$B, ...) grows exponentially and exhausts memory.
const maxExpansion = 8 << 10

var errTooLong = errors.New("variable expansion longer than 8 KiB; not an image reference")

var errMissingBrace = errors.New("syntax error: missing '}'")

func (l *shellLexer) processWord() (ptext, error) {
	res, _, _, err := l.processStopOn(0, false)
	return res, err
}

func (l *shellLexer) processWords() ([]ptext, error) {
	_, words, _, err := l.processStopOn(0, false)
	return words, err
}

type wordsAcc struct {
	word   ptext
	words  []ptext
	inWord bool
}

func (w *wordsAcc) addChar(r rune, bs ptext) {
	if unicode.IsSpace(r) {
		if w.inWord && len(w.word) != 0 {
			w.words = append(w.words, w.word)
			w.word = nil
			w.inWord = false
		}
		return
	}
	w.addRaw(bs)
}

func (w *wordsAcc) addRaw(bs ptext) {
	w.word = append(w.word, bs...)
	w.inWord = true
}

func (w *wordsAcc) addString(t ptext) {
	for i := 0; i < len(t); {
		r, n := t.runeAt(i)
		w.addChar(r, t[i:i+n])
		i += n
	}
}

func (w *wordsAcc) get() []ptext {
	if len(w.word) > 0 {
		w.words = append(w.words, w.word)
		w.word = nil
		w.inWord = false
	}
	return w.words
}

func (l *shellLexer) eof() bool { return l.i >= len(l.in) }

func (l *shellLexer) peek() byte { return l.in[l.i].b }

func (l *shellLexer) next() (ptext, rune) {
	r, n := l.in.runeAt(l.i)
	bs := l.in[l.i : l.i+n]
	l.i += n
	return bs, r
}

func (l *shellLexer) processStopOn(stop byte, hasStop bool) (ptext, []ptext, bool, error) {
	var res ptext
	var w wordsAcc
	for !l.eof() {
		c := l.peek()
		if hasStop && c == stop {
			l.i++
			return res, w.get(), true, nil
		}
		switch c {
		case '$':
			v, err := l.dollar()
			if err != nil {
				return nil, nil, false, err
			}
			if len(res)+len(v) > maxExpansion {
				return nil, nil, false, errTooLong
			}
			res = append(res, v...)
			w.addString(v)
		case '\'':
			v, err := l.singleQuote()
			if err != nil {
				return nil, nil, false, err
			}
			res = append(res, v...)
			w.addRaw(v)
		case '"':
			v, err := l.doubleQuote()
			if err != nil {
				return nil, nil, false, err
			}
			res = append(res, v...)
			w.addRaw(v)
		default:
			bs, r := l.next()
			if r == rune(l.escape) {
				if l.rawEsc {
					w.addRaw(bs)
					res = append(res, bs...)
				}
				if l.eof() {
					// An escape at the end of the word is dropped.
					goto done
				}
				bs, _ = l.next()
				w.addRaw(bs)
			} else {
				w.addChar(r, bs)
			}
			res = append(res, bs...)
		}
	}
done:
	if hasStop {
		return nil, nil, false, nil
	}
	return res, w.get(), true, nil
}

func (l *shellLexer) singleQuote() (ptext, error) {
	var res ptext
	bs, _ := l.next()
	if l.rawQuotes {
		res = append(res, bs...)
	}
	for {
		if l.eof() {
			return nil, errors.New("unexpected end of statement while looking for matching single-quote")
		}
		bs, r := l.next()
		if r == '\'' {
			if l.rawQuotes {
				res = append(res, bs...)
			}
			return res, nil
		}
		res = append(res, bs...)
	}
}

func (l *shellLexer) doubleQuote() (ptext, error) {
	var res ptext
	bs, _ := l.next()
	if l.rawQuotes {
		res = append(res, bs...)
	}
	for {
		if l.eof() {
			return nil, errors.New("unexpected end of statement while looking for matching double-quote")
		}
		switch l.peek() {
		case '"':
			bs, _ := l.next()
			if l.rawQuotes {
				res = append(res, bs...)
			}
			return res, nil
		case '$':
			v, err := l.dollar()
			if err != nil {
				return nil, err
			}
			if len(res)+len(v) > maxExpansion {
				return nil, errTooLong
			}
			res = append(res, v...)
		default:
			bs, r := l.next()
			if r == rune(l.escape) {
				if l.rawEsc {
					res = append(res, bs...)
				}
				if l.eof() {
					continue
				}
				switch nc := l.peek(); nc {
				case '"', '$', l.escape:
					bs, _ = l.next()
				}
			}
			res = append(res, bs...)
		}
	}
}

// name reads a variable name the way BuildKit's processName does.
func (l *shellLexer) name() string {
	var out []byte
	for !l.eof() {
		r, n := l.in.runeAt(l.i)
		if len(out) == 0 && unicode.IsDigit(r) {
			for !l.eof() {
				r, n := l.in.runeAt(l.i)
				if !unicode.IsDigit(r) {
					break
				}
				for k := 0; k < n; k++ {
					out = append(out, l.in[l.i+k].b)
				}
				l.i += n
			}
			return string(out)
		}
		if len(out) == 0 && isSpecialParam(r) {
			l.i += n
			return string(r)
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			break
		}
		for k := 0; k < n; k++ {
			out = append(out, l.in[l.i+k].b)
		}
		l.i += n
	}
	return string(out)
}

func isSpecialParam(r rune) bool {
	switch r {
	case '@', '*', '#', '?', '-', '$', '!', '0':
		return true
	}
	return false
}

func (l *shellLexer) note(name string) {
	for _, u := range l.used {
		if u == name {
			return
		}
	}
	l.used = append(l.used, name)
}

func (l *shellLexer) lookupPlain(name string) (ptext, error) {
	l.note(name)
	v := l.env(name)
	if v.hardErr != nil {
		return nil, v.hardErr
	}
	if !v.set {
		if v.plainErr != nil {
			return nil, v.plainErr
		}
		return nil, nil
	}
	if len(v.val) > maxExpansion {
		return nil, errTooLong
	}
	return v.val, nil
}

func (l *shellLexer) dollar() (ptext, error) {
	l.depth++
	defer func() { l.depth-- }()
	if l.depth > maxSubstDepth {
		return nil, errors.New("variable substitution nested too deeply")
	}
	dollar := l.in[l.i : l.i+1]
	l.i++
	if l.eof() || l.peek() != '{' {
		name := l.name()
		if name == "" {
			return dollar, nil
		}
		return l.lookupPlain(name)
	}
	l.i++ // {
	if l.eof() {
		return nil, errMissingBrace
	}
	switch l.peek() {
	case '{', '}', ':':
		return nil, errors.New("syntax error: bad substitution")
	}
	name := l.name()
	if l.eof() {
		return nil, errMissingBrace
	}
	ch := l.peek()
	l.i++
	switch ch {
	case '}':
		return l.lookupPlain(name)
	case '?':
		_, _, found, err := l.processStopOn('}', true)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errMissingBrace
		}
		l.note(name)
		v := l.env(name)
		if v.hardErr != nil {
			return nil, v.hardErr
		}
		if !v.set {
			return nil, fmt.Errorf("%s: is not allowed to be unset", name)
		}
		return v.val, nil
	case ':':
		if l.eof() {
			return nil, errMissingBrace
		}
		mod := l.peek()
		l.i++
		word, _, found, err := l.processStopOn('}', true)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errMissingBrace
		}
		l.note(name)
		v := l.env(name)
		if v.hardErr != nil {
			return nil, v.hardErr
		}
		switch mod {
		case '+':
			if len(v.val) != 0 {
				return word, nil
			}
			return v.val, nil
		case '-':
			if len(v.val) == 0 {
				return word, nil
			}
			return v.val, nil
		case '?':
			if len(v.val) == 0 {
				return nil, fmt.Errorf("%s: is not allowed to be empty", name)
			}
			return v.val, nil
		default:
			return nil, fmt.Errorf("unsupported modifier (%c) in substitution", mod)
		}
	case '+', '-':
		word, _, found, err := l.processStopOn('}', true)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, errMissingBrace
		}
		l.note(name)
		v := l.env(name)
		if v.hardErr != nil {
			return nil, v.hardErr
		}
		if ch == '+' {
			if v.set {
				return word, nil
			}
			return nil, nil
		}
		if !v.set {
			return word, nil
		}
		return v.val, nil
	case '#', '%', '/':
		return nil, fmt.Errorf("pattern substitution (%c) in ${%s...} is not supported by the scanner", ch, name)
	default:
		return nil, fmt.Errorf("unsupported modifier (%c) in substitution", ch)
	}
}
