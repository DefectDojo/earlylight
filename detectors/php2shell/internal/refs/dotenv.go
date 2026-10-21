package refs

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Compose reads variables for interpolation from the shell environment and
// from the .env file in the project directory (by default, the directory of
// the Compose file), the shell winning. The scanner reads only that .env file:
// a variable it defines replaces the Compose default, exactly as when Compose
// runs without the variable exported in the shell.
//
// Only simple .env values are used: KEY=value (optionally "export KEY=value")
// where the value is unquoted, '...' or "..." on one line and contains no
// variable reference or escape. A variable whose .env line is more complex
// makes the references that use it unresolvable, and so does any .env line the
// scanner cannot parse (it might define the variable).

type dotEnvEntry struct {
	val  ptext
	line int
	err  error
}

type dotEnv struct {
	file    string
	vars    map[string]dotEnvEntry
	fileErr error
}

var reEnvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

func (s *scanner) loadDotEnv(rel string) *dotEnv {
	e := &dotEnv{file: rel, vars: map[string]dotEnvEntry{}}
	b, err := s.read(rel)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return e
	case err != nil:
		e.fileErr = fmt.Errorf("%s is unreadable: %v", rel, err)
		return e
	}
	parseDotEnv(e, b)
	return e
}

func parseDotEnv(e *dotEnv, b []byte) {
	for _, l := range splitLines(b) {
		t := strings.TrimSpace(l.text)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		lead := len(l.text) - len(strings.TrimLeft(l.text, " \t"))
		body := l.text[lead:]
		if strings.HasPrefix(body, "export ") {
			n := len("export ")
			for n < len(body) && (body[n] == ' ' || body[n] == '\t') {
				n++
			}
			lead += n
			body = body[n:]
		}
		eq := strings.IndexByte(body, '=')
		if eq < 0 {
			e.fileErr = fmt.Errorf("%s line %d is not KEY=VALUE", e.file, l.num)
			return
		}
		key := strings.TrimRight(body[:eq], " \t")
		if !reEnvKey.MatchString(key) {
			e.fileErr = fmt.Errorf("%s line %d has an unsupported key %q", e.file, l.num, key)
			return
		}
		vs := lead + eq + 1
		for vs < len(l.text) && (l.text[vs] == ' ' || l.text[vs] == '\t') {
			vs++
		}
		raw := l.text[vs:]
		col := l.off + vs
		ent := dotEnvEntry{line: l.num}
		switch {
		case strings.HasPrefix(raw, "'") || strings.HasPrefix(raw, `"`):
			q := raw[:1]
			end := strings.Index(raw[1:], q)
			if end < 0 {
				ent.err = fmt.Errorf("%s line %d: multi-line or unterminated quoted value is not supported", e.file, l.num)
				break
			}
			content := raw[1 : 1+end]
			after := strings.TrimSpace(raw[2+end:])
			if after != "" && !strings.HasPrefix(after, "#") {
				ent.err = fmt.Errorf("%s line %d: text after the quoted value", e.file, l.num)
				break
			}
			if q == `"` && strings.ContainsAny(content, `\$`) {
				ent.err = fmt.Errorf("%s line %d: escapes and variables in double-quoted values are not supported", e.file, l.num)
				break
			}
			ent.val = newPText(e.file, l.num, col+1, content)
		default:
			v := raw
			if i := strings.Index(v, " #"); i >= 0 {
				v = v[:i]
			}
			if i := strings.Index(v, "\t#"); i >= 0 {
				v = v[:i]
			}
			v = strings.TrimRight(v, " \t")
			if strings.ContainsAny(v, "$\\\"'") {
				ent.err = fmt.Errorf("%s line %d: variables, escapes and quotes inside unquoted values are not supported", e.file, l.num)
				break
			}
			ent.val = newPText(e.file, l.num, col, v)
		}
		key = strings.TrimSpace(key)
		if ent.err == nil {
			ent.val = ent.val.withVar(key)
		}
		e.vars[key] = ent
	}
}

// lookup returns a variable's .env value; set is false when .env does not
// define it.
func (e *dotEnv) lookup(name string) (ptext, bool, VarUse, error) {
	use := VarUse{Name: name}
	if e == nil {
		return nil, false, use, nil
	}
	if e.fileErr != nil {
		return nil, false, use, e.fileErr
	}
	ent, ok := e.vars[name]
	if !ok {
		return nil, false, use, nil
	}
	if ent.err != nil {
		return nil, false, use, ent.err
	}
	use.File, use.Line = e.file, ent.line
	return ent.val, true, use, nil
}
