package repo

import "strings"

// word is one shell word: its value with quotes removed, and where its raw
// text sits in the logical command.
type word struct {
	val        string
	start, end int // byte offsets of the raw word in the logical text
	quoted     bool
	dynamic    bool // contains $ or ` outside single quotes: value not literal
}

// command is a simple command, and whether a pipe feeds it from the
// previous one.
type command struct {
	words  []word
	piped  bool
	redirs []redir
}

type redir struct {
	op     string // ">", ">>", "<"
	target word
}

// splitShell splits shell text into simple commands. It understands quotes,
// backslashes, comments, the separators ; & && || | and newlines, and
// redirections. It is not a full shell: what it cannot follow it keeps as
// literal text, and callers decide only on literal words.
func splitShell(s string) []command {
	var out []command
	cur := command{}
	var w strings.Builder
	in := false
	var ws word
	pendingRedir := ""
	flush := func(end int) {
		if !in {
			return
		}
		ws.end = end
		ws.val = w.String()
		if pendingRedir != "" {
			cur.redirs = append(cur.redirs, redir{op: pendingRedir, target: ws})
			pendingRedir = ""
		} else {
			cur.words = append(cur.words, ws)
		}
		w.Reset()
		in = false
		ws = word{}
	}
	endCmd := func(piped bool) {
		if len(cur.words) > 0 || len(cur.redirs) > 0 {
			out = append(out, cur)
		}
		cur = command{piped: piped}
	}
	start := func(i int) {
		if !in {
			in = true
			ws = word{start: i}
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			start(i)
			ws.quoted = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				w.WriteString(s[i+1:])
				i = len(s)
				continue
			}
			w.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			start(i)
			ws.quoted = true
			i++
			for ; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
					i++
					if s[i] != '\n' {
						w.WriteByte(s[i])
					}
					continue
				}
				if s[i] == '$' || s[i] == '`' {
					ws.dynamic = true
				}
				w.WriteByte(s[i])
			}
		case c == '\\':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++ // line continuation
				continue
			}
			start(i)
			if i+1 < len(s) {
				i++
				w.WriteByte(s[i])
			}
		case c == '#' && !in:
			for i < len(s) && s[i] != '\n' {
				i++
			}
			i--
		case c == ' ' || c == '\t' || c == '\r':
			flush(i)
		case c == '\n' || c == ';' || c == '(' || c == ')' || c == '{' && !in || c == '}' && !in:
			flush(i)
			endCmd(false)
		case c == '&':
			flush(i)
			if i+1 < len(s) && s[i+1] == '&' {
				i++
			} else if i > 0 && s[i-1] == '>' {
				continue
			}
			endCmd(false)
		case c == '|':
			flush(i)
			if i+1 < len(s) && s[i+1] == '|' {
				i++
				endCmd(false)
			} else {
				endCmd(true)
			}
		case c == '>' || c == '<':
			// A redirection: a leading fd number in the current word is
			// dropped with it.
			if in && isDigits(w.String()) {
				w.Reset()
				in = false
				ws = word{}
			} else {
				flush(i)
			}
			op := string(c)
			if c == '>' && i+1 < len(s) && s[i+1] == '>' {
				op = ">>"
				i++
			}
			if i+1 < len(s) && s[i+1] == '&' {
				i++
			}
			pendingRedir = op
		default:
			start(i)
			if c == '$' || c == '`' {
				ws.dynamic = true
			}
			w.WriteByte(c)
		}
	}
	flush(len(s))
	endCmd(false)
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// program returns the command's program name, past env assignments and
// wrappers like sudo, exec or env.
func (c command) program() (string, int) {
	for i := 0; i < len(c.words); i++ {
		v := c.words[i].val
		if strings.Contains(v, "=") && !strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "=") {
			continue
		}
		switch base(v) {
		case "sudo", "doas", "exec", "env", "command", "nohup", "time":
			continue
		}
		return base(v), i
	}
	return "", -1
}

func base(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
