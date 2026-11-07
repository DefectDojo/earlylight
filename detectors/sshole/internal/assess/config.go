package assess

import (
	"path"
	"strings"
)

// Config is an sshd_config, flattened through Include, as a list of
// directives each with the Match criteria it sits under.
type Config struct {
	Path       string      `json:"path"`
	Read       bool        `json:"read"`
	Directives []Directive `json:"-"`
	// Missing lists Include patterns that matched no file, and files that
	// could not be read.
	Missing []string `json:"missing,omitempty"`
}

// Directive is one keyword line.
type Directive struct {
	Key   string // lower case
	Args  []string
	File  string
	Line  int
	Match []Criterion // nil: global
	Block int         // index of the Match block (0: global)
}

// Criterion is one Match criterion ("User", "alice,bob").
type Criterion struct {
	Key, Value string
}

// Files gives a config reader access to the target's files.
type Files interface {
	// Read returns a regular file's content, or nil.
	Read(p string) []byte
	// Glob returns the files matching an absolute glob pattern, sorted.
	Glob(pattern string) []string
}

// ParseConfig reads an sshd_config and every file it includes, the way
// servconf.c does: relative Include paths are under /etc/ssh, globs expand
// in sorted order, and a Match inside an included file ends with that file.
func ParseConfig(files Files, p string) Config {
	c := Config{Path: p}
	data := files.Read(p)
	if data == nil {
		return c
	}
	c.Read = true
	block := 0
	filesRead := 1
	onStack := map[string]bool{}
	var walk func(file string, data []byte, match []Criterion, depth int)
	walk = func(file string, data []byte, match []Criterion, depth int) {
		onStack[file] = true
		defer delete(onStack, file)
		cur := match
		curBlock := block
		for i, raw := range lines(data) {
			args := splitArgs(raw)
			if len(args) == 0 {
				continue
			}
			key := strings.ToLower(args[0])
			switch key {
			case "match":
				block++
				curBlock = block
				cur = parseMatch(args[1:])
				continue
			case "include":
				if depth >= 16 {
					c.Missing = append(c.Missing, file+": Include nested too deeply")
					continue
				}
				for _, pat := range args[1:] {
					if !strings.HasPrefix(pat, "/") && !strings.HasPrefix(pat, "~") {
						pat = path.Join("/etc/ssh", pat)
					}
					got := files.Glob(pat)
					if len(got) == 0 && !hasGlob(pat) {
						c.Missing = append(c.Missing, pat)
					}
					for _, g := range got {
						if onStack[g] {
							c.Missing = append(c.Missing, g+": includes itself")
							continue
						}
						if filesRead >= maxIncludes {
							c.Missing = append(c.Missing, g+": more than 256 included files; the rest are not read")
							break
						}
						filesRead++
						if b := files.Read(g); b != nil {
							walk(g, b, cur, depth+1)
						} else {
							c.Missing = append(c.Missing, g)
						}
					}
				}
				continue
			}
			if len(c.Directives) >= maxDirectives {
				c.Missing = append(c.Missing, file+": more than 100000 directives; the rest are not read")
				return
			}
			c.Directives = append(c.Directives, Directive{Key: key, Args: args[1:], File: file, Line: i + 1, Match: cur, Block: curBlock})
		}
	}
	walk(p, data, nil, 0)
	return c
}

// Limits on what one sshd_config can make the parser read.
const (
	maxIncludes   = 256
	maxDirectives = 100000
)

func hasGlob(p string) bool { return strings.ContainsAny(p, "*?[") }

// splitArgs splits a config line the way servconf.c reads it: the keyword
// ends at whitespace or '=', then words separated by whitespace with double
// quotes grouping, and '#' starting a comment outside quotes.
func splitArgs(line string) []string {
	line = strings.TrimLeft(line, " \t\r")
	if line == "" || line[0] == '#' {
		return nil
	}
	k := strings.IndexAny(line, " \t\r=")
	if k < 0 {
		return []string{line}
	}
	out := []string{line[:k]}
	rest := strings.TrimLeft(line[k:], " \t\r")
	if strings.HasPrefix(rest, "=") {
		rest = rest[1:]
	}
	var b strings.Builder
	in, quoted := false, false
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case quoted:
			if c == '"' {
				quoted = false
			} else {
				b.WriteByte(c)
			}
		case c == '"':
			quoted, in = true, true
		case c == '#':
			i = len(rest)
		case c == ' ' || c == '\t' || c == '\r':
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

func parseMatch(args []string) []Criterion {
	var out []Criterion
	for i := 0; i < len(args); i++ {
		k := strings.ToLower(args[i])
		if k == "all" || k == "canonical" || k == "final" || k == "invalid-user" {
			out = append(out, Criterion{Key: k})
			continue
		}
		v := ""
		if j := strings.IndexByte(args[i], '='); j > 0 {
			k, v = strings.ToLower(args[i][:j]), args[i][j+1:]
		} else if i+1 < len(args) {
			i++
			v = args[i]
		}
		out = append(out, Criterion{Key: k, Value: v})
	}
	if len(out) == 0 {
		out = []Criterion{{Key: "unknown"}}
	}
	return out
}

// Tri is a three-valued answer.
type Tri int

const (
	No Tri = iota
	Maybe
	Yes
)

// matches says whether a Match block applies to a connection by user.
func matches(crit []Criterion, acc Account, groups []string) Tri {
	res := Yes
	for _, c := range crit {
		var t Tri
		switch c.Key {
		case "all":
			t = Yes
		case "user":
			t = boolTri(matchPatternList(acc.Name, c.Value))
		case "group":
			t = No
			for _, g := range groups {
				if matchPatternList(g, c.Value) {
					t = Yes
				}
			}
		case "invalid-user":
			t = No // the accounts that matter exist
		default:
			t = Maybe // Address, Host, LocalPort, Exec, Version...: depends on the connection
		}
		if t == No {
			return No
		}
		if t == Maybe {
			res = Maybe
		}
	}
	return res
}

func boolTri(b bool) Tri {
	if b {
		return Yes
	}
	return No
}

// matchPatternList is OpenSSH's match_pattern_list: comma-separated globs,
// a leading '!' negates and a negated match wins.
func matchPatternList(s, list string) bool {
	got := false
	for _, p := range strings.Split(list, ",") {
		neg := strings.HasPrefix(p, "!")
		if neg {
			p = p[1:]
		}
		if p == "" {
			continue
		}
		if globMatch(p, s) {
			if neg {
				return false
			}
			got = true
		}
	}
	return got
}

// globMatch is OpenSSH's match_pattern: '*' and '?' only. Iterative, with
// one backtrack point, so it runs in time linear in the input for each star.
func globMatch(p, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == s[si]):
			pi++
			si++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// Values returns every value a single-valued keyword can take for a
// connection by acc: the first value in each Match block that may apply,
// up to the first block that certainly applies, else the global value (the
// first one, as sshd keeps the first value it reads), else def.
func (c Config) Values(key string, acc Account, groups []string, def string) []string {
	global := ""
	haveGlobal := false
	type blk struct {
		tri Tri
		val string
	}
	var blocks []blk
	seen := map[int]bool{}
	for _, d := range c.Directives {
		if d.Key != key || len(d.Args) == 0 {
			continue
		}
		val := strings.Join(d.Args, " ")
		if d.Match == nil {
			if !haveGlobal {
				global, haveGlobal = val, true
			}
			continue
		}
		if seen[d.Block] {
			continue
		}
		seen[d.Block] = true
		if t := matches(d.Match, acc, groups); t != No {
			blocks = append(blocks, blk{t, val})
		}
	}
	var out []string
	for _, b := range blocks {
		out = appendOnce(out, b.val)
		if b.tri == Yes {
			return out
		}
	}
	if !haveGlobal {
		global = def
	}
	return appendOnce(out, global)
}

// Lists returns the patterns of a list keyword (AllowUsers, DenyUsers...)
// for each way a connection by acc can resolve: global lines accumulate, a
// Match block that sets the keyword replaces them. nil entries mean unset.
func (c Config) Lists(key string, acc Account, groups []string) [][]string {
	var global []string
	set := false
	blockVals := map[int][]string{}
	var order []int
	tri := map[int]Tri{}
	for _, d := range c.Directives {
		if d.Key != key {
			continue
		}
		if d.Match == nil {
			global = append(global, d.Args...)
			set = true
			continue
		}
		t := matches(d.Match, acc, groups)
		if t == No {
			continue
		}
		if _, ok := blockVals[d.Block]; !ok {
			order = append(order, d.Block)
			tri[d.Block] = t
		}
		blockVals[d.Block] = append(blockVals[d.Block], d.Args...)
	}
	var out [][]string
	for _, b := range order {
		out = append(out, blockVals[b])
		if tri[b] == Yes {
			return out
		}
	}
	if !set {
		global = nil
	}
	return append(out, global)
}

// Prepend puts directives before the file's own, as global ones: sshd -o
// options, which sshd reads before its config file, so they win.
func (c *Config) Prepend(ds []Directive) {
	c.Directives = append(append([]Directive(nil), ds...), c.Directives...)
}

// Global returns a global-only keyword's value (UsePAM), or def.
func (c Config) Global(key, def string) string {
	for _, d := range c.Directives {
		if d.Key == key && d.Match == nil && len(d.Args) > 0 {
			return d.Args[0]
		}
	}
	return def
}
