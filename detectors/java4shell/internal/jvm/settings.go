package jvm

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Setting is a file that gives JVM options to the JVMs one product or
// service starts: a Tomcat or Atlassian setenv.sh, an Elasticsearch-style
// jvm.options, a JetBrains or install4j .vmoptions file, a systemd unit.
type Setting struct {
	File string `json:"file"`
	Kind string `json:"kind"` // setenv, jvm.options, vmoptions, systemd
	// Scope is the product directory whose JVMs the file configures; "" for
	// a systemd unit, which configures the service it starts.
	Scope string `json:"scope,omitempty"`
	// Unit is the systemd unit name.
	Unit string `json:"unit,omitempty"`
	// Exec is the program a systemd unit starts.
	Exec string `json:"exec,omitempty"`
	// Env are the JVM option variables a systemd unit sets, and ExecOpts
	// the JVM options its ExecStart gives java.
	Env      map[string]string `json:"env,omitempty"`
	ExecOpts []string          `json:"exec_options,omitempty"`
	// WindowsOnly is a batch file (setenv.bat): it applies only to Windows
	// runtimes.
	WindowsOnly bool `json:"windows_only,omitempty"`
	// ExecSet is true when the file sets ExecStart (a drop-in may not).
	ExecSet bool `json:"-"`
	lines   []optLine
}

// optLine is one option, with the Java releases it applies to
// (Elasticsearch's "17-:-XX:..." lines); hi 0 means no upper bound.
type optLine struct {
	lo, hi int
	word   string
}

// Options returns what the file sets for a runtime of the given Java
// release.
func (s Setting) Options(feature int) Options {
	var o Options
	s.ApplyTo(&o, feature)
	return o
}

// ApplyTo applies the file's options, in order, on top of o. For a
// systemd unit the order is HotSpot's: JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS,
// the command line, then _JAVA_OPTIONS.
func (s Setting) ApplyTo(o *Options, feature int) {
	if s.Kind == "systemd" {
		env := map[string]string{}
		for k, v := range s.Env {
			if k != "_JAVA_OPTIONS" {
				env[k] = v
			}
		}
		*o = FromEnv(env, nil, feature, nil)
		for _, w := range s.ExecOpts {
			o.ApplyWord(w, s.File)
		}
		if v, ok := s.Env["_JAVA_OPTIONS"]; ok {
			o.Apply(v, "_JAVA_OPTIONS in "+s.File)
		}
		return
	}
	for _, l := range s.lines {
		if feature > 0 && (l.lo > 0 && feature < l.lo || l.hi > 0 && feature > l.hi) {
			continue
		}
		o.ApplyWord(l.word, s.File)
	}
}

// Mentions reports whether the file sets either option at all.
func (s Setting) Mentions() bool { return len(s.lines) > 0 || len(s.ExecOpts) > 0 || len(s.Env) > 0 }

// SettingKind classifies a path, "" when it is not a settings file.
func SettingKind(p string) string {
	base := path.Base(p)
	dir := path.Dir(p)
	switch {
	case base == "setenv.sh" || base == "setenv.bat":
		return "setenv"
	case base == "jvm.options" || strings.HasPrefix(base, "jvm") && strings.HasSuffix(base, ".options") ||
		strings.HasSuffix(base, ".options") && path.Base(dir) == "jvm.options.d":
		return "jvm.options"
	case strings.HasSuffix(base, ".vmoptions"):
		return "vmoptions"
	case (strings.HasSuffix(base, ".service") || strings.HasSuffix(base, ".conf") && strings.HasSuffix(dir, ".service.d")) && systemdDir(p):
		return "systemd"
	}
	return ""
}

func systemdDir(p string) bool {
	for _, d := range []string{"/etc/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/", "/run/systemd/system/", "/usr/local/lib/systemd/system/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// maxSetting bounds a settings file.
const maxSetting = 1 << 20

var (
	xxRE          = regexp.MustCompile(`-XX:(?:[+-]UseBASE64Intrinsics|UseBASE64Intrinsics=(?:true|false)|UseAVX=\d{1,2})\b`)
	selectorRE    = regexp.MustCompile(`^(\d{1,3})(-(\d{1,3})?)?:`)
	fileReleaseRE = regexp.MustCompile(`^jvm(\d{1,2})-`)
	assignRE      = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	batSetRE      = regexp.MustCompile(`(?i)^set\s+"?([A-Za-z_][A-Za-z0-9_]*)=(.*?)"?\s*$`)
	shVarRE       = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	batVarRE      = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]*)%`)
)

// ReadSetting reads a settings file. ok is false when p is not one, or it
// is too large.
func ReadSetting(p string, b []byte) (Setting, bool) {
	kind := SettingKind(p)
	if kind == "" || len(b) > maxSetting {
		return Setting{}, false
	}
	s := Setting{File: p, Kind: kind}
	dir := path.Dir(p)
	switch kind {
	case "setenv", "vmoptions":
		if path.Base(dir) == "bin" {
			dir = path.Dir(dir)
		}
		s.Scope = scopeOrNone(dir)
	case "jvm.options":
		if path.Base(dir) == "jvm.options.d" {
			dir = path.Dir(dir)
		}
		if b := path.Base(dir); b == "config" || b == "conf" || b == "etc" {
			dir = path.Dir(dir)
		}
		s.Scope = scopeOrNone(dir)
	case "systemd":
		u := path.Base(p)
		if strings.HasSuffix(dir, ".service.d") {
			u = path.Base(dir)
			u = strings.TrimSuffix(u, ".d")
		}
		s.Unit = u
		s.Env = map[string]string{}
	}
	if kind == "setenv" {
		s.WindowsOnly = strings.HasSuffix(p, ".bat")
		readSetenv(&s, string(b))
		return s, true
	}
	// Cassandra names the Java release a file is for: jvm11-server.options.
	fileLo := 0
	if m := fileReleaseRE.FindStringSubmatch(path.Base(p)); m != nil && kind == "jvm.options" {
		fileLo, _ = strconv.Atoi(m[1])
	}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(strings.ToLower(line), "rem ") {
			continue
		}
		switch kind {
		case "jvm.options", "vmoptions":
			lo, hi := 0, 0
			if m := selectorRE.FindStringSubmatch(line); m != nil {
				lo, _ = strconv.Atoi(m[1])
				switch {
				case m[2] == "":
					hi = lo
				case m[3] != "":
					hi, _ = strconv.Atoi(m[3])
				}
				line = line[len(m[0]):]
			}
			if fileLo > 0 {
				lo, hi = fileLo, fileLo
			}
			if xxRE.MatchString(line) && strings.HasPrefix(line, "-XX:") {
				s.lines = append(s.lines, optLine{lo, hi, strings.TrimSpace(line)})
			}
		case "systemd":
			s.systemdLine(line)
		}
	}
	return s, true
}

// broadDirs are directories too general to be one product's: a settings
// file there configures no runtime by its place.
var broadDirs = map[string]bool{"/": true, ".": true, "": true, "/usr": true, "/usr/local": true, "/usr/share": true, "/usr/lib": true,
	"/opt": true, "/etc": true, "/var": true, "/srv": true, "/home": true, "/root": true, "/app": true, "/usr/local/share": true, "/var/lib": true}

func scopeOrNone(dir string) string {
	if broadDirs[dir] {
		return ""
	}
	return dir
}

// stripComment drops a shell comment: a "#" that starts a word, outside
// quotes.
func stripComment(line string) string {
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '\\':
			i++
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t' || line[i-1] == ';'):
			return line[:i]
		}
	}
	return line
}

// MergeUnits joins systemd unit files the way systemd does: the unit file
// from the directory with the highest precedence (/etc, then /run, then
// /usr/local/lib, /usr/lib, /lib), then its drop-ins in name order, later
// assignments replacing earlier ones. It returns one setting per unit.
func MergeUnits(settings []Setting) []Setting {
	rank := func(p string) int {
		for i, d := range []string{"/etc/systemd/system/", "/run/systemd/system/", "/usr/local/lib/systemd/system/", "/usr/lib/systemd/system/", "/lib/systemd/system/"} {
			if strings.HasPrefix(p, d) {
				return i
			}
		}
		return 9
	}
	mains := map[string]Setting{}
	drops := map[string][]Setting{}
	for _, s := range settings {
		if s.Kind != "systemd" {
			continue
		}
		if strings.HasSuffix(path.Dir(s.File), ".service.d") {
			drops[s.Unit] = append(drops[s.Unit], s)
			continue
		}
		if m, ok := mains[s.Unit]; !ok || rank(s.File) < rank(m.File) {
			mains[s.Unit] = s
		}
	}
	var out []Setting
	units := map[string]bool{}
	for u := range mains {
		units[u] = true
	}
	for u := range drops {
		units[u] = true
	}
	names := make([]string, 0, len(units))
	for u := range units {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, u := range names {
		m := mains[u]
		merged := Setting{File: m.File, Kind: "systemd", Unit: u, Exec: m.Exec, ExecOpts: m.ExecOpts, ExecSet: m.ExecSet, Env: map[string]string{}}
		for k, v := range m.Env {
			merged.Env[k] = v
		}
		ds := drops[u]
		sort.SliceStable(ds, func(i, j int) bool { return path.Base(ds[i].File) < path.Base(ds[j].File) })
		for _, d := range ds {
			if merged.File == "" {
				merged.File = d.File
			} else {
				merged.File += ", " + d.File
			}
			for k, v := range d.Env {
				merged.Env[k] = v
			}
			if d.ExecSet {
				merged.Exec, merged.ExecOpts, merged.ExecSet = d.Exec, d.ExecOpts, true
			}
		}
		out = append(out, merged)
	}
	return out
}

func (s *Setting) systemdLine(line string) {
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	switch strings.TrimSpace(k) {
	case "Environment":
		// Only the variables the JVM itself reads: a script variable such
		// as JAVA_OPTS reaches java only through a start script.
		for _, a := range Words(v) {
			name, val, ok := strings.Cut(a, "=")
			if !ok {
				continue
			}
			for _, n := range EnvVars {
				if name == n {
					s.Env[name] = val
				}
			}
		}
	case "ExecStart":
		v = strings.TrimSpace(v)
		s.ExecSet = true
		s.Exec, s.ExecOpts = "", nil
		v = strings.TrimLeft(v, "-@:+!")
		ws := Words(v)
		if len(ws) == 0 {
			return // "ExecStart=" resets the command
		}
		s.Exec = ws[0]
		if opts, ok := JavaOptions(ws); ok {
			for _, w := range opts {
				if xxRE.MatchString(w) {
					s.ExecOpts = append(s.ExecOpts, w)
				}
			}
		}
	}
}

// launcherVars are the variables a start script passes to java.
func launcherVar(name string) bool {
	for _, n := range EnvVars {
		if n == name {
			return true
		}
	}
	for _, n := range ScriptVars {
		if n == name {
			return true
		}
	}
	return false
}

// shellControl are the words that make what follows conditional or
// repeated.
var shellControl = map[string]bool{"if": true, "then": true, "else": true, "elif": true, "fi": true, "case": true, "esac": true,
	"for": true, "while": true, "until": true, "do": true, "done": true, "&&": true, "||": true, "{": true, "}": true, "function": true}

// readSetenv reads a start script's settings file the way the script
// uses it: only the variables the launcher passes to java count, the last
// assignment wins ("$VAR ..." appends), and a file that sets one of them
// under a condition, in a loop or in a function counts for nothing, since
// which value java gets cannot be known without running it. Batch files
// (setenv.bat) are read the same way with "set NAME=value" and %NAME%.
func readSetenv(s *Setting, text string) {
	vals := map[string]string{}
	var order []string
	depth := 0
	uncertain := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		var name, value string
		if s.WindowsOnly {
			low := strings.ToLower(line)
			if line == "" || strings.HasPrefix(low, "rem") && (len(low) == 3 || low[3] == ' ') || strings.HasPrefix(line, "::") || strings.HasPrefix(line, "@rem") {
				continue
			}
			if strings.HasPrefix(low, "if ") || strings.HasPrefix(low, "for ") || strings.HasPrefix(low, "goto") || strings.HasPrefix(line, ":") || strings.Contains(line, "(") || strings.Contains(line, ")") {
				for _, n := range append(append([]string{}, EnvVars...), ScriptVars...) {
					if strings.Contains(line, n) {
						uncertain = true
					}
				}
				continue
			}
			m := batSetRE.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			name = m[1]
			value = batVarRE.ReplaceAllStringFunc(m[2], func(v string) string { return vals[strings.Trim(v, "%")] })
		} else {
			line = strings.TrimSpace(stripComment(line))
			if line == "" {
				continue
			}
			words := Words(line)
			cond := depth > 0
			for _, w := range words {
				w = strings.TrimSuffix(w, ";")
				if shellControl[w] {
					cond = true
				}
				switch w {
				case "if", "case", "for", "while", "until":
					depth++
				case "fi", "esac", "done":
					if depth > 0 {
						depth--
					}
				}
			}
			m := assignRE.FindStringSubmatch(line)
			if m == nil {
				if cond {
					for _, n := range append(append([]string{}, EnvVars...), ScriptVars...) {
						if strings.Contains(line, n+"=") {
							uncertain = true
						}
					}
				}
				continue
			}
			if cond {
				if launcherVar(m[1]) {
					uncertain = true
				}
				continue
			}
			name = m[1]
			value = strings.Join(Words(m[2]), " ")
			value = shVarRE.ReplaceAllStringFunc(value, func(v string) string {
				return vals[strings.Trim(v, "${}")]
			})
		}
		if !launcherVar(name) {
			continue
		}
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = value
	}
	if uncertain {
		return
	}
	for _, n := range order {
		for _, w := range xxRE.FindAllString(vals[n], -1) {
			s.lines = append(s.lines, optLine{0, 0, w})
		}
	}
}
