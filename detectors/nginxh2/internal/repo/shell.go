package repo

import (
	"path"
	"regexp"
	"strings"
)

// The shell reading here follows java4shell's (internal/repo and
// internal/jvm on that branch): a RUN line is read the way the builder's
// shell would run it, so an install hidden in a subshell, behind sh -c,
// in a variable or after xargs is still found.

// words splits a command on white space, with quotes grouping and a
// backslash escaping.
func words(s string) []string {
	var out []string
	var b strings.Builder
	in := false
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			q, in = c, true
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
			in = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
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

// splitCommands returns the simple commands of a shell line (split on ;
// && || | & outside quotes).
func splitCommands(line string) []string {
	var out []string
	var q byte
	start := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else if c == '\\' && q == '"' {
				i++
			}
		case c == '"' || c == '\'':
			q = c
		case c == '\\':
			i++
		case c == ';' || c == '&' || c == '|':
			out = append(out, strings.TrimSpace(line[start:min(i, len(line))]))
			if i+1 < len(line) && line[i+1] == c {
				i++
			}
			start = i + 1
		}
	}
	if start <= len(line) {
		out = append(out, strings.TrimSpace(line[start:]))
	}
	return out
}

var (
	installRE = regexp.MustCompile(`\b(?:apt-get|aptitude|apt|apt-fast|nala|install_packages|apk|dnf5?|yum|microdnf|tdnf|zypper)\b`)
	pkgTools  = map[string]bool{"apt-get": true, "aptitude": true, "apt": true, "apt-fast": true, "nala": true, "install_packages": true, "apk": true, "dnf": true, "dnf5": true, "yum": true, "microdnf": true, "tdnf": true, "zypper": true}
	// pkgVerbs install the packages named after them. An upgrade that
	// names a package installs a release of it too.
	pkgVerbs = map[string]bool{"install": true, "add": true, "in": true, "reinstall": true, "satisfy": true,
		"upgrade": true, "update": true, "up": true, "downgrade": true, "dist-upgrade": true, "full-upgrade": true}
	// pkgValueFlags are package-manager options followed by a separate value.
	pkgValueFlags = map[string]bool{"-t": true, "-o": true, "-X": true, "--repository": true, "--virtual": true, "-c": true, "--root": true,
		"-p": true, "--target-release": true, "--option": true, "--repo": true, "--setopt": true, "--enablerepo": true, "--disablerepo": true,
		"--installroot": true, "--releasever": true, "--prefix": true}
	assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	bareVar    = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)
	// redirect is a redirection written onto a word (nginx>/dev/null);
	// apk and zypper write version ranges with > and <, followed by a
	// version, not by a path or a descriptor.
	redirect  = regexp.MustCompile(`(?:>>?|<)[/&].*$|(?:>>?|<)$`)
	shellLead = map[string]bool{"do": true, "then": true, "else": true, "export": true, "declare": true, "local": true, "readonly": true, "while": true, "until": true, "if": true, "!": true}
	varRef    = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

// opaqueArg marks an install argument whose package names the scan
// cannot read: a variable the file does not set, or a command's output.
const opaqueArg = "\x00opaque:"

// leadWords returns the index of a command's own word: after assignments
// and the words that run another command (env, exec, sudo...).
func leadWords(ws []string) int {
	i := 0
	for i < len(ws) && i < 12 {
		w := ws[i]
		switch b := path.Base(w); {
		case b == "chroot" && i+1 < len(ws):
			i++
		case strings.HasPrefix(w, "-"), assignment.MatchString(w), b == "env", b == "exec", b == "sudo", b == "nice", b == "time", b == "nohup", b == "command":
		default:
			return i
		}
		i++
	}
	return i
}

// shellText returns the script of "sh -c TEXT" (also -ec, -lc, su -c,
// eval).
func shellText(ws []string) (string, bool) {
	i := leadWords(ws)
	if i >= len(ws) {
		return "", false
	}
	script := func(text string) (string, bool) { return strings.ReplaceAll(text, "\n", " ; "), true }
	switch path.Base(ws[i]) {
	case "sh", "bash", "ash", "dash", "zsh", "ksh":
		c := false
		for j := i + 1; j < len(ws); j++ {
			w := ws[j]
			switch {
			case w == "-o" || w == "+o" || w == "-O" || w == "+O" || w == "--rcfile" || w == "--init-file":
				j++
			case strings.HasPrefix(w, "--"):
			case strings.HasPrefix(w, "-") || strings.HasPrefix(w, "+"):
				if strings.HasPrefix(w, "-") && strings.Contains(w, "c") {
					c = true
				}
				if strings.HasSuffix(w, "o") {
					j++
				}
			case c:
				return script(w)
			default:
				return "", false
			}
		}
	case "su":
		for j := i + 1; j+1 < len(ws); j++ {
			if ws[j] == "-c" || ws[j] == "--command" {
				return script(ws[j+1])
			}
		}
	case "eval":
		if i+1 < len(ws) {
			return script(strings.Join(ws[i+1:], " "))
		}
	}
	return "", false
}

// install is the package arguments of one install command, with its tool.
type install struct {
	tool string
	args []string
}

// installs returns the install commands of a RUN line: the words after
// "<tool> [flags] install|add", without flags and their values.
func installs(run string, depth int) []install {
	var out []install
	var prev []string
	at := 0
	for _, cmd := range splitCommands(run) {
		piped := false
		if k := strings.Index(run[at:], cmd); k >= 0 && cmd != "" {
			before := strings.TrimRight(run[:at+k], " \t\n")
			piped = strings.HasSuffix(before, "|") && !strings.HasSuffix(before, "||")
			at += k + len(cmd)
		}
		ws := words(cmd)
		last := prev
		prev = ws
		for k, w := range ws {
			if t := strings.TrimLeft(w, "({"); t != "" {
				w = t
			}
			if !strings.Contains(w, "(") {
				if t := strings.TrimRight(w, ")"); t != "" {
					w = t
				}
			}
			ws[k] = w
		}
		for len(ws) > 0 && shellLead[ws[0]] {
			ws = ws[1:]
		}
		if text, ok := shellText(ws); ok && depth < 4 {
			out = append(out, installs(text, depth+1)...)
			continue
		}
		i := 0
		for i < len(ws) && (strings.HasPrefix(ws[i], "-") || !pkgTools[path.Base(ws[i])]) {
			i++
		}
		if i == len(ws) {
			// A tool named by a variable this file does not set ($INSTALL
			// nginx): the words after it are read as packages.
			if k := leadWords(ws); k < len(ws) && bareVar.MatchString(ws[k]) {
				var args []string
				for _, w := range ws[k+1:] {
					if strings.HasPrefix(w, "#") {
						break
					}
					if !strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "$") {
						args = append(args, w)
					}
				}
				if len(args) > 0 {
					out = append(out, install{tool: "?", args: args})
				}
			}
			continue
		}
		var args []string
		for _, w := range ws[:i] {
			if path.Base(w) != "xargs" {
				continue
			}
			lead := leadWords(last)
			if piped && lead < len(last) && (last[lead] == "echo" || last[lead] == "printf") {
				for _, a := range last[lead+1:] {
					if a = redirect.ReplaceAllString(a, ""); a == "" || strings.HasPrefix(a, "-") || strings.Contains(a, "%") || strings.Contains(a, "\\") {
						continue
					}
					if strings.HasPrefix(a, "$") || strings.HasPrefix(a, "`") {
						args = append(args, opaqueArg+a)
					} else {
						args = append(args, a)
					}
				}
			} else {
				args = append(args, opaqueArg+"xargs")
			}
			break
		}
		tool := path.Base(ws[i])
		i++
		isWrapper := tool == "install_packages" // Bitnami's wrapper: the packages follow it
		for i < len(ws) && strings.HasPrefix(ws[i], "-") {
			if pkgValueFlags[ws[i]] {
				i++
			}
			i++
		}
		// dnf module install nginx:1.24, dnf module enable nginx:1.24
		if (tool == "dnf" || tool == "yum" || tool == "microdnf") && i < len(ws) && ws[i] == "module" {
			i++
			for i < len(ws) && strings.HasPrefix(ws[i], "-") {
				i++
			}
			if i < len(ws) && (ws[i] == "install" || ws[i] == "enable" || ws[i] == "switch-to" || ws[i] == "reset") {
				for _, w := range ws[i+1:] {
					if !strings.HasPrefix(w, "-") {
						args = append(args, "@module:"+w)
					}
				}
			}
			if len(args) > 0 {
				out = append(out, install{tool: tool, args: args})
			}
			continue
		}
		if isWrapper {
			i--
		} else if i >= len(ws) || !pkgVerbs[ws[i]] {
			if len(args) > 0 {
				out = append(out, install{tool: tool, args: args})
			}
			continue
		}
		for j := i + 1; j < len(ws); j++ {
			if strings.HasPrefix(ws[j], "#") {
				break
			}
			w := redirect.ReplaceAllString(ws[j], "")
			switch {
			case w == "":
			case strings.HasPrefix(w, "$") || strings.HasPrefix(w, "`"):
				args = append(args, opaqueArg+w)
			case pkgValueFlags[w]:
				j++
			case strings.HasPrefix(w, "-"), strings.Contains(w, "://"), strings.HasPrefix(w, "/"):
			default:
				args = append(args, w)
			}
		}
		if len(args) > 0 {
			out = append(out, install{tool: tool, args: args})
		}
	}
	return out
}

// expandVars puts in the values the Dockerfile's ARG and ENV lines give;
// a variable the file does not set stays as written.
func expandVars(run string, vars map[string]string) string {
	if !strings.Contains(run, "$") {
		return run
	}
	return varRef.ReplaceAllStringFunc(run, func(m string) string {
		g := varRef.FindStringSubmatch(m)
		n := g[1] + g[3]
		if v, ok := vars[n]; ok && v != "" {
			return v
		}
		if g[2] != "" {
			return g[2]
		}
		return m
	})
}

// lineVars returns the variables in force for a RUN line: the stage's,
// changed by what the line itself assigns (NAME=x && ..., export NAME=x).
// One set from a command, another variable or by read has no value here.
func lineVars(run string, vars map[string]string) map[string]string {
	if !strings.Contains(run, "$") {
		return vars
	}
	out := make(map[string]string, len(vars)+2)
	for k, v := range vars {
		out[k] = v
	}
	for _, cmd := range splitCommands(run) {
		ws := words(cmd)
		for len(ws) > 0 && shellLead[strings.TrimLeft(ws[0], "({")] {
			ws = ws[1:]
		}
		if len(ws) == 0 {
			continue
		}
		switch {
		case ws[0] == "for" && len(ws) >= 3 && ws[2] == "in":
			list := strings.Join(ws[3:], " ")
			if strings.ContainsAny(list, "$`*") {
				delete(out, ws[1])
			} else {
				out[ws[1]] = list
			}
		case ws[0] == "read":
			for _, w := range ws[1:] {
				if !strings.HasPrefix(w, "-") {
					delete(out, w)
				}
			}
		case assignment.MatchString(ws[0]):
			all := true
			for _, w := range ws {
				all = all && assignment.MatchString(w)
			}
			if !all {
				k, v, _ := strings.Cut(ws[0], "=")
				if strings.HasPrefix(v, "$(") || strings.HasPrefix(v, "`") {
					delete(out, k)
				}
				continue
			}
			for _, w := range ws {
				k, v, _ := strings.Cut(w, "=")
				if strings.ContainsAny(v, "$`") {
					delete(out, k)
				} else {
					out[k] = v
				}
			}
		}
	}
	return out
}
