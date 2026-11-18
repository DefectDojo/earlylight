package assess

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// Startup is what a container does when it starts: the command its image
// runs and the startup scripts in it.
type Startup struct {
	// Command is the image's Entrypoint followed by its Cmd.
	Command []string
	// Scripts are the image's shell scripts ("#!" files), by path.
	Scripts map[string][]byte
	// Unread are scripts that were not read (over a size limit, or
	// unreadable): one that runs at start can start sshd with any
	// settings. UnreadDirs could not be listed; UnreadAll stands for more
	// unread files than were recorded.
	Unread     map[string]bool
	UnreadDirs []string
	UnreadAll  bool
}

// inUnreadDir is the directory that was not listed that holds p, or "".
func (s Startup) inUnreadDir(p string) string {
	for _, d := range s.UnreadDirs {
		if p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
			return d
		}
	}
	return ""
}

// unreadStart lists the scripts that run at start and were not read: the
// command's own script, one a start script names, and those in the init
// directories.
func (s Startup) unreadStart(resolve func(string) (string, bool), scripts []script) []string {
	if s.UnreadAll {
		return []string{"more files than the scan records"}
	}
	if len(s.Unread) == 0 && len(s.UnreadDirs) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		r := p
		if resolve != nil {
			if rp, ok := resolve(p); ok {
				r = rp
			}
		}
		if !strings.HasPrefix(r, "/") {
			for _, d := range pathDirs {
				if s.Unread[d+r] {
					r = d + r
					break
				}
			}
		}
		if !strings.HasPrefix(r, "/") {
			for _, d := range pathDirs {
				if s.inUnreadDir(d+r) != "" {
					r = d + r
					break
				}
			}
		}
		if d := s.inUnreadDir(r); d != "" {
			r = d // a script in a directory that was not listed
		}
		if (s.Unread[r] || s.inUnreadDir(r) != "") && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, w := range s.Command {
		add(w)
	}
	for _, sc := range scripts {
		for _, m := range absPathRE.FindAllString(sc.text, -1) {
			add(m)
		}
	}
	for p := range s.Unread {
		for _, d := range initDirs {
			if strings.HasPrefix(p, d) {
				add(p)
			}
		}
	}
	for _, u := range s.UnreadDirs {
		for _, d := range initDirs {
			// An init directory that was not listed, or one inside it.
			if strings.HasPrefix(d, strings.TrimSuffix(u, "/")+"/") || strings.HasPrefix(u+"/", d) {
				add(u)
			}
		}
	}
	sort.Strings(out)
	return out
}

// initDirs hold scripts an init system runs at start whatever the command
// (s6-overlay, linuxserver's cont-init, baseimage-docker, entrypoint.d).
var initDirs = []string{"/etc/cont-init.d/", "/etc/s6-overlay/", "/custom-cont-init.d/", "/docker-entrypoint.d/",
	"/etc/services.d/", "/etc/my_init.d/", "/etc/runit/", "/entrypoint.d/", "/docker-entrypoint-init.d/", "/etc/entrypoint.d/", "/etc/s6/"}

// pathDirs is where a command named without a path is looked up.
var pathDirs = []string{"/usr/local/sbin/", "/usr/local/bin/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"}

// startScripts returns the scripts that run at start, in a stable order:
// the command's own script (or its sh -c text), one level of scripts it
// names, and the init directories.
func (s Startup) startScripts(resolve func(string) (string, bool)) []script {
	var out []script
	seen := map[string]bool{}
	add := func(p string) {
		if seen[p] {
			return
		}
		r := p
		if resolve != nil {
			if rp, ok := resolve(p); ok {
				r = rp
			}
		}
		if !strings.HasPrefix(r, "/") {
			for _, d := range pathDirs {
				if _, ok := s.Scripts[d+r]; ok {
					r = d + r
					break
				}
			}
		}
		if b, ok := s.Scripts[r]; ok {
			seen[p], seen[r] = true, true
			out = append(out, script{where: p, text: string(b)})
		}
	}
	if len(s.Command) > 0 {
		// Every word of the command that names a script: wrappers take
		// arguments of their own ("tini --", "gosu USER", "su-exec USER"),
		// so the script is not always the first word after them.
		// The first is the program the command runs; a later one is an
		// argument to it, which may or may not run (arg).
		c := s.Command
		program := false
		for i, w := range c {
			n := len(out)
			if isShell(path.Base(w)) {
				for j := i + 1; j < len(c); j++ {
					if c[j] == "-c" && j+1 < len(c) {
						out = append(out, script{where: "the container command", text: c[j+1]})
						break
					}
				}
			}
			add(w)
			for k := n; k < len(out); k++ {
				out[k].arg = program
				program = true
			}
		}
		// One level of scripts the command's scripts name.
		for _, sc := range append([]script(nil), out...) {
			for _, m := range absPathRE.FindAllString(sc.text, -1) {
				add(m)
			}
		}
	}
	var dirs []string
	for p := range s.Scripts {
		for _, d := range initDirs {
			if strings.HasPrefix(p, d) {
				dirs = append(dirs, p)
			}
		}
	}
	sort.Strings(dirs)
	for _, p := range dirs {
		add(p)
	}
	return out
}

type script struct {
	where, text string
	// arg is set for a script the command names after its program: an
	// argument, which may not run.
	arg bool
}

var absPathRE = regexp.MustCompile(`/[A-Za-z0-9_./-]+`)

func isShell(b string) bool {
	switch b {
	case "sh", "bash", "ash", "dash", "busybox":
		return true
	}
	return false
}

// invocation is an sshd command line: the binary, -f and -o.
type invocation struct {
	binary string
	config string
	opts   []Directive
	where  string
	// arg: found in a script the command passes as an argument, which may
	// not run.
	arg bool
}

// invocations finds sshd command lines in the container command and the
// startup scripts.
func invocations(s Startup, scripts []script) []invocation {
	var out []invocation
	if inv, ok := parseSSHD(s.Command, "the container command"); ok {
		out = append(out, inv)
	}
	for _, sc := range scripts {
		for _, line := range strings.Split(sc.text, "\n") {
			for _, part := range splitCommands(line) {
				if inv, ok := parseSSHD(fieldsQuoted(part), sc.where); ok {
					inv.arg = sc.arg
					out = append(out, inv)
				}
			}
		}
	}
	return out
}

func splitCommands(line string) []string {
	if i := strings.Index(line, "#"); i == 0 || i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
		line = line[:i]
	}
	return regexp.MustCompile(`&&|\|\||;|\|`).Split(line, -1)
}

// fieldsQuoted splits on spaces, keeping quoted words whole and unquoted.
func fieldsQuoted(s string) []string {
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

// sshd options that take a value, besides -f and -o.
var sshdValueFlags = "CEbcghkpu" // sshd.c getopt "C:E:b:c:f:g:h:k:o:p:u:..."

func parseSSHD(argv []string, where string) (invocation, bool) {
	// A line that only prints, tests or looks for sshd does not run it.
	if len(argv) > 0 {
		switch path.Base(argv[0]) {
		case "echo", "printf", "test", "[", "[[", "grep", "pgrep", "pkill", "kill", "which", "command", "type", "ls", "cat", "if", "case":
			return invocation{}, false
		}
	}
	i := 0
	for i < len(argv) {
		b := path.Base(argv[i])
		if b == "sshd" || strings.HasPrefix(b, "sshd.") {
			break
		}
		i++
	}
	if i >= len(argv) {
		return invocation{}, false
	}
	for _, a := range argv[i+1:] {
		if a == "-t" || a == "-T" || a == "-G" {
			return invocation{}, false // a config test, not the server
		}
	}
	inv := invocation{binary: argv[i], where: where}
	for j := i + 1; j < len(argv); j++ {
		a := argv[j]
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		flag := a[1]
		val := a[2:]
		if val == "" && (flag == 'f' || flag == 'o' || strings.IndexByte(sshdValueFlags, flag) >= 0) && j+1 < len(argv) {
			j++
			val = argv[j]
		}
		switch flag {
		case 'f':
			inv.config = val
		case 'o':
			if args := splitArgs(val); len(args) >= 2 {
				inv.opts = append(inv.opts, Directive{Key: strings.ToLower(args[0]), Args: args[1:], File: where})
			}
		}
	}
	return inv, true
}

// Startup signals: what the startup scripts do to sshd's settings and the
// accounts before sshd runs.
var (
	pwOnRE     = regexp.MustCompile(`(?i)PasswordAuthentication\s*[= ]\s*["']?yes`)
	usePAMOnRE = regexp.MustCompile(`(?im)^[^#\n]*UsePAM\s*[= ]\s*["']?yes`)
	starSetRE  = []*regexp.Regexp{
		regexp.MustCompile(`(?:usermod|useradd)\b[^\n]*(?:-p|--password)[ =]\s*(?:'\*'|"\*"|\\\*|\*)(?:\s|$)`),
		regexp.MustCompile(`[A-Za-z0-9_$.{}-]+:\*['"]?\s*\|\s*chpasswd\s+(?:-e|--encrypted)`),
		regexp.MustCompile(`sed\b[^\n]*:\\?\*[:/][^\n]*/etc/shadow`),
		regexp.MustCompile(`[A-Za-z0-9_$.{}-]+:\*:[^\n]*>>?\s*/etc/shadow`),
	}
	chpasswdRE = regexp.MustCompile(`\bchpasswd\b`)
)

type signals struct {
	passwordOn, starSet, passwords, usePAMOn bool
	where                                    []string
}

func (g signals) describe() string {
	var d []string
	if g.passwordOn {
		d = append(d, "turns PasswordAuthentication on")
	}
	if g.starSet {
		d = append(d, "sets a password field to \"*\"")
	}
	if g.passwords {
		d = append(d, "sets passwords with chpasswd")
	}
	if g.usePAMOn {
		d = append(d, "turns UsePAM on")
	}
	return strings.Join(d, ", ")
}

func (g signals) any() bool { return g.passwordOn || g.starSet || g.passwords || g.usePAMOn }

func startupSignals(scripts []script) signals {
	var g signals
	for _, sc := range scripts {
		hit := false
		if pwOnRE.MatchString(sc.text) {
			g.passwordOn, hit = true, true
		}
		if usePAMOnRE.MatchString(sc.text) {
			g.usePAMOn, hit = true, true
		}
		for _, re := range starSetRE {
			if re.MatchString(sc.text) {
				g.starSet, hit = true, true
			}
		}
		for _, line := range strings.Split(sc.text, "\n") {
			if !chpasswdRE.MatchString(line) {
				continue
			}
			for _, part := range splitCommands(line) {
				words := fieldsQuoted(part)
				for i, w := range words {
					if path.Base(w) != "chpasswd" {
						continue
					}
					encrypted := false
					for _, a := range words[i+1:] {
						if a == "-e" || a == "--encrypted" || strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "e") {
							encrypted = true
						}
					}
					if !encrypted {
						g.passwords, hit = true, true // busybox and shadow chpasswd write sha512 hashes by default
					}
				}
			}
		}
		if hit {
			g.where = append(g.where, sc.where)
		}
	}
	return g
}
