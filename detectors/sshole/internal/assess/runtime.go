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
		c := s.Command
		for len(c) > 1 && isWrapper(path.Base(c[0])) {
			c = c[1:]
		}
		if isShell(path.Base(c[0])) {
			for i := 1; i < len(c); i++ {
				if c[i] == "-c" && i+1 < len(c) {
					out = append(out, script{where: "the container command", text: c[i+1]})
					break
				}
				if strings.HasPrefix(c[i], "/") {
					add(c[i])
					break
				}
			}
		} else {
			add(c[0])
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

type script struct{ where, text string }

var absPathRE = regexp.MustCompile(`/[A-Za-z0-9_./-]+`)

func isWrapper(b string) bool {
	switch b {
	case "tini", "dumb-init", "su-exec", "gosu", "env", "exec", "catatonit", "s6-svscan":
		return true
	}
	return false
}

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
	usePAMOnRE = regexp.MustCompile(`(?i)UsePAM\s*[= ]\s*["']?yes`)
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
			if chpasswdRE.MatchString(line) && !strings.Contains(line, "-e") && !strings.Contains(line, "--encrypted") {
				g.passwords, hit = true, true // busybox and shadow chpasswd write sha512 hashes by default
			}
		}
		if hit {
			g.where = append(g.where, sc.where)
		}
	}
	return g
}
