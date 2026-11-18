package assess

import (
	"fmt"
	"path"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/conf"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
)

// The configuration nginx loads depends on how it is started. Exposure can
// read as "not exposed" only when the command that starts nginx was read
// and nothing it runs first can change the configuration; otherwise the
// configuration read may not be the one that runs, and unsure says why.

// nginxNames are the words that start an nginx build.
var nginxNames = map[string]bool{"nginx": true, "nginx-debug": true, "openresty": true, "angie": true, "tengine": true}

// launchers start the next word as the command without touching the
// configuration.
var launchers = map[string]bool{"tini": true, "tini-static": true, "dumb-init": true, "exec": true, "env": true, "--": true}

// configFor returns the configuration file a binary loads, the -g
// directives, where the path came from, and why the answer is unsure ("" when
// the start command was read in full).
func configFor(b *ngx.Binary, in Input) (string, []conf.Directive, string, string) {
	main, how := b.ConfPath, "the binary's default"
	prefix := b.Prefix
	var extra []conf.Directive
	cmd, from := in.Command, in.CommandFrom
	none := ""
	if in.CommandFor != nil {
		cmd, from, none = in.CommandFor(b.Path)
	}
	args, unsure := startArgs(cmd, in.Launcher)
	if len(cmd) == 0 && none != "" {
		unsure = none
	}
	if from == "" {
		from = "the start command"
	}
	o, err := nginxOptions(args)
	if err != "" && unsure == "" {
		unsure = err
	}
	if o.conf != "" {
		main, how = o.conf, from+"'s -c"
	}
	if o.prefix != "" {
		prefix = o.prefix
		if o.conf == "" && !strings.HasPrefix(b.ConfRaw, "/") {
			// -p moves a relative compiled-in configuration path.
			main, how = b.ConfRaw, "the binary's default under "+from+"'s -p"
			if main == "" {
				main = "conf/nginx.conf"
			}
		}
	}
	for _, g := range o.global {
		ds, err := conf.Parse("-g", g)
		if err != nil {
			if unsure == "" {
				unsure = from + "'s -g directives could not be read"
			}
			continue
		}
		extra = append(extra, ds...)
	}
	if main == "" {
		main = "/usr/local/nginx/conf/nginx.conf"
		how = "nginx's default"
	}
	if !strings.HasPrefix(main, "/") {
		if prefix == "" {
			prefix = "/usr/local/nginx/"
		}
		main = path.Join(prefix, main)
	}
	return path.Clean("/" + main), extra, how, unsure
}

// startArgs returns nginx's arguments in a start command and why the
// configuration read may not be what runs.
func startArgs(cmd []string, launcher func(string) (bool, string)) ([]string, string) {
	if len(cmd) == 0 {
		return nil, "no command that starts nginx was read (an image without one, or a host whose service unit was not found)"
	}
	for i := 0; i < len(cmd); i++ {
		w := cmd[i]
		b := path.Base(w)
		switch {
		case nginxNames[b] && noServe(cmd[i+1:]):
			return nil, "the command runs nginx only to test or show it, so what serves is started elsewhere"
		case nginxNames[b]:
			return varArgs(cmd[i+1:])
		case launchers[b] || strings.HasPrefix(w, "-") && i > 0 && launchers[path.Base(cmd[i-1])] || strings.Contains(w, "=") && i > 0 && path.Base(cmd[i-1]) == "env":
		case b == "sh" || b == "bash" || b == "ash" || b == "dash":
			for j := i + 1; j < len(cmd); j++ {
				if strings.HasPrefix(cmd[j], "-") && strings.Contains(cmd[j], "c") && j+1 < len(cmd) {
					return shellStart(cmd[j+1])
				}
			}
			return nil, "the container starts a shell script, which can change the configuration"
		default:
			if launcher != nil {
				ok, why := launcher(w)
				if ok {
					continue
				}
				return nil, why
			}
			return nil, fmt.Sprintf("nginx is started through %s, which can change the configuration or the options it is given", w)
		}
	}
	return nil, "the start command does not run nginx"
}

func varArgs(args []string) ([]string, string) {
	for _, a := range args {
		if strings.ContainsAny(a, "$`") {
			return args, "nginx is started with arguments that use variables"
		}
	}
	return args, ""
}

// shellStart reads a "sh -c" text. It must run nginx and nothing else
// that could change the configuration first: any other command (sed,
// envsubst, a script) makes the answer unsure.
func shellStart(text string) ([]string, string) {
	cmds, ok := shellCommands(text)
	if !ok {
		return nil, "nginx is started from a shell command that could not be read word by word"
	}
	for _, ws := range cmds {
		for len(ws) > 0 && (ws[0] == "exec" || strings.Contains(ws[0], "=") && !strings.HasPrefix(ws[0], "-")) {
			ws = ws[1:]
		}
		switch {
		case len(ws) == 0, ws[0] == "set":
		case nginxNames[path.Base(ws[0])] && noServe(ws[1:]):
			// nginx -t, -T, -v, -V, -s or -h: tests, shows or signals,
			// and does not serve; the start comes later.
		case nginxNames[path.Base(ws[0])]:
			return varArgs(ws[1:])
		default:
			return nil, fmt.Sprintf("the shell command runs %s before nginx, which can change the configuration", ws[0])
		}
	}
	return nil, "the shell command does not run nginx"
}

// shellCommands splits a shell text into simple commands of words: quotes
// group, a backslash escapes the next character and joins a line it ends,
// and ; & | and newlines separate commands. A substitution or redirection
// makes it unreadable here.
func shellCommands(text string) ([][]string, bool) {
	var cmds [][]string
	var cur []string
	var w strings.Builder
	in, q := false, byte(0)
	flush := func() {
		if in {
			cur = append(cur, w.String())
			w.Reset()
			in = false
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case q == '\'':
			if c == q {
				q = 0
			} else {
				w.WriteByte(c)
			}
		case q == '"':
			switch {
			case c == q:
				q = 0
			case c == '\\' && i+1 < len(text):
				i++
				if text[i] != '\n' {
					w.WriteByte(text[i])
				}
			case c == '`' || c == '$' && i+1 < len(text) && text[i+1] == '(':
				return nil, false
			default:
				w.WriteByte(c)
			}
		case c == '\\' && i+1 < len(text):
			i++
			if text[i] != '\n' {
				w.WriteByte(text[i])
				in = true
			}
		case c == '"' || c == '\'':
			q, in = c, true
		case c == ' ' || c == '\t':
			flush()
		case c == ';' || c == '&' || c == '|' || c == '\n':
			flush()
			cmds = append(cmds, cur)
			cur = nil
		case c == '`' || c == '<' || c == '>' || c == '(' || c == ')' || c == '$' && i+1 < len(text) && text[i+1] == '(':
			return nil, false
		default:
			w.WriteByte(c)
			in = true
		}
	}
	if q != 0 {
		return nil, false
	}
	flush()
	return append(cmds, cur), true
}

// noServe reports nginx arguments with an option that makes nginx test,
// show its version or configuration, send a signal or print help, and
// exit without serving.
func noServe(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 't', 'T', 'v', 'V', 's', 'h', '?':
				return true
			case 'p', 'c', 'e', 'g':
				if j == len(a)-1 {
					i++
				}
				j = len(a)
			}
		}
	}
	return false
}

type options struct {
	conf, prefix string
	global       []string
}

// nginxOptions reads nginx's command line as ngx_get_options does: each
// argument is a "-" and letters; ? h v V t T q take nothing, p c e g s
// take the rest of the argument or the next one ("-qc file").
func nginxOptions(args []string) (options, string) {
	var o options
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			return o, fmt.Sprintf("nginx is given %q, which it does not take as an option", a)
		}
	opts:
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case '?', 'h', 'v', 'V', 't', 'T', 'q':
			case 'p', 'c', 'e', 'g', 's':
				v := a[j+1:]
				if v == "" {
					if i+1 >= len(args) {
						return o, fmt.Sprintf("nginx's option -%c has no value", a[j])
					}
					i++
					v = args[i]
				}
				switch a[j] {
				case 'p':
					o.prefix = v
				case 'c':
					o.conf = v
				case 'g':
					o.global = append(o.global, v)
				}
				break opts
			default:
				return o, fmt.Sprintf("nginx is given the option -%c, which this scan does not know", a[j])
			}
		}
	}
	return o, ""
}
