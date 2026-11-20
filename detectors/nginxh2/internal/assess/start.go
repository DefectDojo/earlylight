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
	args, word, unsure := startArgs(cmd, in.Launcher)
	if len(cmd) == 0 && none != "" {
		unsure = none
	}
	if unsure == "" && word != "" {
		// The word must start the very binary judged.
		switch {
		case in.Starts == nil:
			unsure = "which binary " + word + " starts was not checked"
		default:
			if ok, why := in.Starts(word, b.Path); !ok {
				unsure = why
			}
		}
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

// startArgs returns nginx's arguments in a start command, the word that
// starts nginx, and why the configuration read may not be what runs. Only
// two starts are read: the nginx binary itself, and the official image's
// entrypoint (trusted by its content) given nginx or nginx-debug as its
// first argument. Anything else that runs first (tini, env, a shell, a
// wrapper) is trusted by nothing the scan can check, so it is unsure.
func startArgs(cmd []string, launcher func(string) (bool, string)) ([]string, string, string) {
	if len(cmd) == 0 {
		return nil, "", "no command that starts nginx was read (an image without one, or a host whose service unit was not found)"
	}
	i := 0
	if !nginxNames[path.Base(cmd[0])] {
		ok, why := false, ""
		if launcher != nil {
			ok, why = launcher(cmd[0])
		}
		if !ok {
			if why == "" {
				why = fmt.Sprintf("nginx is started through %s, which can change the configuration or the options it is given", cmd[0])
			}
			return nil, "", why
		}
		i = 1
		if i >= len(cmd) || cmd[i] != "nginx" && cmd[i] != "nginx-debug" {
			return nil, "", "the entrypoint is not given nginx as its first argument, so what it runs is not read"
		}
	}
	w := cmd[i]
	if !nginxNames[path.Base(w)] {
		return nil, "", fmt.Sprintf("nginx is started through %s, which can change the configuration or the options it is given", w)
	}
	if noServe(cmd[i+1:]) {
		return nil, "", "the command runs nginx only to test or show it, so what serves is started elsewhere"
	}
	args, unsure := varArgs(cmd[i+1:])
	return args, w, unsure
}

// OfficialEntrypointRuns reports a command whose first word is the
// official entrypoint given nginx or nginx-debug: only then does it run
// /docker-entrypoint.d and write the templates.
func OfficialEntrypointRuns(cmd []string, launcher func(string) (bool, string)) bool {
	if len(cmd) < 2 || launcher == nil || cmd[1] != "nginx" && cmd[1] != "nginx-debug" {
		return false
	}
	ok, _ := launcher(cmd[0])
	return ok
}

func varArgs(args []string) ([]string, string) {
	for _, a := range args {
		if strings.ContainsAny(a, "$`") {
			return args, "nginx is started with arguments that use variables"
		}
	}
	return args, ""
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
