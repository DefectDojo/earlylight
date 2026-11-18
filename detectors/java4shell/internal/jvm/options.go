package jvm

import (
	"fmt"
	"strconv"
	"strings"
)

// Options is what JVM options say about the vulnerable decoder: the last
// value given to -XX:±UseBASE64Intrinsics and -XX:UseAVX. HotSpot applies
// options in order, so the last one wins.
type Options struct {
	Base64 *bool // nil: not set
	UseAVX *int
	// Where names the setting that decided each value ("JAVA_TOOL_OPTIONS").
	Base64From, AVXFrom string
}

// maxOptionText bounds an option string: environment values and option
// files are short.
const maxOptionText = 256 << 10

// Apply reads one option string from source (an environment variable, a
// file) on top of what is already set.
func (o *Options) Apply(text, source string) {
	if len(text) > maxOptionText {
		text = text[:maxOptionText]
	}
	for _, w := range Words(text) {
		o.ApplyWord(w, source)
	}
}

// ApplyWord reads one option.
func (o *Options) ApplyWord(w, source string) {
	switch {
	case w == "-XX:-UseBASE64Intrinsics":
		f := false
		o.Base64, o.Base64From = &f, source
	case w == "-XX:+UseBASE64Intrinsics":
		t := true
		o.Base64, o.Base64From = &t, source
	case strings.HasPrefix(w, "-XX:UseBASE64Intrinsics="):
		switch strings.TrimPrefix(w, "-XX:UseBASE64Intrinsics=") {
		case "false":
			f := false
			o.Base64, o.Base64From = &f, source
		case "true":
			t := true
			o.Base64, o.Base64From = &t, source
		}
	case strings.HasPrefix(w, "-XX:UseAVX="):
		if n, err := strconv.Atoi(strings.TrimPrefix(w, "-XX:UseAVX=")); err == nil && n >= 0 && n < 100 {
			o.UseAVX, o.AVXFrom = &n, source
		}
	}
}

// Mitigates reports whether the options keep HotSpot from generating the
// vulnerable decoder, and how.
func (o Options) Mitigates() (bool, string) {
	if o.Base64 != nil && !*o.Base64 {
		return true, fmt.Sprintf("-XX:-UseBASE64Intrinsics (from %s) turns the Base64 intrinsics off", o.Base64From)
	}
	if o.UseAVX != nil && *o.UseAVX <= 2 {
		return true, fmt.Sprintf("-XX:UseAVX=%d (from %s) turns AVX-512 off, so the AVX-512 VBMI decoder is not generated", *o.UseAVX, o.AVXFrom)
	}
	return false, ""
}

// Set reports whether either option was given at all.
func (o Options) Set() bool { return o.Base64 != nil || o.UseAVX != nil }

// Words splits an option string the way a shell or the JVM's option
// variables do: on white space, with single and double quotes grouping.
func Words(s string) []string {
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

// EnvVars are the variables the JVM itself reads, in the order HotSpot
// applies them: JAVA_TOOL_OPTIONS first, then JDK_JAVA_OPTIONS (the java
// launcher, Java 9 and later, puts it before the command line), then the
// command line, then _JAVA_OPTIONS, which overrides everything.
var EnvVars = []string{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}

// ScriptVars are variables only launch scripts read (catalina.sh,
// Atlassian's setenv.sh, many start scripts).
var ScriptVars = []string{"JAVA_OPTS", "CATALINA_OPTS", "JVM_SUPPORT_RECOMMENDED_ARGS", "JVM_OPTS", "ES_JAVA_OPTS", "SOLR_OPTS", "KAFKA_OPTS", "KAFKA_HEAP_OPTS"}

// FromEnv computes the options a JVM started in env with command line cmd
// gets. feature is the Java release (JDK_JAVA_OPTIONS needs 9 or later);
// scriptVars lists the script variables the launch passes on.
func FromEnv(env map[string]string, cmd []string, feature int, scriptVars map[string]bool) Options {
	var o Options
	if v, ok := env["JAVA_TOOL_OPTIONS"]; ok {
		o.Apply(v, "JAVA_TOOL_OPTIONS")
	}
	if v, ok := env["JDK_JAVA_OPTIONS"]; ok && feature >= 9 {
		o.Apply(v, "JDK_JAVA_OPTIONS")
	}
	for _, name := range ScriptVars {
		if v, ok := env[name]; ok && scriptVars[name] {
			o.Apply(v, name)
		}
	}
	for _, w := range cmd {
		o.ApplyWord(w, "the command line")
	}
	if v, ok := env["_JAVA_OPTIONS"]; ok {
		o.Apply(v, "_JAVA_OPTIONS")
	}
	return o
}

// EnvMap turns "KEY=value" entries into a map, the last one winning.
func EnvMap(env []string) map[string]string {
	m := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}

// valueOptions are java launcher options followed by a separate value.
var valueOptions = map[string]bool{"-cp": true, "-classpath": true, "--class-path": true, "-p": true, "--module-path": true,
	"--upgrade-module-path": true, "--add-modules": true, "--enable-native-access": true, "--limit-modules": true,
	"--add-reads": true, "--add-exports": true, "--add-opens": true, "--patch-module": true, "--source": true}

// JavaOptions returns the JVM options a container command gives the java
// launcher: the words after a java executable up to the main class or
// -jar. A "sh -c" script is split into words first. ok is false when the
// command does not start java directly.
func JavaOptions(cmd []string) ([]string, bool) {
	if len(cmd) > 1024 {
		cmd = cmd[:1024]
	}
	words := cmd
	for i := 0; i+2 < len(cmd); i++ {
		if b := baseName(cmd[i]); (b == "sh" || b == "bash" || b == "ash" || b == "dash") && cmd[i+1] == "-c" {
			words = Words(cmd[i+2])
			break
		}
	}
	for i, w := range words {
		if baseName(w) != "java" {
			continue
		}
		var out []string
		for j := i + 1; j < len(words); j++ {
			x := words[j]
			if x == "-jar" || x == "-m" || x == "--module" || !strings.HasPrefix(x, "-") {
				break
			}
			if valueOptions[x] {
				j++
				continue
			}
			out = append(out, x)
		}
		return out, true
	}
	return nil, false
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(p), ".exe")
}

// CommandWords returns every word of a container command, with the words
// of a "sh -c" script split out.
func CommandWords(cmd []string) []string {
	if len(cmd) > 1024 {
		cmd = cmd[:1024]
	}
	var out []string
	for i, w := range cmd {
		if i > 0 && cmd[i-1] == "-c" && i >= 2 {
			if b := baseName(cmd[i-2]); b == "sh" || b == "bash" || b == "ash" || b == "dash" {
				out = append(out, Words(w)...)
				continue
			}
		}
		out = append(out, w)
	}
	return out
}

// Undoes reports what in a command or option text can turn the decoder
// back on, wherever the java it starts is: -XX:+UseBASE64Intrinsics,
// -XX:UseAVX=3 or higher, or a java @argfile this scan cannot read.
func Undoes(words []string) (base64, avx, argfile bool) {
	java := false
	for _, w := range words {
		switch {
		case baseName(w) == "java":
			java = true
		case w == "-XX:+UseBASE64Intrinsics" || w == "-XX:UseBASE64Intrinsics=true":
			base64 = true
		case strings.HasPrefix(w, "-XX:UseAVX="):
			if n, err := strconv.Atoi(strings.TrimPrefix(w, "-XX:UseAVX=")); err != nil || n >= 3 {
				avx = true
			}
		case java && strings.HasPrefix(w, "@") && len(w) > 1:
			argfile = true
		}
	}
	return
}
