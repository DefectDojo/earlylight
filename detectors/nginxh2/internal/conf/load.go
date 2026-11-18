package conf

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Source serves the files a configuration may read.
type Source interface {
	// Read returns a file's content; ok is false when the file was not
	// read (missing, unreadable, not kept). why says which, for the
	// report.
	Read(p string) (data []byte, ok bool, why string)
	// Glob returns the files matching pattern, sorted, and whether that
	// list is complete: false when files the pattern can match were not
	// read, so the list may miss some.
	Glob(pattern string) (matches []string, complete bool)
}

// Limits on what one configuration can make the loader read.
const (
	MaxFiles = 4096
	MaxBytes = 16 << 20
	// MaxTotalTokens bounds what every file of one configuration, each
	// time it is included, makes the loader parse: one file included many
	// times is parsed each time.
	MaxTotalTokens = 2 << 20
	maxNest        = 32
)

// Config is a loaded configuration.
type Config struct {
	Main  string      `json:"main"`
	Root  []Directive `json:"-"`
	Files []string    `json:"files"`
	// Unread lists what could not be read or settled: each one makes a
	// "not exposed" answer unknown.
	Unread []string `json:"unread,omitempty"`
}

type loader struct {
	src    Source
	prefix string // the configuration prefix: the main file's directory
	cfg    *Config
	bytes  int
	tokens int // left of MaxTotalTokens
	stack  []string
}

// Load reads the main file and every file it includes, at any level, the
// way nginx does: a relative include is taken from the main file's
// directory; a pattern with *, ? or [ is a glob; a file included from
// itself, directly or not, is a loop nginx cannot load. extra are
// directives given on the command line (-g), added to the main context.
func Load(src Source, main string, extra []Directive) *Config {
	l := &loader{src: src, prefix: path.Dir(main), cfg: &Config{Main: main}, tokens: MaxTotalTokens}
	root, ok := l.file(main, 0)
	if !ok {
		return l.cfg
	}
	// -g directives are in the main context, and their includes are
	// followed like any other.
	l.cfg.Root = append(root, l.expand(extra, 0)...)
	return l.cfg
}

func (l *loader) unread(format string, a ...any) {
	if len(l.cfg.Unread) < 64 {
		l.cfg.Unread = append(l.cfg.Unread, fmt.Sprintf(format, a...))
	}
}

func (l *loader) file(p string, nest int) ([]Directive, bool) {
	for _, s := range l.stack {
		if s == p {
			l.unread("%s includes itself (through %s): nginx cannot load this configuration", p, strings.Join(l.stack, " -> "))
			return nil, false
		}
	}
	if nest > maxNest {
		l.unread("includes nested more than %d deep at %s", maxNest, p)
		return nil, false
	}
	if len(l.cfg.Files) >= MaxFiles {
		l.unread("more than %d configuration files; %s and later ones not read", MaxFiles, p)
		return nil, false
	}
	data, ok, why := l.src.Read(p)
	if !ok {
		l.unread("%s not read: %s", p, why)
		return nil, false
	}
	l.bytes += len(data)
	if l.bytes > MaxBytes {
		l.unread("more than %d bytes of configuration; %s not read", MaxBytes, p)
		return nil, false
	}
	l.cfg.Files = append(l.cfg.Files, p)
	ds, err := parse(p, string(data), &l.tokens)
	if err != nil {
		l.unread("%s could not be parsed: %v", p, err)
		return nil, false
	}
	l.stack = append(l.stack, p)
	defer func() { l.stack = l.stack[:len(l.stack)-1] }()
	return l.expand(ds, nest), true
}

// expand replaces include directives, at every level, with what they
// include.
func (l *loader) expand(ds []Directive, nest int) []Directive {
	out := make([]Directive, 0, len(ds))
	for _, d := range ds {
		if d.Name == "include" && !d.HasBlock {
			out = append(out, l.include(d, nest)...)
			continue
		}
		if d.HasBlock {
			d.Block = l.expand(d.Block, nest)
		}
		out = append(out, d)
	}
	return out
}

func (l *loader) include(d Directive, nest int) []Directive {
	where := fmt.Sprintf("%s:%d", d.File, d.Line)
	if len(d.Args) != 1 {
		l.unread("include at %s has %d arguments", where, len(d.Args))
		return nil
	}
	p := d.Args[0]
	if strings.Contains(p, "$") {
		l.unread("include at %s names a variable (%s), which nginx does not expand", where, p)
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		p = path.Join(l.prefix, p)
	}
	p = path.Clean(p)
	if !strings.ContainsAny(p, "*?[") {
		ds, _ := l.file(p, nest+1)
		return ds
	}
	matches, complete := l.src.Glob(p)
	if !complete {
		l.unread("include %s at %s: the files it matches were not all read", p, where)
	}
	sort.Strings(matches)
	var out []Directive
	for _, m := range matches {
		ds, _ := l.file(m, nest+1)
		out = append(out, ds...)
	}
	return out
}
