package repo

import (
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// Override is a deployment's replacement for an image's Entrypoint and Cmd:
// Compose entrypoint and command, Kubernetes command and args. A nil field
// keeps the image's own; ClearCmd drops the image's Cmd.
type Override struct {
	Entrypoint, Cmd *[]string
	ClearCmd        bool
}

// Apply returns the command the container runs.
func (o *Override) Apply(entrypoint, cmd []string) []string {
	if o == nil {
		return append(append([]string(nil), entrypoint...), cmd...)
	}
	if o.Entrypoint != nil {
		entrypoint = *o.Entrypoint
		if o.ClearCmd {
			cmd = nil
		}
	}
	if o.Cmd != nil {
		cmd = *o.Cmd
	}
	return append(append([]string(nil), entrypoint...), cmd...)
}

// OverrideFor reads the command a Compose service or Kubernetes container
// sets next to an image reference. nil when it sets none or the file is not
// one of those.
func OverrideFor(root string, r refs.Ref, overlay map[string][]byte) *Override {
	if r.Kind != refs.KindCompose && r.Kind != refs.KindKubernetes {
		return nil
	}
	b, ok := overlay[r.File]
	if !ok {
		var err error
		if b, err = readFile(root, r.File); err != nil {
			return nil
		}
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	for i := 0; i < 1000; i++ {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return nil
		}
		if m := findImageMapping(&doc, r.Line, 0); m != nil {
			return overrideOf(m, r.Kind)
		}
	}
	return nil
}

// findImageMapping finds the mapping whose "image" value sits on line.
func findImageMapping(n *yaml.Node, line, depth int) *yaml.Node {
	if n == nil || depth > 64 {
		return nil
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "image" && n.Content[i+1].Line == line {
				return n
			}
		}
	}
	for _, c := range n.Content {
		if m := findImageMapping(c, line, depth+1); m != nil {
			return m
		}
	}
	return nil
}

func overrideOf(m *yaml.Node, kind refs.Kind) *Override {
	get := func(key string) (*[]string, bool) {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value != key {
				continue
			}
			v := m.Content[i+1]
			var out []string
			switch v.Kind {
			case yaml.SequenceNode:
				for _, c := range v.Content {
					out = append(out, c.Value)
				}
			case yaml.ScalarNode:
				if v.Tag == "!!null" {
					return nil, false
				}
				out = shellWords(v.Value)
			default:
				return nil, false
			}
			return &out, true
		}
		return nil, false
	}
	o := &Override{}
	set := false
	switch kind {
	case refs.KindCompose:
		if e, ok := get("entrypoint"); ok {
			o.Entrypoint, o.ClearCmd, set = e, true, true
		}
		if c, ok := get("command"); ok {
			o.Cmd, set = c, true
		}
	case refs.KindKubernetes:
		if e, ok := get("command"); ok {
			o.Entrypoint, o.ClearCmd, set = e, true, true
		}
		if a, ok := get("args"); ok {
			o.Cmd, set = a, true
		}
	}
	if !set {
		return nil
	}
	return o
}

// shellWords splits a command string the way Compose does (shell quoting).
func shellWords(s string) []string {
	var out []string
	for _, c := range splitShell(s) {
		for _, w := range c.words {
			out = append(out, w.val)
		}
	}
	return out
}
