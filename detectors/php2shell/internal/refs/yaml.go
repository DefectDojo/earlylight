package refs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/go-containerregistry/pkg/name"
	"gopkg.in/yaml.v3"
)

// YAML documents are decoded into yaml.Node trees, which yaml.v3 builds
// without expanding aliases (the alias bomb limit only applies to decoding
// into Go values). The walkers here follow aliases and merge keys themselves,
// visiting each node at most once and within a fixed work budget per file, so
// hostile input cannot make them run long.

const yamlWorkBudget = 1 << 20

var errBudget = errors.New("too many YAML nodes or alias expansions")

type yamlCtx struct {
	s        *scanner
	file     string
	kind     Kind
	lines    []string
	budget   int
	reported map[*yaml.Node]bool
	visited  map[*yaml.Node]bool
	env      *dotEnv // compose only
}

func (y *yamlCtx) spend() bool {
	y.budget--
	return y.budget >= 0
}

func decodeYAML(b []byte) (docs []*yaml.Node, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("YAML parser failed: %v", r)
		}
	}()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				return docs, nil
			}
			return docs, err
		}
		docs = append(docs, &doc)
	}
}

func deref(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode; i++ {
		if i > 64 {
			return nil
		}
		n = n.Alias
	}
	if n != nil && n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return deref(n.Content[0])
	}
	return n
}

type kv struct {
	key string
	k   *yaml.Node
	v   *yaml.Node
}

// pairs returns a mapping's key/value pairs with merge keys (<<) applied:
// keys written in the mapping win over merged ones, earlier merges over later.
func (y *yamlCtx) pairs(m *yaml.Node) []kv {
	return y.pairsDepth(m, 0)
}

func (y *yamlCtx) pairsDepth(m *yaml.Node, depth int) []kv {
	m = deref(m)
	if m == nil || m.Kind != yaml.MappingNode || depth > 16 {
		return nil
	}
	var own, merged []kv
	for i := 0; i+1 < len(m.Content); i += 2 {
		if !y.spend() {
			return nil
		}
		k := deref(m.Content[i])
		v := m.Content[i+1]
		if k == nil || k.Kind != yaml.ScalarNode {
			continue
		}
		if k.Value == "<<" && k.ShortTag() == "!!merge" {
			src := deref(v)
			if src == nil {
				continue
			}
			var srcs []*yaml.Node
			if src.Kind == yaml.SequenceNode {
				srcs = src.Content
			} else {
				srcs = []*yaml.Node{src}
			}
			for _, sm := range srcs {
				merged = append(merged, y.pairsDepth(sm, depth+1)...)
			}
			continue
		}
		own = append(own, kv{key: k.Value, k: k, v: v})
	}
	seen := map[string]bool{}
	var out []kv
	for _, p := range own {
		if !seen[p.key] {
			seen[p.key] = true
			out = append(out, p)
		}
	}
	for _, p := range merged {
		if !seen[p.key] {
			seen[p.key] = true
			out = append(out, p)
		}
	}
	return out
}

func (y *yamlCtx) get(m *yaml.Node, key string) *yaml.Node {
	for _, p := range y.pairs(m) {
		if p.key == key {
			return deref(p.v)
		}
	}
	return nil
}

func isStr(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && n.ShortTag() == "!!str"
}

// scalar returns a scalar's value with the position of each byte, when the
// value is written verbatim on its line.
func (y *yamlCtx) scalar(n *yaml.Node) ptext {
	v := n.Value
	opaque := newPText(y.file, n.Line, -1, v)
	if n.Line < 1 || n.Line > len(y.lines) || n.Column < 1 || strings.ContainsAny(v, "\n\r") {
		return opaque
	}
	if n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return opaque
	}
	line := y.lines[n.Line-1]
	off := 0
	if n.Line == 1 && strings.HasPrefix(line, "\uFEFF") {
		off = 3
	}
	for c := 1; c < n.Column; c++ {
		if off >= len(line) {
			return opaque
		}
		_, w := utf8.DecodeRuneInString(line[off:])
		off += w
	}
	rest := line[off:]
	switch {
	case n.Style&yaml.DoubleQuotedStyle != 0:
		if strings.HasPrefix(rest, `"`+v+`"`) && !strings.ContainsAny(v, `\"`) {
			return newPText(y.file, n.Line, off+1, v)
		}
	case n.Style&yaml.SingleQuotedStyle != 0:
		if strings.HasPrefix(rest, "'"+v+"'") && !strings.Contains(v, "'") {
			return newPText(y.file, n.Line, off+1, v)
		}
	default:
		if strings.HasPrefix(rest, v) {
			return newPText(y.file, n.Line, off, v)
		}
	}
	return opaque
}

func (s *scanner) yamlFile(rel string, k Kind, b []byte) {
	mentionsImage := bytes.Contains(b, []byte("image")) || bytes.Contains(b, []byte("repository"))
	if (k == KindKubernetes || k == KindHelmValues) && bytes.Contains(b, []byte("{{")) && !bytes.Contains(b, []byte("${{")) {
		if mentionsImage {
			s.skip(Skip{File: rel, Kind: k, Reason: "Go template (a Helm chart template?): image references are decided when the chart is rendered; scan the rendered output instead"})
		}
		return
	}
	y := &yamlCtx{
		s: s, file: rel, kind: k, lines: rawLines(b), budget: yamlWorkBudget,
		reported: map[*yaml.Node]bool{}, visited: map[*yaml.Node]bool{},
	}
	docs, err := decodeYAML(b)
	if err != nil && (k != KindKubernetes || mentionsImage) {
		s.skip(Skip{File: rel, Kind: k, Reason: "YAML does not parse: " + err.Error()})
	}
	if k == KindCompose {
		y.env = s.loadDotEnv(path.Join(path.Dir(rel), ".env"))
	}
	for _, doc := range docs {
		root := deref(doc)
		if root == nil {
			continue
		}
		switch k {
		case KindCompose:
			if y.get(root, "services") != nil {
				y.compose(root)
			} else {
				y.kind = KindKubernetes
				y.kubernetes(root, true)
				y.kind = k
			}
		case KindGitHubActions:
			y.githubActions(root)
		case KindGitLabCI:
			y.gitlab(root)
		case KindBitbucket:
			y.bitbucket(root, "")
		case KindHelmValues:
			y.helmValues(root, "")
			y.kubernetes(root, false)
		case KindKubernetes:
			if y.looksCompose(root) {
				// A Compose file under another name (docker stack deploy -c
				// anything.yml, compose -f anything.yml).
				if y.env == nil {
					y.env = s.loadDotEnv(path.Join(path.Dir(rel), ".env"))
				}
				y.compose(root)
			} else {
				y.kubernetes(root, true)
			}
		}
		if y.budget < 0 {
			s.skip(Skip{File: rel, Kind: k, Reason: "not fully scanned: " + errBudget.Error()})
			return
		}
	}
}

// ref records a YAML scalar as an image reference (or a Skip).
func (y *yamlCtx) ref(n *yaml.Node, ctx string, t ptext, vars []VarUse, kind Kind) {
	if y.reported[n] {
		return
	}
	y.reported[n] = true
	r := Ref{File: y.file, Line: n.Line, Kind: kind, Context: ctx, Text: n.Value}
	if len(t) > 0 && t[0].s.line == n.Line && t[0].s.col >= 0 {
		r.Column = t[0].s.col + 1
	}
	y.s.addRef(r, t, vars)
}

func (y *yamlCtx) skipNode(n *yaml.Node, kind Kind, reason string) {
	if y.reported[n] {
		return
	}
	y.reported[n] = true
	y.s.skip(Skip{File: y.file, Line: n.Line, Kind: kind, Text: n.Value, Reason: reason})
}

// plainImage handles a scalar that must not contain variables: values with
// $ or {{ are decided at run time.
func (y *yamlCtx) plainImage(n *yaml.Node, ctx string, kind Kind, varReason string) {
	if n == nil || n.Kind != yaml.ScalarNode || n.ShortTag() == "!!null" || strings.TrimSpace(n.Value) == "" {
		return
	}
	if strings.Contains(n.Value, "{{") || (varReason != "" && strings.Contains(n.Value, "$")) {
		reason := varReason
		if reason == "" || strings.Contains(n.Value, "{{") && !strings.Contains(n.Value, "${{") {
			reason = "template expression: the value is decided at render or run time"
		}
		y.skipNode(n, kind, reason)
		return
	}
	y.ref(n, ctx, y.scalar(n), nil, kind)
}

func join(ctx, k string) string {
	if ctx == "" {
		return k
	}
	return ctx + "." + k
}

// ---- Compose ----

func (y *yamlCtx) compose(root *yaml.Node) {
	for _, svc := range y.pairs(y.get(root, "services")) {
		m := deref(svc.v)
		img := y.get(m, "image")
		if img == nil || img.Kind != yaml.ScalarNode || img.ShortTag() == "!!null" {
			continue
		}
		ctx := "services." + svc.key + ".image"
		if pp := y.get(m, "pull_policy"); pp != nil && pp.Value == "build" && y.get(m, "build") != nil {
			y.skipNode(img, KindCompose, "pull_policy: build: the service builds this image locally, image: only names the result")
			continue
		}
		if y.get(m, "build") != nil {
			ctx += " (service also has build:)"
		}
		t, vars, err := y.interpolate(y.scalar(img), 0)
		if err != nil {
			y.skipNode(img, KindCompose, "cannot interpolate: "+err.Error())
			continue
		}
		y.ref(img, ctx, t, vars, KindCompose)
	}
}

// interpolate applies Compose variable interpolation ($VAR, ${VAR},
// ${VAR:-default}, ${VAR-default}, ${VAR:?err}, ${VAR?err}, ${VAR:+alt},
// ${VAR+alt}, $$) using the .env file next to the Compose file. Shell
// environment variables override .env when Compose runs; the scanner cannot see
// them, exactly as it cannot see --build-arg.
func (y *yamlCtx) interpolate(in ptext, depth int) (ptext, []VarUse, error) {
	if depth > 16 {
		return nil, nil, errors.New("interpolation nested too deeply")
	}
	var out ptext
	var vars []VarUse
	for i := 0; i < len(in); {
		c := in[i].b
		if c != '$' {
			out = append(out, in[i])
			i++
			continue
		}
		if i+1 >= len(in) {
			return nil, nil, errors.New("invalid template: trailing $")
		}
		switch nc := in[i+1].b; {
		case nc == '$':
			out = append(out, in[i+1])
			i += 2
		case nc == '{':
			// Find the matching brace.
			j, level := i+2, 1
			for ; j < len(in); j++ {
				switch {
				case in[j].b == '{' && in[j-1].b == '$':
					level++
				case in[j].b == '}':
					level--
				}
				if level == 0 {
					break
				}
			}
			if j >= len(in) {
				return nil, nil, errors.New("invalid template: missing }")
			}
			body := in[i+2 : j]
			k := 0
			for k < len(body) && isNameByte(body[k].b, k == 0) {
				k++
			}
			if k == 0 {
				return nil, nil, fmt.Errorf("invalid template: %q", in[i:j+1].String())
			}
			name := body[:k].String()
			op, word := "", ptext(nil)
			if k < len(body) {
				rest := body[k:]
				switch {
				case len(rest) >= 2 && rest[0].b == ':' && strings.IndexByte("-?+", rest[1].b) >= 0:
					op, word = rest[:2].String(), rest[2:]
				case strings.IndexByte("-?+", rest[0].b) >= 0:
					op, word = rest[:1].String(), rest[1:]
				default:
					return nil, nil, fmt.Errorf("invalid template: %q", in[i:j+1].String())
				}
			}
			v, set, use, err := y.env.lookup(name)
			if err != nil {
				return nil, nil, err
			}
			var val ptext
			usedDefault := false
			switch op {
			case "":
				if !set {
					return nil, nil, fmt.Errorf("variable %s is not set in .env and has no default", name)
				}
				val = v
			case ":-", "-":
				if !set || (op == ":-" && len(v) == 0) {
					w, wv, err := y.interpolate(word, depth+1)
					if err != nil {
						return nil, nil, err
					}
					val, usedDefault = w, true
					vars = append(vars, wv...)
				} else {
					val = v
				}
			case ":?", "?":
				if !set || (op == ":?" && len(v) == 0) {
					return nil, nil, fmt.Errorf("variable %s is required (%s) and is not set in .env", name, word.String())
				}
				val = v
			case ":+", "+":
				if set && (op == "+" || len(v) != 0) {
					w, wv, err := y.interpolate(word, depth+1)
					if err != nil {
						return nil, nil, err
					}
					val = w
					vars = append(vars, wv...)
				}
			}
			if usedDefault || !set {
				use.Default = true
				use.File, use.Line = "", 0
			}
			vars = append(vars, use)
			out = append(out, val...)
			i = j + 1
		case isNameByte(nc, true):
			j := i + 1
			for j < len(in) && isNameByte(in[j].b, j == i+1) {
				j++
			}
			name := in[i+1 : j].String()
			v, set, use, err := y.env.lookup(name)
			if err != nil {
				return nil, nil, err
			}
			if !set {
				return nil, nil, fmt.Errorf("variable %s is not set in .env and has no default", name)
			}
			vars = append(vars, use)
			out = append(out, v...)
			i = j
		default:
			return nil, nil, fmt.Errorf("invalid template: %q", in[i:].String())
		}
	}
	return out, vars, nil
}

func isNameByte(b byte, first bool) bool {
	switch {
	case b == '_', b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return !first
	}
	return false
}

// looksCompose reports whether a document is Compose-shaped: no apiVersion
// or kind, and a top-level services mapping with at least one service that has
// an image.
func (y *yamlCtx) looksCompose(root *yaml.Node) bool {
	if y.get(root, "apiVersion") != nil || y.get(root, "kind") != nil {
		return false
	}
	for _, svc := range y.pairs(y.get(root, "services")) {
		if img := y.get(svc.v, "image"); img != nil && img.Kind == yaml.ScalarNode {
			return true
		}
	}
	return false
}

// ---- Kubernetes ----

// containerKeys are lists of containers: Pod specs (containers,
// initContainers, ephemeralContainers), Argo Workflows containerSet and
// sidecars, Tekton steps and sidecars.
var containerKeys = map[string]bool{
	"containers": true, "initContainers": true, "ephemeralContainers": true,
	"sidecars": true, "steps": true,
}

// containerMapKeys hold a single container: Argo Workflows template
// container and script, Tekton stepTemplate.
var containerMapKeys = map[string]bool{"container": true, "script": true, "stepTemplate": true}

// kubernetes reports the image of every container anywhere in the document:
// containers, initContainers and ephemeralContainers lists (Pods, workload and
// Argo Rollouts templates, CronJob job templates, Knative and OpenShift
// objects, List items), Argo Workflows templates (container, script,
// containerSet, initContainers, sidecars) and Tekton (steps, sidecars,
// stepTemplate). With needAPI, the document must have apiVersion and kind.
func (y *yamlCtx) kubernetes(root *yaml.Node, needAPI bool) {
	if needAPI && (!isStr(y.get(root, "apiVersion")) || !isStr(y.get(root, "kind"))) {
		return
	}
	y.walk(root, "", func(m *yaml.Node, ctx string) {
		for _, p := range y.pairs(m) {
			if containerMapKeys[p.key] {
				if c := deref(p.v); c != nil && c.Kind == yaml.MappingNode {
					if img := y.get(c, "image"); img != nil {
						y.plainImage(img, join(ctx, p.key)+".image", y.kind, "")
					}
				}
				continue
			}
			if !containerKeys[p.key] {
				continue
			}
			seq := deref(p.v)
			if seq == nil || seq.Kind != yaml.SequenceNode {
				continue
			}
			for i, c := range seq.Content {
				img := y.get(c, "image")
				if img == nil {
					continue
				}
				y.plainImage(img, fmt.Sprintf("%s[%d].image", join(ctx, p.key), i), y.kind, "")
			}
		}
	})
}

// walk visits every mapping once.
func (y *yamlCtx) walk(n *yaml.Node, ctx string, fn func(m *yaml.Node, ctx string)) {
	n = deref(n)
	if n == nil || y.visited[n] || !y.spend() {
		return
	}
	y.visited[n] = true
	switch n.Kind {
	case yaml.MappingNode:
		fn(n, ctx)
		for _, p := range y.pairs(n) {
			y.walk(p.v, join(ctx, p.key), fn)
		}
	case yaml.SequenceNode:
		for i, c := range n.Content {
			y.walk(c, ctx+"["+strconv.Itoa(i)+"]", fn)
		}
	}
}

// ---- Helm values ----

// helmValues reports image maps with sibling repository and tag keys (and an
// optional registry and digest), assembled as registry/repository:tag@digest,
// the convention of most charts; and string image: values with a tag or
// digest. A chart's template may assemble the reference differently, which the
// scanner cannot see.
func (y *yamlCtx) helmValues(root *yaml.Node, ctx string) {
	visited := y.visited
	y.visited = map[*yaml.Node]bool{}
	defer func() { y.visited = visited }()
	y.walk(root, ctx, func(m *yaml.Node, ctx string) {
		var repo, tag, reg, dig, img *yaml.Node
		for _, p := range y.pairs(m) {
			switch p.key {
			case "repository":
				repo = deref(p.v)
			case "tag":
				tag = deref(p.v)
			case "registry":
				reg = deref(p.v)
			case "digest":
				dig = deref(p.v)
			case "image":
				img = deref(p.v)
			}
		}
		if img != nil && img.Kind == yaml.ScalarNode && isStr(img) && img.Value != "" {
			if strings.Contains(img.Value, "{{") {
				y.skipNode(img, KindHelmValues, "template expression: the value is decided at render time")
			} else if TagStart(img.Value) >= 0 || strings.Contains(img.Value, "@") {
				if _, err := name.ParseReference(img.Value); err == nil {
					y.ref(img, join(ctx, "image"), y.scalar(img), nil, KindHelmValues)
				}
			}
		}
		if !isStr(repo) || repo.Value == "" {
			return
		}
		full := repo.Value
		if isStr(reg) && reg.Value != "" {
			full = reg.Value + "/" + repo.Value
		}
		if _, err := name.NewRepository(full); err != nil {
			return
		}
		switch {
		case tag == nil:
			return
		case tag.Kind != yaml.ScalarNode:
			return
		case tag.ShortTag() == "!!null" || tag.Value == "":
			y.skipNode(repo, KindHelmValues, "the image tag is empty in values; the chart decides it (often .Chart.AppVersion)")
			return
		case tag.ShortTag() != "!!str":
			y.skipNode(repo, KindHelmValues, fmt.Sprintf("the tag %s is an unquoted YAML number; Helm reads it as a number, so the rendered tag may differ from the text", tag.Value))
			return
		case strings.Contains(tag.Value, "{{") || strings.Contains(repo.Value, "{{"):
			y.skipNode(repo, KindHelmValues, "template expression: the value is decided at render time")
			return
		}
		if y.reported[repo] {
			return
		}
		var t ptext
		if isStr(reg) && reg.Value != "" {
			t = append(t, y.scalar(reg)...)
			t = append(t, newPText("", 0, -1, "/")...)
		}
		t = append(t, y.scalar(repo)...)
		t = append(t, newPText("", 0, -1, ":")...)
		t = append(t, y.scalar(tag)...)
		if isStr(dig) && dig.Value != "" {
			t = append(t, newPText("", 0, -1, "@")...)
			t = append(t, y.scalar(dig)...)
		}
		y.reported[repo] = true
		r := Ref{File: y.file, Line: repo.Line, Kind: KindHelmValues, Context: join(ctx, "repository") + "+tag", Text: t.String()}
		y.s.addRef(r, t, nil)
	})
}

// ---- CI ----

const ghExprReason = "GitHub Actions expression: the value is decided when the workflow runs"

func (y *yamlCtx) githubActions(root *yaml.Node) {
	ghImage := func(n *yaml.Node, ctx string) {
		if n == nil || n.Kind != yaml.ScalarNode {
			return
		}
		if strings.Contains(n.Value, "${{") {
			y.skipNode(n, KindGitHubActions, ghExprReason)
			return
		}
		y.plainImage(n, ctx, KindGitHubActions, "")
	}
	dockerURI := func(n *yaml.Node, ctx string) {
		if n == nil || n.Kind != yaml.ScalarNode || !strings.HasPrefix(n.Value, "docker://") {
			return
		}
		if strings.Contains(n.Value, "${{") {
			y.skipNode(n, KindGitHubActions, ghExprReason)
			return
		}
		t := y.scalar(n)[len("docker://"):]
		if y.reported[n] {
			return
		}
		y.reported[n] = true
		r := Ref{File: y.file, Line: n.Line, Kind: KindGitHubActions, Context: ctx, Text: n.Value}
		if len(t) > 0 && t[0].s.col >= 0 {
			r.Column = t[0].s.col + 1
		}
		y.s.addRef(r, t, nil)
	}
	// Composite/Docker action metadata (action.yml).
	if runs := y.get(root, "runs"); runs != nil {
		dockerURI(y.get(runs, "image"), "runs.image")
	}
	for _, job := range y.pairs(y.get(root, "jobs")) {
		j := deref(job.v)
		base := "jobs." + job.key
		if c := y.get(j, "container"); c != nil {
			if c.Kind == yaml.ScalarNode {
				ghImage(c, base+".container")
			} else {
				ghImage(y.get(c, "image"), base+".container.image")
			}
		}
		for _, svc := range y.pairs(y.get(j, "services")) {
			ghImage(y.get(svc.v, "image"), base+".services."+svc.key+".image")
		}
		if steps := y.get(j, "steps"); steps != nil && steps.Kind == yaml.SequenceNode {
			for i, st := range steps.Content {
				dockerURI(y.get(st, "uses"), fmt.Sprintf("%s.steps[%d].uses", base, i))
			}
		}
	}
}

const ciVarReason = "CI variable: the value is decided when the pipeline runs"

var gitlabReserved = map[string]bool{
	"image": true, "services": true, "stages": true, "variables": true, "include": true,
	"workflow": true, "default": true, "before_script": true, "after_script": true, "cache": true,
}

func (y *yamlCtx) gitlabImage(n *yaml.Node, ctx string) {
	n = deref(n)
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		y.plainImage(y.get(n, "name"), ctx+".name", KindGitLabCI, ciVarReason)
		return
	}
	y.plainImage(n, ctx, KindGitLabCI, ciVarReason)
}

func (y *yamlCtx) gitlabServices(n *yaml.Node, ctx string) {
	n = deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		return
	}
	for i, s := range n.Content {
		y.gitlabImage(s, fmt.Sprintf("%s[%d]", ctx, i))
	}
}

func (y *yamlCtx) gitlab(root *yaml.Node) {
	y.gitlabImage(y.get(root, "image"), "image")
	y.gitlabServices(y.get(root, "services"), "services")
	if d := y.get(root, "default"); d != nil {
		y.gitlabImage(y.get(d, "image"), "default.image")
		y.gitlabServices(y.get(d, "services"), "default.services")
	}
	for _, p := range y.pairs(root) {
		if gitlabReserved[p.key] {
			continue
		}
		j := deref(p.v)
		if j == nil || j.Kind != yaml.MappingNode {
			continue
		}
		y.gitlabImage(y.get(j, "image"), p.key+".image")
		y.gitlabServices(y.get(j, "services"), p.key+".services")
	}
}

// bitbucket reports every image: key (a string, or a mapping with name:).
func (y *yamlCtx) bitbucket(root *yaml.Node, ctx string) {
	y.walk(root, ctx, func(m *yaml.Node, ctx string) {
		for _, p := range y.pairs(m) {
			if p.key != "image" {
				continue
			}
			n := deref(p.v)
			if n == nil {
				continue
			}
			if n.Kind == yaml.MappingNode {
				y.plainImage(y.get(n, "name"), join(ctx, "image.name"), KindBitbucket, ciVarReason)
			} else {
				y.plainImage(n, join(ctx, "image"), KindBitbucket, ciVarReason)
			}
		}
	})
}
