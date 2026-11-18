package repo

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// images judges the image references the tree builds on and deploys.
func (s *scanner) images(opts Options) {
	rs, skips, err := refs.Scan(s.root, refs.Options{Overlay: opts.Overlay})
	if err != nil {
		s.skips = append(s.skips, Skip{File: ".", Reason: "image references: " + err.Error()})
		return
	}
	for _, sk := range skips {
		// An unresolved reference that does not look like Java is left
		// out, unless a variable hides its name: FROM ${BASE}:${VER} can be
		// a Java image, FROM nginx:${VER} cannot.
		if sk.Text != "" && !couldBeJava(sk.Text) {
			continue
		}
		s.skips = append(s.skips, Skip{File: sk.File, Line: sk.Line, Reason: sk.Reason})
	}
	for i := range rs {
		s.judgeRef(rs[i], opts)
		if rs[i].Kind == refs.KindDockerfile && len(rs[i].Vars) > 0 {
			s.composeBuilds(rs[i], opts)
		}
	}
}

// composeBuilds judges a FROM again as each Compose service builds it: a
// build argument replaces the ARG default the reference was read with.
// The value is a literal in the Compose file, so the image it gives is
// judged like any other (not one fix edits: the argument is the Compose
// file's). When the value cannot be read (it comes from the environment),
// or another variable of the reference stays open, the image that build
// uses is not checked, and that is recorded only when it could be a Java
// image.
func (s *scanner) composeBuilds(r refs.Ref, opts Options) {
	uses := map[string]bool{}
	for _, v := range r.Vars {
		uses[v.Name] = true
	}
	// Each Compose file's arguments for this Dockerfile: the services that
	// build it, or, when a service's Dockerfile cannot be placed, any that
	// set an ARG the FROM uses.
	type build struct {
		values map[string]string
		opaque string // an argument whose value the file does not give
	}
	builds := map[string]*build{}
	var order []string
	for _, a := range s.buildArgs {
		if !uses[a.name] || a.dockerfile != "" && a.dockerfile != r.File {
			continue
		}
		b := builds[a.compose]
		if b == nil {
			b = &build{values: map[string]string{}}
			builds[a.compose] = b
			order = append(order, a.compose)
		}
		if !a.literal {
			b.opaque = a.name
		} else if _, ok := b.values[a.name]; !ok {
			b.values[a.name] = a.value
		}
	}
	done := map[string]bool{}
	for _, file := range order {
		b := builds[file]
		img := varRef.ReplaceAllStringFunc(r.Text, func(m string) string {
			g := varRef.FindStringSubmatch(m)
			if v, ok := b.values[g[1]+g[3]]; ok && v != "" {
				return v
			}
			return m
		})
		if b.opaque != "" || strings.Contains(img, "$") {
			if couldBeJava(img) || couldBeJava(r.Text) || Javaish(r.Image) {
				name := b.opaque
				if name == "" {
					for n := range b.values {
						name = n
					}
				}
				s.skips = append(s.skips, Skip{File: r.File, Line: r.Line, Reason: fmt.Sprintf("the FROM is read with the default of ARG %s, which %s sets as a build argument this scan cannot resolve: the image that build uses is not checked", refs.CleanText(name, 60), refs.CleanText(file, 120))})
			}
			continue
		}
		if img == r.Image || done[img] {
			continue
		}
		done[img] = true
		alt := r
		alt.Image, alt.Context = img, "FROM (build arguments of "+file+")"
		before := len(s.findings)
		s.judgeRef(alt, opts)
		for k := before; k < len(s.findings); k++ {
			f := &s.findings[k]
			f.Reason += "; the image is the one " + refs.CleanText(file, 120) + " builds, by its build arguments"
			if f.Fixable {
				f.Fixable, f.edit = false, nil
				f.Fix = "Change the build argument in " + refs.CleanText(file, 120) + " by hand. " + f.Fix
			}
		}
	}
}

// couldBeJava reports whether an image reference with variables in it
// could name a Java image: what is written looks like one, or a variable
// stands where the name is (a variable in the tag alone does not hide the
// name).
func couldBeJava(text string) bool {
	if Javaish(text) {
		return true
	}
	// The name is what comes before the tag: the last ":" outside ${...}
	// that no "/" follows.
	name, depth := text, 0
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == '{':
			depth++
		case c == '}' && depth > 0:
			depth--
		case c == ':' && depth == 0 && !strings.Contains(text[i:], "/"):
			name = text[:i]
			i = len(text)
		}
	}
	return strings.Contains(name, "$")
}

// amd64 reports whether the tree builds for x86-64 (or does not say).
func amd64(opts Options) bool {
	if len(opts.Platforms) == 0 {
		return true
	}
	for _, p := range opts.Platforms {
		if strings.Contains(p, "amd64") || strings.Contains(p, "x86_64") || p == "all" {
			return true
		}
	}
	return false
}

func (s *scanner) judgeRef(r refs.Ref, opts Options) {
	img := r.Image
	if img == "" || img == "scratch" || strings.Contains(img, "$") || !amd64(opts) {
		return
	}
	// FROM --platform=linux/arm64: a stage that is not x86-64. The builder
	// takes amd64, x86_64 and x86-64 in any case, and an OS alone means the
	// builder's own architecture.
	if p := strings.ToLower(r.Platform); p != "" && !strings.Contains(p, "$") {
		if _, arch, ok := strings.Cut(p, "/"); ok && !strings.HasPrefix(arch, "amd64") && !strings.HasPrefix(arch, "x86_64") && !strings.HasPrefix(arch, "x86-64") {
			return
		}
	}
	mit := s.mitigationFor(r)
	props := map[string]string{"image": img}
	if mit != "" {
		props["mitigation"] = mit
	}
	if s.redHatRef(r, img, props, mit) {
		return
	}
	fam, tag, ok := FamilyOf(img)
	if !ok {
		if Javaish(img) {
			s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r,
				Reason:  "the image's Java runtime can only be judged by reading the image",
				Message: fmt.Sprintf("image %s may hold a Java runtime; it was not read", img), Props: props})
		}
		return
	}
	props["vendor"] = fam.Vendor
	if fam.OpenJ9 {
		return // OpenJ9: not affected
	}
	// tag@digest: the digest is the image that runs, and the tag next to
	// it is only text. A tag that says vulnerable is reported; one that
	// would clear is not believed: the image has to be read.
	byDigest := func() {
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r,
			Reason:  "the reference pins a digest, which decides the image that runs; the tag written next to it does not, so only the image can show which Java release it holds",
			Message: fmt.Sprintf("image %s is pinned by digest; it was not read", img), Props: props})
	}
	pinned := strings.Contains(img, "@")
	tv, ok := fam.ParseTag(tag)
	if !ok {
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r,
			Reason:  "the tag does not name a Java release, so only the image can show which one it holds",
			Message: fmt.Sprintf("image %s: the tag names no Java release; it was not read", img), Props: props})
		return
	}
	props["current"] = tv.Text
	st, why := JudgeTag(tv)
	if fam.GraalVM {
		st, why = graalTag(tv, st, why, graalDist(fam.Vendor))
	}
	switch st {
	case knowledge.Unknown:
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r,
			Reason: why, Message: fmt.Sprintf("image %s: %s", img, why), Props: props})
		return
	case knowledge.Vulnerable:
	default:
		if pinned {
			byDigest()
		}
		return
	}
	feature := tv.Nums[0]
	if fam.GraalVM {
		f := Finding{Rule: RuleImagePin, File: r.File, Line: r.Line, Level: "error", Status: StatusVulnerable, Reason: why, ref: &r, Props: props,
			Message: fmt.Sprintf("image %s holds %s for Java %s, without the Java4Shell fix", img, fam.Vendor, tv.Text),
			Fix:     graalFix(feature, "")}
		if mit != "" {
			f.Status, f.Reason = StatusMitigated, why+"; "+mit
			f.Message += ", mitigated by its JVM options until it is updated"
		}
		s.add(f)
		return
	}
	f := Finding{Rule: RuleImagePin, File: r.File, Line: r.Line, Level: "error", Status: StatusVulnerable, Reason: why, ref: &r, Props: props,
		Message: fmt.Sprintf("image %s holds %s Java %s, without the Java4Shell fix", img, fam.Vendor, tv.Text)}
	if fx := knowledge.FixedVersion(feature); fx != "" {
		props["fixed_in"] = fx
		f.Fixable = true
		f.edit = &pinEdit{kind: "tag", family: fam, tv: tv, image: img, feature: feature}
		f.Fix = fmt.Sprintf("Move to the %s image of Java %s or later with the same variant (%q) once %s publishes it, rebuild and redeploy. fix does this after reading the new image.", fam.Vendor, fx, strings.TrimPrefix(tv.Variant, "-"), fam.Vendor)
	} else {
		f.Fix = fmt.Sprintf("Java %d received no fix: move to a supported release with the fix, such as %s (a major upgrade: test it).", feature, knowledge.Upgrade(feature))
	}
	if mit != "" {
		f.Status = StatusMitigated
		f.Reason = why + "; " + mit
		f.Message += ", mitigated by its JVM options until it is updated"
	}
	s.add(f)
}

// mitigationFor returns the mitigation the file sets for the container or
// stage of a reference: a Dockerfile stage's ENV, a Compose service's
// environment, a Kubernetes container's env.
func (s *scanner) mitigationFor(r refs.Ref) string {
	if r.Kind == refs.KindDockerfile {
		return s.mitigated[fmt.Sprintf("%s:%d", r.File, r.Line)]
	}
	return EnvMitigation(s.root, r, s.opts.Overlay)
}

// EnvMitigation reads the JVM option variables a Compose service or
// Kubernetes container sets next to an image reference, and returns the
// mitigation they make ("" for none).
func EnvMitigation(root string, r refs.Ref, overlay map[string][]byte) string {
	if r.Kind != refs.KindCompose && r.Kind != refs.KindKubernetes {
		return ""
	}
	b, ok := overlay[r.File]
	if !ok {
		var err error
		if b, err = readFile(root, r.File); err != nil {
			return ""
		}
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	for i := 0; i < 1000; i++ {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			return ""
		}
		m := findImageMapping(&doc, r.Line, 0)
		if m == nil {
			continue
		}
		env := map[string]string{}
		if r.Kind == refs.KindCompose {
			e := mapGet(m, "environment")
			switch {
			case e == nil:
			case e.Kind == yaml.MappingNode:
				for j := 0; j+1 < len(e.Content); j += 2 {
					env[e.Content[j].Value] = e.Content[j+1].Value
				}
			case e.Kind == yaml.SequenceNode:
				for _, c := range e.Content {
					if k, v, ok := strings.Cut(c.Value, "="); ok {
						env[k] = v
					}
				}
			}
		} else if e := mapGet(m, "env"); e != nil && e.Kind == yaml.SequenceNode {
			for _, c := range e.Content {
				if n, v := mapGet(c, "name"), mapGet(c, "value"); n != nil && v != nil {
					env[n.Value] = v.Value
				}
			}
		}
		// The command the file sets can turn the decoder back on.
		var cmd []string
		for _, k := range []string{"entrypoint", "command", "args"} {
			n := mapGet(m, k)
			switch {
			case n == nil:
			case n.Kind == yaml.SequenceNode:
				var arr []string
				for _, c := range n.Content {
					arr = append(arr, c.Value)
				}
				cmd = append(cmd, jvm.CommandWords(arr)...)
			case n.Kind == yaml.ScalarNode:
				cmd = append(cmd, jvm.Words(n.Value)...)
			}
		}
		if len(cmd) > 0 && !strings.Contains(strings.Join(cmd, " "), "java") {
			cmd = append([]string{"java"}, cmd...) // Kubernetes args go to the image's own java entrypoint
		}
		o := undo(jvm.FromEnv(withoutJavaOptions(env), nil, 17, nil), cmd, env)
		if ok, how := o.Mitigates(); ok {
			return strings.Replace(how, "(from ", "(from "+r.File+" ", 1)
		}
		return ""
	}
	return ""
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
