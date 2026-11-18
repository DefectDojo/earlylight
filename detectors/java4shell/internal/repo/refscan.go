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
		if sk.Text != "" && !Javaish(sk.Text) {
			continue // an unresolved reference that does not look like Java
		}
		s.skips = append(s.skips, Skip{File: sk.File, Line: sk.Line, Reason: sk.Reason})
	}
	for i := range rs {
		s.judgeRef(rs[i], opts)
	}
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
	mit := s.mitigationFor(r)
	props := map[string]string{"image": img}
	if mit != "" {
		props["mitigation"] = mit
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
	tv, ok := fam.ParseTag(tag)
	if !ok {
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r,
			Reason:  "the tag does not name a Java release, so only the image can show which one it holds",
			Message: fmt.Sprintf("image %s: the tag names no Java release; it was not read", img), Props: props})
		return
	}
	props["current"] = tv.Text
	st, why := JudgeTag(tv)
	switch st {
	case knowledge.Unknown:
		s.add(Finding{Rule: RuleNotChecked, File: r.File, Line: r.Line, Level: "note", Status: StatusUnknown, Pull: img, ref: &r,
			Reason: why, Message: fmt.Sprintf("image %s: %s", img, why), Props: props})
		return
	case knowledge.Vulnerable:
	default:
		return
	}
	feature := tv.Nums[0]
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
		o := jvm.FromEnv(env, nil, 17, nil)
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
