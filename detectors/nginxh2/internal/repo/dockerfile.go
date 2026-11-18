package repo

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/pkgdb"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// stage is what a Dockerfile stage installs on.
type stage struct {
	base     string // the resolved FROM image, "" when not resolved
	distro   string // debian, ubuntu, alpine, rhel, "" when not known
	branch   string // the Alpine branch the base names ("3.24", "edge"), "" when it does not
	nginxOrg bool   // the stage adds nginx.org's package repository
	vars     map[string]string
}

// dockerfile reads the packages each RUN installs, with the ARG and ENV
// values of its stage.
func (s *scanner) dockerfile(rel string, b []byte) {
	ins, err := refs.Instructions(b)
	if err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: "the Dockerfile could not be parsed (" + refs.CleanText(err.Error(), 120) + "): its RUN lines are not checked for nginx packages"})
		return
	}
	globals := map[string]string{}
	stages := map[string]*stage{}
	var cur *stage
	index := -1
	fromLine := 0
	for _, in := range ins {
		if in.Onbuild && in.Cmd != "run" {
			continue
		}
		switch in.Cmd {
		case "from", "label", "expose", "healthcheck", "stopsignal", "maintainer", "arg", "user", "workdir", "shell":
		default:
			// What the stage changes on top of the image it builds on
			// (files, commands, environment): the built image's
			// configuration is not the base image's.
			if fromLine > 0 && s.stageMods != nil {
				k := fmt.Sprintf("%s:%d", rel, fromLine)
				if _, ok := s.stageMods[k]; !ok {
					s.stageMods[k] = fmt.Sprintf("the Dockerfile builds on this image (%s at line %d), so the image it makes may load another configuration or command", strings.ToUpper(in.Cmd), in.Line)
				}
			}
		}
		if in.Cmd == "from" {
			fromLine = in.Line
		}
		switch in.Cmd {
		case "from":
			index++
			cur = &stage{vars: map[string]string{}}
			w := words(in.Args)
			if len(w) > 0 {
				if prev, ok := stages[strings.ToLower(w[0])]; ok {
					// FROM an earlier stage: its base, repositories and ENV.
					cur.base, cur.distro, cur.branch, cur.nginxOrg = prev.base, prev.distro, prev.branch, prev.nginxOrg
					for k, v := range prev.vars {
						cur.vars[k] = v
					}
				} else if r, ok := s.fromImage[fmt.Sprintf("%s:%d", rel, in.Line)]; ok {
					cur.base = r.Image
					cur.distro = distroOfImage(r.Image)
					if cur.distro == "alpine" {
						cur.branch = alpineBranchOf(r.Image)
					}
				}
			}
			stages[fmt.Sprint(index)] = cur
			if len(w) >= 3 && strings.EqualFold(w[len(w)-2], "as") {
				stages[strings.ToLower(w[len(w)-1])] = cur
			}
		case "arg":
			for _, kv := range words(in.Args) {
				k, v, ok := strings.Cut(kv, "=")
				switch {
				case cur == nil && ok:
					globals[k] = v
				case cur == nil:
				case ok:
					cur.vars[k] = v
				default:
					if g, set := globals[k]; set {
						cur.vars[k] = g
					}
				}
			}
		case "env":
			if cur == nil {
				continue
			}
			ws := words(in.Args)
			if len(ws) >= 2 && !strings.Contains(ws[0], "=") {
				// ENV NAME value (the legacy form)
				cur.vars[ws[0]] = strings.Join(ws[1:], " ")
				continue
			}
			for _, kv := range ws {
				if k, v, ok := strings.Cut(kv, "="); ok {
					cur.vars[k] = v
				}
			}
		case "run":
			if cur == nil {
				continue
			}
			run := in.Args
			if in.JSON != nil {
				run = strings.Join(in.JSON, " ")
			}
			texts := []string{run}
			for _, h := range in.Heredocs {
				texts = append(texts, heredocCommands(h))
			}
			for _, t := range texts {
				if nginxRepo.MatchString(t) {
					cur.nginxOrg = true
				}
				s.packages(rel, in.Line, t, cur)
			}
		}
	}
}

// nginxRepo is nginx.org's package repository being added.
var nginxRepo = regexp.MustCompile(`nginx\.org/packages|packages\.nginx\.org|nginx_signing`)

// heredocCommands turns a heredoc script into one command line.
func heredocCommands(body string) string {
	var out []string
	cur := ""
	for _, l := range strings.Split(body, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasSuffix(t, "\\") {
			cur += strings.TrimSuffix(t, "\\") + " "
			continue
		}
		out = append(out, cur+t)
		cur = ""
	}
	if cur != "" {
		out = append(out, cur)
	}
	return strings.Join(out, " ; ")
}

// distroOfImage tells a base image's distribution from its name; "" when
// the name does not say.
func distroOfImage(image string) string {
	low := strings.ToLower(image)
	repoName, tag, _ := splitImage(low)
	name := repoName[strings.LastIndexByte(repoName, '/')+1:]
	for _, w := range []struct{ word, distro string }{
		{"alpine", "alpine"}, {"ubuntu", "ubuntu"}, {"jammy", "ubuntu"}, {"noble", "ubuntu"}, {"focal", "ubuntu"}, {"resolute", "ubuntu"},
		{"debian", "debian"}, {"bookworm", "debian"}, {"trixie", "debian"}, {"bullseye", "debian"}, {"forky", "debian"},
		{"ubi", "rhel"}, {"rhel", "rhel"}, {"rockylinux", "rhel"}, {"almalinux", "rhel"}, {"centos", "rhel"}, {"fedora", "rhel"}, {"amazonlinux", "rhel"}, {"oraclelinux", "rhel"},
	} {
		if name == w.word || strings.Contains(name, w.word) || strings.Contains(tag, w.word) {
			return w.distro
		}
	}
	switch {
	case strings.HasSuffix(tag, "-slim") || tag == "slim":
		return "debian"
	case name == "nginx" || name == "nginx-unprivileged":
		return "debian" // the official image's default variant is Debian
	}
	return ""
}

var alpineBranchRE = regexp.MustCompile(`(?:^|[^0-9])(3\.\d{1,2})(?:\.\d+)?(?:$|[^0-9.])`)

// alpineBranchOf reads the Alpine branch an image names: alpine:3.24,
// alpine:3.24.4, alpine:edge, python:3.12-alpine3.23, nginx:1.31.8-alpine3.24.
// A moving name (alpine:3, alpine:latest, -alpine) names none.
func alpineBranchOf(image string) string {
	repoName, tag, _ := splitImage(strings.ToLower(image))
	name := repoName[strings.LastIndexByte(repoName, '/')+1:]
	if name == "alpine" {
		if tag == "edge" {
			return "edge"
		}
		if m := alpineBranchRE.FindStringSubmatch(tag); m != nil && strings.HasPrefix(tag, m[1]) {
			return m[1]
		}
		return ""
	}
	if i := strings.Index(tag, "alpine"); i >= 0 {
		if m := alpineBranchRE.FindStringSubmatch(tag[i+len("alpine"):]); m != nil && strings.HasPrefix(tag[i+len("alpine"):], m[1]) {
			return m[1]
		}
	}
	return ""
}

// nginxPackages are the packages that install an nginx server.
var nginxPackages = map[string]string{
	"nginx": "nginx", "nginx-core": "nginx", "nginx-full": "nginx", "nginx-light": "nginx", "nginx-extras": "nginx",
	"nginx-mainline": "nginx", "openresty": "openresty", "angie": "angie", "nginx-plus": "nginx-plus",
}

// pkg is one package argument.
type pkg struct {
	name, product string
	op, ver       string
	module        string // a dnf module stream (nginx:1.24)
}

// parsePkg reads a package argument of the tool: apt's name=version,
// apk's name=version (and ~ > >= < <=), dnf's and yum's name-version, a
// dnf module stream, with an apk @repo tag, a Debian :arch or
// /release removed.
func parsePkg(tool, w string) (pkg, bool) {
	if m, ok := strings.CutPrefix(w, "@module:"); ok {
		m = strings.TrimPrefix(m, "@")
		name, stream, _ := strings.Cut(m, ":")
		stream, _, _ = strings.Cut(stream, "/")
		if p, ok := nginxPackages[name]; ok {
			return pkg{name: name, product: p, module: stream}, true
		}
		return pkg{}, false
	}
	w = strings.TrimPrefix(w, "@")
	for _, op := range []string{">=", "<=", "=", "~", ">", "<"} {
		if i := strings.Index(w, op); i > 0 {
			name := cleanName(w[:i])
			if p, ok := nginxPackages[name]; ok {
				return pkg{name: name, product: p, op: op, ver: strings.Trim(w[i+len(op):], "'\"")}, true
			}
			return pkg{}, false
		}
	}
	name := cleanName(w)
	if p, ok := nginxPackages[name]; ok {
		return pkg{name: name, product: p}, true
	}
	if tool == "dnf" || tool == "dnf5" || tool == "yum" || tool == "microdnf" || tool == "tdnf" || tool == "?" {
		// name-version[-release][.arch]
		for n, p := range nginxPackages {
			if rest, ok := strings.CutPrefix(name, n+"-"); ok && rest != "" && (rest[0] >= '0' && rest[0] <= '9') {
				return pkg{name: n, product: p, op: "=", ver: rest}, true
			}
		}
	}
	return pkg{}, false
}

func cleanName(n string) string {
	if i := strings.IndexByte(n, '@'); i > 0 {
		n = n[:i]
	}
	if i := strings.IndexByte(n, '/'); i > 0 {
		n = n[:i]
	}
	if i := strings.IndexByte(n, ':'); i > 0 {
		n = n[:i]
	}
	for _, a := range []string{".x86_64", ".aarch64", ".noarch"} {
		n = strings.TrimSuffix(n, a)
	}
	return n
}

// packages finds the nginx packages a RUN line installs.
func (s *scanner) packages(rel string, line int, run string, st *stage) {
	run = expandVars(run, lineVars(run, st.vars))
	if !installRE.MatchString(run) && !strings.Contains(run, "$") {
		return
	}
	for _, in := range installs(run, 0) {
		for _, a := range in.args {
			if o, ok := strings.CutPrefix(a, opaqueArg); ok {
				s.skips = append(s.skips, Skip{File: rel, Line: line, Reason: fmt.Sprintf("installs packages named by %s, which this file does not set: not checked for nginx", refs.CleanText(o, 80))})
				continue
			}
			p, ok := parsePkg(in.tool, a)
			if !ok {
				continue
			}
			s.judgePackage(rel, line, in.tool, p, st)
		}
	}
}

func (s *scanner) judgePackage(rel string, line int, tool string, p pkg, st *stage) {
	props := map[string]string{"package": p.name, "tool": tool}
	if st.base != "" {
		props["base"] = st.base
	}
	if p.ver != "" {
		props["pinned"] = p.op + p.ver
	}
	f := Finding{Rule: RulePackage, File: rel, Line: line, Level: "error", Props: props}
	switch {
	case p.product == "nginx-plus":
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Message = "installs NGINX Plus (" + p.name + "), whose release the Dockerfile does not show"
		f.Fix = "Check the NGINX Plus release (nginx -v): 37.0.8.1 or 37.3.0.1 fixes both CVEs."
		f.Reason = "the release is decided by F5's repository at build time"
	case p.module != "":
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		props["module_stream"] = p.module
		f.Message = fmt.Sprintf("enables the nginx:%s module stream: upstream %s received no fix, and Red Hat's status for these CVEs could not be read on %s", p.module, p.module, knowledge.Checked)
		f.Reason = knowledge.DistroStatus["rhel"]
		f.Fix = "Check Red Hat's advisories for CVE-2026-123007 and CVE-2026-123633 and update the stream's packages when a fixed build is published."
	case p.op == "=" || p.op == "" && p.ver != "":
		s.pinned(&f, p, st)
	case (p.op == ">=" || p.op == ">") && p.ver != "":
		if floorFixed(p) {
			return
		}
		s.unpinned(&f, p, st)
	default:
		s.unpinned(&f, p, st)
	}
	if f.Status == "" || f.Status == knowledge.Fixed || f.Status == knowledge.NotAffected {
		return
	}
	if f.Status == knowledge.Vulnerable {
		f.Interim = "Until the package is updated, turn HTTP/2 off in the configuration (\"http2 off;\" and no \"http2\" on any listen): an interim step, not a fix."
	}
	s.add(f)
}

// floorFixed reports a version floor at or past a fixed release.
func floorFixed(p pkg) bool {
	v, err := knowledge.UpstreamOf(p.ver)
	if err != nil {
		return false
	}
	for _, c := range knowledge.CVEs {
		st, _ := knowledge.Nginx(c, v)
		if p.product == "openresty" {
			st, _ = knowledge.OpenResty(c, v)
		}
		if st != knowledge.Fixed {
			return false
		}
	}
	return true
}

// pinned judges a package pinned to a version.
func (s *scanner) pinned(f *Finding, p pkg, st *stage) {
	v, err := knowledge.UpstreamOf(p.ver)
	if err != nil {
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Reason = "the pinned version could not be read"
		f.Message = fmt.Sprintf("installs %s pinned to %q, which does not read as a release", p.name, p.ver)
		f.Fix = "Pin a release with the fix: nginx 1.31.9 or 1.30.7."
		return
	}
	verdicts := map[string]Verdict{}
	for _, c := range knowledge.CVEs {
		var x knowledge.Status
		var why string
		switch p.product {
		case "openresty":
			x, why = knowledge.OpenResty(c, v)
		case "angie":
			x, why = knowledge.Angie(c, v)
		default:
			x, why = knowledge.Nginx(c, v)
		}
		if x == knowledge.Vulnerable && p.product == "nginx" && !nginxOrgVersion(p.ver) && backported(st.distro, p, c.ID) {
			x, why = knowledge.Fixed, "the distribution's backport"
		}
		verdicts[c.ID] = Verdict{x, why}
	}
	f.CVEs = cveList(verdicts)
	f.Status = worst(f.CVEs)
	f.Reason = reasons(f.CVEs)
	f.Message = fmt.Sprintf("installs %s pinned to %s: %s", p.name, p.ver, f.Reason)
	if f.Status == knowledge.Unknown {
		f.Rule, f.Level = RuleNotChecked, "note"
	}
	switch {
	case p.product == "nginx" && st.distro == "alpine" && f.Status == knowledge.Vulnerable:
		if v, ok := knowledge.AlpineFixed[st.branch]; ok && p.op == "=" {
			f.Fix = fmt.Sprintf("Pin %s=%s, the fixed package on Alpine %s, and rebuild.", p.name, v, st.branch)
			f.Fixable = true
			f.pin = &pinEdit{old: p.name + "=" + p.ver, repl: p.name + "=" + v, branch: st.branch}
		} else {
			f.Fix = knowledge.AlpineText(st.branch) + ". Build on Alpine 3.24 with nginx>=1.30.7-r0."
		}
	case p.product == "nginx" && nginxOrgVersion(p.ver):
		f.Fix = fmt.Sprintf("Pin nginx.org's package of 1.31.9 or 1.30.7 (for example nginx=1.31.9-1~%s) after checking that nginx.org's repository lists it, then rebuild.", codename(p.ver))
	case p.product == "nginx" && st.distro != "" && knowledge.DistroStatus[st.distro] != "":
		f.Fix = knowledge.DistroStatus[st.distro] + ". Move the pin to the fixed package when it is published, or install nginx.org's 1.31.9 / 1.30.7."
	case p.product == "openresty":
		f.Fix = OpenResty.NoFix + "."
	case p.product == "angie":
		f.Fix = AngieImage.NoFix + "."
	default:
		f.Fix = "Pin a release with the fix: nginx 1.31.9 or 1.30.7."
	}
}

// unpinned judges a package installed without a version: the build gets
// whatever the repository has.
func (s *scanner) unpinned(f *Finding, p pkg, st *stage) {
	f.CVEs = nil
	switch {
	case p.product == "openresty":
		f.Status, f.Reason = knowledge.Vulnerable, OpenResty.NoFix
		f.Message = "installs OpenResty without a version: " + OpenResty.NoFix
		f.Fix = "Rebuild with an OpenResty release that has the fix once one is published."
	case p.product == "angie":
		f.Status, f.Reason = knowledge.Vulnerable, AngieImage.NoFix
		f.Message = "installs Angie without a version: " + AngieImage.NoFix
		f.Fix = "Rebuild with an Angie release that has the fix once one is published."
	case st.nginxOrg:
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Reason = "the release is decided when the image is built"
		f.Message = "installs nginx from nginx.org without a version: a build from 2026-11-18 on gets 1.31.9 or 1.30.7; an image built before, or from a cached layer, does not"
		f.Fix = "Pin nginx=1.31.9-1~<codename> or 1.30.7-1~<codename> (or a floor) so a cached layer cannot keep the vulnerable release, and rebuild."
	case st.distro == "alpine" && knowledge.AlpineFixed[st.branch] != "":
		v := knowledge.AlpineFixed[st.branch]
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Reason = "the release is decided when the image is built"
		f.Message = fmt.Sprintf("installs %s on Alpine %s (%s) without a version: a build from %s on gets the fixed %s; an image built before, or from a cached layer, does not", p.name, st.branch, st.base, knowledge.Checked, v)
		f.Fix = fmt.Sprintf("Add a floor (apk add '%s>=%s') so a cached layer cannot keep the vulnerable release, and rebuild.", p.name, v)
	case st.distro == "alpine" && st.branch == "":
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Reason = "the base image does not name its Alpine branch"
		f.Message = fmt.Sprintf("installs %s on %s, which does not name its Alpine branch: %s", p.name, st.base, knowledge.DistroStatus["alpine"])
		f.Fix = "Build on alpine:3.24 (or an image that names it) and add a floor: apk add 'nginx>=1.30.7-r0'."
	case st.distro == "alpine":
		f.Status, f.Reason = knowledge.Vulnerable, knowledge.AlpineText(st.branch)
		f.Message = fmt.Sprintf("installs %s from Alpine %s's repository (%s): %s", p.name, st.branch, st.base, knowledge.AlpineText(st.branch))
		f.Fix = "Build on Alpine 3.24 (nginx 1.30.7-r0), or install nginx.org's 1.31.9 / 1.30.7."
	case st.distro == "debian" || st.distro == "ubuntu":
		f.Status, f.Reason = knowledge.Vulnerable, knowledge.DistroStatus[st.distro]
		f.Message = fmt.Sprintf("installs %s from %s's repository (%s): %s", p.name, st.distro, st.base, knowledge.DistroStatus[st.distro])
		f.Fix = "Rebuild when " + st.distro + " publishes a fixed nginx package, or install nginx.org's 1.31.9 / 1.30.7, or build on nginx:1.31.9 / nginx:1.30.7."
	case st.distro == "rhel":
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Reason = knowledge.DistroStatus["rhel"]
		f.Message = fmt.Sprintf("installs %s from a Red Hat family repository (%s): %s", p.name, st.base, knowledge.DistroStatus["rhel"])
		f.Fix = "Check the distribution's advisories for CVE-2026-123007 and CVE-2026-123633 and rebuild with the fixed package."
	default:
		f.Rule, f.Level, f.Status = RuleNotChecked, "note", knowledge.Unknown
		f.Reason = "the base image's distribution could not be told from its name"
		base := st.base
		if base == "" {
			base = "a base image this scan could not resolve"
		}
		f.Message = fmt.Sprintf("installs %s on %s, without a version: which release it gets is not known", p.name, base)
		f.Fix = "Pin a release with the fix (nginx 1.31.9 or 1.30.7), or check the image this builds."
	}
}

// backported reports a backport table row that covers the pinned
// distribution package.
func backported(distro string, p pkg, cve string) bool {
	for _, r := range knowledge.Backports {
		if r.Distro != distro || r.Package != "nginx" || !hasCVE(r.CVEs, cve) {
			continue
		}
		var cmp int
		ok := true
		if distro == "alpine" {
			cmp, ok = pkgdb.CompareAPK(p.ver, r.Fixed)
		} else {
			cmp = pkgdb.CompareDpkg(p.ver, r.Fixed)
		}
		if ok && cmp >= 0 {
			return true
		}
	}
	return false
}

func hasCVE(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// nginxOrgVersion reports nginx.org's package version form:
// 1.31.8-1~trixie (Debian, Ubuntu).
var nginxOrgRE = regexp.MustCompile(`^\d+\.\d+\.\d+-\d+~[a-z]+$`)

func nginxOrgVersion(v string) bool { return nginxOrgRE.MatchString(v) }

func codename(v string) string {
	_, c, ok := strings.Cut(v, "~")
	if !ok {
		return "<codename>"
	}
	return c
}
