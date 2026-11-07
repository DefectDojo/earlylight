package repo

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// Build systems that make musl firmware: Buildroot and OpenWrt
// configurations name the package and the C library in one file; Yocto's
// TCLIBC and image contents are joined across the tree in finishBuild.
//
// Buildroot and Yocto findings are fixed by adding upstream commit
// 4353fdc43 as a patch, scoped to the OpenSSH versions it applies to (8.9p1
// to 10.6p1, checked with patch --dry-run on every release, and built on
// musl for 8.9p1, 9.9p2 and 10.6p1), so it never lands on 10.6p2 or later.

//go:embed avoid-password-authn-bypass.patch
var upstreamPatch []byte

// PatchName is the file name the fix adds.
const PatchName = "0001-avoid-password-authn-bypass.patch"

// buildrootVersions are the OpenSSH versions Buildroot's branches from
// 2022.02.x to 2026.08.x ship (checked 2026-11-05); master has 10.6p2.
var buildrootVersions = []string{"8.9p1", "9.0p1", "9.1p1", "9.3p2", "9.6p1", "9.7p1", "9.8p1", "9.9p2", "10.0p1", "10.2p1", "10.5p1", "10.6p1"}

// yoctoSeries maps an OpenEmbedded release to its OpenSSH version (checked
// 2026-11-05). dunfell (8.2p1) and older are too old for the patch;
// blacksail is left out because its branch and master differ.
var yoctoSeries = map[string]string{"kirkstone": "8.9p1", "langdale": "9.0p1", "mickledore": "9.3p2", "nanbield": "9.5p1",
	"scarthgap": "9.6p1", "styhead": "9.8p1", "walnascar": "9.9p2", "whinlatter": "10.2p1", "wrynose": "10.3p1"}

var (
	brOpenSSH     = regexp.MustCompile(`(?m)^BR2_PACKAGE_OPENSSH=y`)
	brServer      = regexp.MustCompile(`(?m)^BR2_PACKAGE_OPENSSH_SERVER=(y|n)|^# BR2_PACKAGE_OPENSSH_SERVER is not set`)
	brMusl        = regexp.MustCompile(`(?m)^BR2_TOOLCHAIN_(USES_MUSL|BUILDROOT_MUSL|EXTERNAL_[A-Z0-9_]*MUSL[A-Z0-9_]*)=y`)
	brLibc        = regexp.MustCompile(`(?m)^BR2_TOOLCHAIN_(USES_GLIBC|USES_UCLIBC|BUILDROOT_GLIBC|BUILDROOT_UCLIBC)=y`)
	brPAM         = regexp.MustCompile(`(?m)^BR2_PACKAGE_LINUX_PAM=y`)
	brPatchDir    = regexp.MustCompile(`(?m)^BR2_GLOBAL_PATCH_DIR="([^"]*)"`)
	brExtVar      = regexp.MustCompile(`^\$\(BR2_EXTERNAL_([A-Za-z0-9_]+)_PATH\)/(.*)$`)
	owrtServer    = regexp.MustCompile(`(?m)^CONFIG_PACKAGE_(openssh-server(?:-pam)?)=[ym]`)
	yoctoMusl     = regexp.MustCompile(`(?m)^\s*TCLIBC\s*\??\??=\s*["']musl["']`)
	yoctoOpenSSH  = regexp.MustCompile(`(?m)^[^#\n]*(IMAGE_INSTALL|IMAGE_FEATURES|EXTRA_IMAGE_FEATURES|CORE_IMAGE_EXTRA_INSTALL|RDEPENDS)[^=\n]*=[^\n]*\b(openssh-sshd|openssh|ssh-server-openssh|packagegroup-core-ssh-openssh)\b`)
	yoctoSeriesRE = regexp.MustCompile(`(?m)^\s*LAYERSERIES_COMPAT_[A-Za-z0-9_-]+\s*=\s*"([^"]*)"`)
	ocoreRecipe   = regexp.MustCompile(`(^|/)recipes-connectivity/openssh/openssh_([0-9]+\.[0-9]+p[0-9]+)\.bb$`)
)

func lineOf(text string, at int) int { return strings.Count(text[:at], "\n") + 1 }

// readRel reads a repository file, from the overlay first.
func (s *scanner) readRel(rel string) ([]byte, bool) {
	if b, ok := s.opts.Overlay[rel]; ok {
		return b, true
	}
	b, err := readFile(s.root, rel)
	return b, err == nil
}

// listDir lists a repository directory's entries, overlay included.
func (s *scanner) listDir(rel string) []string {
	seen := map[string]bool{}
	if p, err := refs.SafePath(s.root, rel); err == nil {
		if es, err := os.ReadDir(p); err == nil {
			for _, e := range es {
				seen[e.Name()] = true
			}
		}
	}
	pre := strings.TrimSuffix(rel, "/") + "/"
	for p := range s.opts.Overlay {
		if strings.HasPrefix(p, pre) {
			seen[strings.SplitN(p[len(pre):], "/", 2)[0]] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func hasFix(b []byte) bool { return strings.Contains(string(b), "MIN_PASSWORD_HASH_LEN") }

func (s *scanner) build(rel, text string) {
	switch {
	case brOpenSSH.MatchString(text):
		s.buildroot(rel, text)
	case owrtServer.MatchString(text):
		for _, m := range owrtServer.FindAllStringSubmatchIndex(text, -1) {
			pkg := text[m[2]:m[3]]
			s.addBuild(Finding{Rule: RuleBuild, File: rel, Line: lineOf(text, m[0]), Level: "error", Props: map[string]string{"system": "openwrt", "package": pkg},
				Message: fmt.Sprintf("OpenWrt configuration builds %s (OpenWrt uses musl); its openssh needs the *sshole fix", pkg),
				Fix:     "Build from an OpenWrt packages feed with the fix: 23.05 9.8p1-2, 24.10 9.9_p2-2, 25.12 and master 10.6_p2-1 (2026-11-05). 22.03 and older have none: move to a supported release, or add upstream commit 4353fdc43 to net/openssh/patches in your feed."})
		}
	default:
		if m := yoctoMusl.FindStringIndex(text); m != nil {
			s.yoctoMusl = append(s.yoctoMusl, Finding{File: rel, Line: lineOf(text, m[0])})
		}
		if strings.HasSuffix(rel, ".bbappend") && strings.HasPrefix(path.Base(rel), "openssh_") && strings.Contains(text, PatchName) {
			s.yoctoPatched = append(s.yoctoPatched, rel)
		}
		for _, m := range yoctoOpenSSH.FindAllStringIndex(text, -1) {
			s.yoctoSSH = append(s.yoctoSSH, Finding{File: rel, Line: lineOf(text, m[0])})
		}
	}
}

func (s *scanner) buildroot(rel, text string) {
	loc := brOpenSSH.FindStringIndex(text)
	if m := brServer.FindStringSubmatch(text); m != nil && m[1] != "y" {
		return // the client only
	}
	if brLibc.MatchString(text) {
		return
	}
	f := Finding{Rule: RuleBuild, File: rel, Line: lineOf(text, loc[0]), Level: "error", Props: map[string]string{"system": "buildroot"}}
	pam := ""
	if brPAM.MatchString(text) {
		pam = " It is built with PAM; UsePAM yes in sshd_config also closes the hole."
	}
	f.Fix = "Move to a Buildroot with OpenSSH 10.6p2 (master since 2026-11-05; the 2025.02.x to 2026.08.x branches had not moved when this was written), or add upstream commit 4353fdc43 as BR2_GLOBAL_PATCH_DIR/openssh/<version>/" + PatchName + "." + pam
	if !brMusl.MatchString(text) {
		f.Rule, f.Level = RuleNotChecked, "note"
		f.Message = "Buildroot configuration builds the OpenSSH server, but its C library is not set in this file; with musl, Buildroot releases before 10.6p2 lack the *sshole fix"
		s.addBuild(f)
		return
	}
	f.Message = "Buildroot configuration builds the OpenSSH server against musl; Buildroot releases before 10.6p2 lack the *sshole fix"
	dir, line, err := s.buildrootPatchDir(rel, text)
	if err == nil && s.patchedIn(dir) {
		return // the patch is in place
	}
	if err != nil {
		f.Fix += " (" + err.Error() + ")"
		s.addBuild(f)
		return
	}
	f.Fixable = true
	f.newFiles = map[string][]byte{}
	for _, v := range buildrootVersions {
		f.newFiles[path.Join(dir, "openssh", v, PatchName)] = upstreamPatch
	}
	f.Props["fix_summary"] = fmt.Sprintf("Adds upstream commit 4353fdc43 (the *sshole fix) under %s/openssh/<version>/ for every OpenSSH version Buildroot's release branches ship (8.9p1 to 10.6p1), so it applies to whichever this Buildroot builds and never to 10.6p2 or later.", dir)
	if line != "" {
		last := strings.Count(strings.TrimRight(text, "\n"), "\n") + 1
		lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
		l := strings.TrimRight(lines[last-1], "\r")
		f.edit = &Edit{Line: last, Col: len(l), Old: "", New: "\n" + line}
		f.Props["fix_summary"] += " Sets BR2_GLOBAL_PATCH_DIR to that directory."
	}
	s.addBuild(f)
}

// buildrootPatchDir finds where the global patch directory is in the
// repository, and the BR2_GLOBAL_PATCH_DIR line to add when none is set.
func (s *scanner) buildrootPatchDir(rel, text string) (dir, line string, err error) {
	ext, extName := s.externalTree(rel)
	if m := brPatchDir.FindStringSubmatch(text); m != nil && strings.TrimSpace(m[1]) != "" {
		first := strings.Fields(m[1])[0]
		if v := brExtVar.FindStringSubmatch(first); v != nil {
			if ext == "" || !strings.EqualFold(v[1], extName) {
				return "", "", errors.New("BR2_GLOBAL_PATCH_DIR names another external tree")
			}
			return path.Clean(path.Join(ext, v[2])), "", nil
		}
		if strings.Contains(first, "$") || path.IsAbs(first) {
			return "", "", errors.New("BR2_GLOBAL_PATCH_DIR is not a path inside this repository")
		}
		if _, ok := s.readRel("Config.in"); ok { // a Buildroot tree: paths are from its top
			return path.Clean(first), "", nil
		}
		return "", "", errors.New("BR2_GLOBAL_PATCH_DIR is relative to a Buildroot tree that is not this repository")
	}
	if ext == "" {
		return "", "", errors.New("no BR2_GLOBAL_PATCH_DIR and no BR2_EXTERNAL tree to put one in")
	}
	dir = path.Join(ext, "patches")
	return dir, fmt.Sprintf(`BR2_GLOBAL_PATCH_DIR="$(BR2_EXTERNAL_%s_PATH)/patches"`, extName), nil
}

var extNameRE = regexp.MustCompile(`(?m)^name:\s*([A-Za-z0-9_]+)`)

// externalTree is the BR2_EXTERNAL tree holding a defconfig: the nearest
// directory above it with an external.desc.
func (s *scanner) externalTree(rel string) (string, string) {
	for d := path.Dir(rel); ; d = path.Dir(d) {
		if b, ok := s.readRel(path.Join(d, "external.desc")); ok {
			if m := extNameRE.FindSubmatch(b); m != nil {
				return path.Clean(d), string(m[1])
			}
			return "", ""
		}
		if d == "." || d == "/" || d == "" {
			return "", ""
		}
	}
}

// patchedIn reports whether a patch directory already carries the fix for
// openssh, in itself or in a version directory.
func (s *scanner) patchedIn(dir string) bool {
	base := path.Join(dir, "openssh")
	for _, n := range s.listDir(base) {
		p := path.Join(base, n)
		if b, ok := s.readRel(p); ok && hasFix(b) {
			return true
		}
		for _, m := range s.listDir(p) {
			if b, ok := s.readRel(path.Join(p, m)); ok && hasFix(b) {
				return true
			}
		}
	}
	return false
}

// pending build findings, returned by finishBuild.
func (s *scanner) addBuild(f Finding) { s.yoctoSSH = append(s.yoctoSSH, f) }

// yoctoNeedsTree reports a file whose finding depends on other files.
func (s *scanner) yoctoNeedsTree(rel string) bool {
	b := path.Base(rel)
	return b != ".config" && b != "diffconfig" && !strings.HasSuffix(b, "defconfig")
}

// finishBuild returns the build-system findings: Buildroot and OpenWrt as
// found, and Yocto images with OpenSSH where the tree sets TCLIBC to musl
// and no openssh bbappend adds the patch.
func (s *scanner) finishBuild() []Finding {
	var out []Finding
	for _, f := range s.yoctoSSH {
		if f.Rule != "" {
			out = append(out, f)
			continue
		}
		if len(s.yoctoMusl) == 0 || len(s.yoctoPatched) > 0 {
			continue
		}
		m := s.yoctoMusl[0]
		g := Finding{Rule: RuleBuild, File: f.File, Line: f.Line, Level: "error", Props: map[string]string{"system": "yocto", "tclibc": fmt.Sprintf("%s:%d", m.File, m.Line)},
			Message: fmt.Sprintf("Yocto image installs the OpenSSH server and %s:%d sets TCLIBC to musl; OpenEmbedded's openssh before 10.6p2 lacks the *sshole fix", m.File, m.Line),
			Fix:     "OpenEmbedded-Core had OpenSSH 10.6p1 when this was written (2026-11-05). Add upstream commit 4353fdc43 as a patch in an openssh .bbappend for your release's OpenSSH version, or set PasswordAuthentication no."}
		s.yoctoFix(&g)
		out = append(out, g)
	}
	s.yoctoSSH, s.yoctoMusl, s.yoctoPatched = nil, nil, nil
	return out
}

// yoctoFix plans a version-scoped bbappend with the patch in the layer that
// holds the image recipe. The OpenSSH version comes from an
// OpenEmbedded-Core in the repository, else from the layer's single
// LAYERSERIES_COMPAT release.
func (s *scanner) yoctoFix(f *Finding) {
	layer := ""
	for d := path.Dir(f.File); d != "." && d != "/" && d != ""; d = path.Dir(d) {
		if _, ok := s.readRel(path.Join(d, "conf", "layer.conf")); ok {
			layer = d
			break
		}
	}
	if layer == "" {
		f.Fix += " (the recipe is not inside a layer with conf/layer.conf)"
		return
	}
	ver, why := s.yoctoVersion(layer)
	if ver == "" {
		f.Fix += " (" + why + ")"
		return
	}
	dir := path.Join(layer, "recipes-connectivity", "openssh")
	bb := path.Join(dir, "openssh_"+ver+".bbappend")
	if _, ok := s.readRel(bb); ok {
		f.Fix += " (" + bb + " exists; add the patch to it by hand)"
		return
	}
	f.Fixable = true
	f.newFiles = map[string][]byte{
		bb: []byte("# *sshole: OpenSSH password authentication bypass on musl, fixed upstream in\n" +
			"# 10.6p2 (commit 4353fdc43). Scoped to " + ver + ": remove it when openssh moves on.\n" +
			"FILESEXTRAPATHS:prepend := \"${THISDIR}/files:\"\n" +
			"SRC_URI += \"file://" + PatchName + "\"\n"),
		path.Join(dir, "files", PatchName): upstreamPatch,
	}
	f.Props["fix_summary"] = fmt.Sprintf("Adds %s with upstream commit 4353fdc43 (the *sshole fix) for openssh %s. It is scoped to that version, so BitBake reports it when openssh moves on and it can be removed.", bb, ver)
}

func (s *scanner) yoctoVersion(layer string) (string, string) {
	// An OpenEmbedded-Core checked into the repository decides.
	var found []string
	_ = walkRepo(s.root, func(rel string) {
		if m := ocoreRecipe.FindStringSubmatch(rel); m != nil {
			found = append(found, m[2])
		}
	})
	if len(found) == 1 {
		return checkYoctoVersion(found[0])
	}
	b, _ := s.readRel(path.Join(layer, "conf", "layer.conf"))
	m := yoctoSeriesRE.FindSubmatch(b)
	if m == nil {
		return "", "the layer does not name its OpenEmbedded release (LAYERSERIES_COMPAT), so the openssh version is not known"
	}
	vers := map[string]bool{}
	for _, series := range strings.Fields(string(m[1])) {
		v, ok := yoctoSeries[series]
		if !ok {
			return "", "the layer supports " + series + ", whose openssh version is not known here"
		}
		vers[v] = true
	}
	if len(vers) != 1 {
		return "", "the layer supports releases with different openssh versions; add a bbappend for each by hand"
	}
	for v := range vers {
		return checkYoctoVersion(v)
	}
	return "", "no release"
}

func checkYoctoVersion(v string) (string, string) {
	for _, ok := range buildrootVersions {
		if ok == v {
			return v, ""
		}
	}
	switch v {
	case "9.5p1", "10.3p1":
		return v, ""
	}
	return "", "openssh " + v + " is outside the versions the upstream patch applies to (8.9p1 to 10.6p1)"
}

// walkRepo calls fn for every regular file's repository-relative path,
// skipping dependency directories, up to maxFiles.
func walkRepo(root string, fn func(string)) error {
	n := 0
	return fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if n++; n > maxFiles {
			return fs.SkipAll
		}
		fn(p)
		return nil
	})
}
