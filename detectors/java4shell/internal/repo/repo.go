// Package repo finds what in a source tree selects a Java runtime exposed to
// Java4Shell (CVE-2026-114938), and plans the edits that fix it:
//
//   - image-pin: a Dockerfile, Compose, Kubernetes, Helm values, CI file or
//     Jib configuration names a Java runtime image (eclipse-temurin,
//     amazoncorretto, azul/zulu-openjdk...) whose tag is a release without
//     the fix.
//   - java-pin: a version file (.java-version, .sdkmanrc, .tool-versions,
//     mise), a GitHub Actions setup-java step or a buildpack setting pins a
//     release without the fix.
//   - java-line: a Gradle or Maven toolchain, setup-java or a buildpack
//     selects a Java line that received no fix (18 to 20, 22 to 24, 26).
//   - os-package: a Dockerfile installs a distribution's OpenJDK package
//     (apt, apk, dnf, yum, microdnf) without the fix.
//   - not-checked: what could not be read or decided without reading an
//     image.
//
// It knows nothing about the engine.
package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/refs"
)

// Rules.
const (
	RuleImagePin   = "image-pin"
	RuleJavaPin    = "java-pin"
	RuleLine       = "java-line"
	RulePackage    = "os-package"
	RuleNotChecked = "not-checked"
)

// Status of a finding.
const (
	StatusVulnerable = "vulnerable"
	StatusMitigated  = "mitigated"
	StatusUnknown    = "unknown"
)

// Finding is one thing in the tree.
type Finding struct {
	Rule    string            `json:"rule"`
	File    string            `json:"file"`
	Line    int               `json:"line"`
	Level   string            `json:"level"` // error, warning, note
	Status  string            `json:"status"`
	Reason  string            `json:"reason,omitempty"`
	Message string            `json:"message"`
	Fix     string            `json:"fix,omitempty"`
	Fixable bool              `json:"fixable"`
	Props   map[string]string `json:"props,omitempty"`
	// Pull is set for an image reference that only reading the image can
	// decide (a moving tag, a product image).
	Pull string `json:"pull,omitempty"`
	// Optional is a clearly labelled edit fix offers but does not apply: the
	// interim mitigation for an image whose runtime cannot be updated here.
	Optional string `json:"optional,omitempty"`
	ref      *refs.Ref
	edit     *pinEdit
}

// pinEdit locates a version or tag to replace on one line.
type pinEdit struct {
	file string
	line int
	col  int // 0-based byte column of old on the line
	old  string
	kind string // tag, setup-java
	// tag fields
	family  Family
	tv      TagVersion
	image   string
	feature int
}

// Skip is a file that was not read, and why.
type Skip struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Reason string `json:"reason"`
}

// Result is a scan of a tree.
type Result struct {
	Findings  []Finding
	Skips     []Skip
	Files     int
	Truncated bool
}

// Options control a scan.
type Options struct {
	// Overlay replaces file contents (repository-relative, slash paths), so
	// a plan can rescan an edit in memory.
	Overlay map[string][]byte
	// Platforms are the platforms the tree builds; empty means every one.
	Platforms []string
}

const (
	maxFileSize = 4 << 20
	maxFiles    = 200000
)

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true, "__pycache__": true,
	".tox": true, "bower_components": true, ".gradle": true, "target": true, "build": true, ".idea": true}

// Scan walks root.
func Scan(ctx context.Context, root string, opts Options) (Result, error) {
	var res Result
	var list []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			rel, _ := filepath.Rel(root, p)
			res.Skips = append(res.Skips, Skip{File: filepath.ToSlash(rel), Reason: err.Error()})
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if kindOf(rel) == "" {
			return nil
		}
		if len(list) >= maxFiles {
			res.Truncated = true
			return filepath.SkipAll
		}
		list = append(list, rel)
		return nil
	})
	if err != nil {
		return res, err
	}
	return scanList(ctx, root, list, opts, res)
}

func scanList(ctx context.Context, root string, list []string, opts Options, res Result) (Result, error) {
	for rel := range opts.Overlay {
		if kindOf(rel) != "" && !contains(list, rel) {
			list = append(list, rel)
		}
	}
	sort.Strings(list)
	s := &scanner{root: root, opts: opts, mitigated: map[string]string{}}
	for _, rel := range list {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		b, ok := opts.Overlay[rel]
		if !ok {
			var err error
			if b, err = readFile(root, rel); err != nil {
				res.Skips = append(res.Skips, Skip{File: rel, Reason: err.Error()})
				continue
			}
		}
		res.Files++
		text := string(b)
		switch kindOf(rel) {
		case "dockerfile":
			s.dockerfile(rel, text)
		case "java-version":
			s.javaVersionFile(rel, text)
		case "sdkmanrc":
			s.sdkmanrc(rel, text)
		case "tool-versions":
			s.toolVersions(rel, text)
		case "mise":
			s.mise(rel, text)
		case "workflow":
			s.workflow(rel, b)
		case "gradle":
			s.gradle(rel, text)
		case "maven":
			s.maven(rel, text)
		case "project.toml":
			s.projectToml(rel, text)
		}
	}
	s.images(opts)
	res.Findings = append(res.Findings, s.findings...)
	res.Skips = append(res.Skips, s.skips...)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// kindOf classifies a repository path.
func kindOf(rel string) string {
	name := path.Base(rel)
	lower := strings.ToLower(name)
	switch {
	case isDockerfile(lower):
		return "dockerfile"
	case lower == ".java-version":
		return "java-version"
	case lower == ".sdkmanrc":
		return "sdkmanrc"
	case lower == ".tool-versions":
		return "tool-versions"
	case lower == "mise.toml" || lower == ".mise.toml" || lower == "mise.local.toml" || lower == ".rtx.toml":
		return "mise"
	case strings.HasPrefix(rel, ".github/workflows/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")):
		return "workflow"
	case lower == "build.gradle" || lower == "build.gradle.kts" || lower == "settings.gradle" || lower == "settings.gradle.kts" || lower == "gradle.properties":
		return "gradle"
	case lower == "pom.xml" || lower == "toolchains.xml":
		return "maven"
	case lower == "project.toml" || lower == "jib.yaml":
		return "project.toml"
	case strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") || lower == ".env":
		return "yaml" // read by internal/refs; listed so an overlay rescans it
	}
	return ""
}

func isDockerfile(lower string) bool {
	for _, n := range []string{"dockerfile", "containerfile"} {
		if lower == n || strings.HasSuffix(lower, "."+n) {
			return true
		}
		if strings.HasPrefix(lower, n) && strings.ContainsRune("._-", rune(lower[len(n)])) {
			return true
		}
	}
	return false
}

func readFile(root, rel string) ([]byte, error) {
	p, err := refs.SafePath(root, rel)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if fi.Size() > maxFileSize {
		return nil, fmt.Errorf("larger than %d MiB", maxFileSize>>20)
	}
	return os.ReadFile(p)
}

type scanner struct {
	root     string
	opts     Options
	findings []Finding
	skips    []Skip
	// mitigated maps "file:line" of a Dockerfile FROM to the mitigation its
	// stage sets (ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics).
	mitigated map[string]string
}

func (s *scanner) add(f Finding) {
	if f.Props == nil {
		f.Props = map[string]string{}
	}
	s.findings = append(s.findings, f)
}

// lines splits text into lines without terminators.
func lines(text string) []string {
	ls := strings.Split(text, "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

// ---- version files

var versionInText = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,9}){0,5})`)

// judgeVersion turns a pinned version into a finding, or nothing when it is
// fixed or not affected. A version with fewer numbers than the fix is a
// moving pin (the newest release of that line) and is reported only when
// its line has no fix at all.
func (s *scanner) judgeVersion(rel string, line, col int, verText, source, vendor string) {
	tv := TagVersion{Text: verText, Exact: strings.Count(verText, ".") >= 2}
	for _, p := range strings.Split(verText, ".") {
		n := 0
		fmt.Sscanf(p, "%d", &n)
		tv.Nums = append(tv.Nums, n)
	}
	if len(tv.Nums) == 0 || tv.Nums[0] < 8 || tv.Nums[0] > 99 {
		return
	}
	if strings.Contains(strings.ToLower(vendor), "semeru") || strings.Contains(strings.ToLower(vendor), "openj9") {
		return // OpenJ9: not affected
	}
	st, why := JudgeTag(tv)
	props := map[string]string{"source": source, "current": verText}
	if vendor != "" {
		props["vendor"] = vendor
	}
	if fx := knowledge.FixedVersion(tv.Nums[0]); fx != "" {
		props["fixed_in"] = fx
	}
	switch st {
	case knowledge.Vulnerable:
		rule, level := RuleJavaPin, "warning"
		l, _ := knowledge.LineOf(tv.Nums[0])
		if l.Fixed == nil && tv.Nums[0] > 17 {
			rule, level = RuleLine, "error"
		}
		s.add(Finding{Rule: rule, File: rel, Line: line, Level: level, Status: StatusVulnerable, Reason: why,
			Message: fmt.Sprintf("%s selects Java %s, without the Java4Shell fix", source, verText),
			Fix:     pinFix(tv.Nums[0], source), Props: props})
	case knowledge.Unknown:
		l, ok := knowledge.LineOf(tv.Nums[0])
		if ok && l.Fixed == nil {
			s.add(Finding{Rule: RuleLine, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: l.Note,
				Message: fmt.Sprintf("%s selects Java %s, a line that received no Java4Shell fix", source, verText),
				Fix:     pinFix(tv.Nums[0], source), Props: props})
		}
	}
	_ = col
}

func pinFix(feature int, source string) string {
	if fx := knowledge.FixedVersion(feature); fx != "" {
		return fmt.Sprintf("Select Java %s or later of the same update in %s once your vendor publishes it (Amazon Corretto and SapMachine did on 2026-11-17; Temurin, Debian, Ubuntu and Alpine had not), and reinstall.", fx, source)
	}
	return fmt.Sprintf("Java %d received no fix: move %s to a supported release with the fix, such as %s.", feature, source, knowledge.Upgrade(feature))
}

func (s *scanner) javaVersionFile(rel, text string) {
	for i, l := range lines(text) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if m := versionInText.FindStringIndex(l); m != nil {
			s.judgeVersion(rel, i+1, m[0], l[m[0]:m[1]], ".java-version", vendorWord(l))
		}
		return // jenv reads the first line
	}
}

var sdkmanLine = regexp.MustCompile(`^\s*java\s*=\s*(\d[\w.]*?)(?:-([a-z]+))?\s*$`)

var sdkmanVendors = map[string]string{"tem": "Eclipse Temurin", "amzn": "Amazon Corretto", "zulu": "Azul Zulu", "librca": "BellSoft Liberica",
	"sapmchn": "SapMachine", "ms": "Microsoft", "oracle": "Oracle", "open": "OpenJDK", "sem": "IBM Semeru (OpenJ9)", "graalce": "GraalVM CE",
	"graal": "Oracle GraalVM", "kona": "Tencent Kona", "dragonwell": "Alibaba Dragonwell", "jbr": "JetBrains Runtime", "nik": "Liberica NIK", "mandrel": "Mandrel", "trava": "Trava", "zulufx": "Azul Zulu", "librcafx": "BellSoft Liberica"}

func (s *scanner) sdkmanrc(rel, text string) {
	for i, l := range lines(text) {
		m := sdkmanLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		vendor := sdkmanVendors[m[2]]
		if vendor == "" {
			vendor = m[2]
		}
		if m[2] == "graalce" || m[2] == "graal" || m[2] == "nik" || m[2] == "mandrel" {
			// GraalVM versions follow the JDK's only for 17 and later builds named so.
			if !strings.Contains(m[1], ".") {
				continue
			}
		}
		s.judgeVersion(rel, i+1, strings.Index(l, m[1]), m[1], ".sdkmanrc", vendor)
	}
}

// asdfJava reads asdf-java and mise names: temurin-21.0.5+11.0.LTS,
// corretto-21.0.5.11.1, openjdk-21.0.2, sapmachine-21.0.5, zulu-21.38.21
// (a Zulu version, not a Java version: not judged).
var asdfJava = regexp.MustCompile(`^(?:(adoptopenjdk|temurin|corretto|openjdk|sapmachine|liberica|microsoft|oracle|semeru-openj9|semeru|dragonwell|kona|zulu|graalvm|graalvm-community|oracle-graalvm|mandrel|jetbrains)-)?(?:jre-|jdk-|openj9-)?(\d[\d.]*)`)

func (s *scanner) asdfValue(rel string, line int, value, source string) {
	m := asdfJava.FindStringSubmatch(value)
	if m == nil {
		return
	}
	switch m[1] {
	case "zulu", "graalvm", "mandrel", "jetbrains":
		return // their own version numbers
	}
	ver := m[2]
	if m[1] == "corretto" {
		// corretto-21.0.5.11.1: the fourth number is Corretto's build when
		// the fifth is 1. Keep the Java part.
		parts := strings.Split(ver, ".")
		if len(parts) == 5 && parts[3] != "1" && parts[3] != "0" {
			ver = strings.Join(parts[:3], ".")
		}
	}
	s.judgeVersion(rel, line, 0, strings.TrimSuffix(ver, "."), source, m[1])
}

func (s *scanner) toolVersions(rel, text string) {
	for i, l := range lines(text) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "java" {
			s.asdfValue(rel, i+1, f[1], ".tool-versions")
		}
	}
}

var miseJava = regexp.MustCompile(`^\s*java\s*=\s*["']([^"']+)["']`)

func (s *scanner) mise(rel, text string) {
	for i, l := range lines(text) {
		if m := miseJava.FindStringSubmatch(l); m != nil {
			s.asdfValue(rel, i+1, m[1], path.Base(rel))
		}
	}
}

func vendorWord(s string) string {
	l := strings.ToLower(s)
	for _, v := range []string{"temurin", "corretto", "zulu", "liberica", "sapmachine", "semeru", "openj9", "graalvm", "oracle", "microsoft"} {
		if strings.Contains(l, v) {
			return v
		}
	}
	return ""
}

// ---- GitHub Actions setup-java

// publishedFix are the distributions (setup-java names) whose newest
// release of each fixed line had the fix when the data was checked, so a
// moving version ("21") installs a fixed release.
var publishedFix = map[string]bool{"corretto": true, "sapmachine": true}

func (s *scanner) workflow(rel string, b []byte) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: "not valid YAML: " + refs.CleanText(err.Error(), 200)})
		return
	}
	text := lines(string(b))
	walkYAML(&doc, 0, func(m *yaml.Node) {
		uses := mapGet(m, "uses")
		if uses == nil || !strings.HasPrefix(uses.Value, "actions/setup-java@") {
			return
		}
		with := mapGet(m, "with")
		if with == nil {
			return
		}
		dist := ""
		if d := mapGet(with, "distribution"); d != nil {
			dist = d.Value
		}
		jv := mapGet(with, "java-version")
		if jv == nil {
			return
		}
		vals := []*yaml.Node{jv}
		if jv.Kind == yaml.ScalarNode && strings.Contains(jv.Value, "\n") {
			vals = nil // a block of versions: each line
			for i, v := range strings.Split(strings.TrimSpace(jv.Value), "\n") {
				vals = append(vals, &yaml.Node{Kind: yaml.ScalarNode, Value: strings.TrimSpace(v), Line: jv.Line + 1 + i})
			}
		}
		for _, v := range vals {
			if v.Kind != yaml.ScalarNode {
				continue
			}
			if strings.Contains(v.Value, "${{") {
				s.add(Finding{Rule: RuleNotChecked, File: rel, Line: v.Line, Level: "note", Status: StatusUnknown,
					Reason:  "the version is a workflow expression decided when the job runs",
					Message: fmt.Sprintf("setup-java's java-version %q is decided when the job runs; check that it selects a release with the Java4Shell fix", refs.CleanText(v.Value, 80))})
				continue
			}
			s.setupJava(rel, v, dist, text)
		}
	})
}

func (s *scanner) setupJava(rel string, v *yaml.Node, dist string, text []string) {
	ver := strings.TrimSpace(v.Value)
	ver = strings.TrimSuffix(strings.TrimSuffix(ver, "-ea"), ".x")
	m := versionInText.FindString(ver)
	if m == "" || m != ver && !strings.HasPrefix(ver, m+"+") {
		return
	}
	if dist == "semeru" {
		return
	}
	before := len(s.findings)
	s.judgeVersion(rel, v.Line, 0, m, "actions/setup-java", dist)
	if len(s.findings) == before {
		return
	}
	f := &s.findings[len(s.findings)-1]
	f.Props["distribution"] = dist
	feature := 0
	fmt.Sscanf(m, "%d", &feature)
	// A pin of a fixed line moves to the moving major version when the
	// distribution's newest release is fixed: setup-java then installs it.
	if f.Rule == RuleJavaPin && publishedFix[dist] && v.Line >= 1 && v.Line <= len(text) {
		line := text[v.Line-1]
		col := strings.Index(line, ver)
		if col >= 0 && strings.Count(line, ver) == 1 {
			f.Fixable = true
			f.edit = &pinEdit{file: rel, line: v.Line, col: col, old: ver, kind: "setup-java", feature: feature}
			f.Fix = fmt.Sprintf("Set java-version to %d: %s's newest Java %d release has the fix (%s), and setup-java installs it.", feature, dist, feature, knowledge.FixedVersion(feature))
		}
	}
	if !f.Fixable && f.Rule == RuleJavaPin {
		f.Fix = fmt.Sprintf("Set java-version to %s or later once the %s distribution publishes it (it had not when this detector's data was checked, %s), or use distribution corretto or sapmachine, which have.", knowledge.FixedVersion(feature), orAny(dist), knowledge.Checked)
	}
}

func orAny(d string) string {
	if d == "" {
		return "selected"
	}
	return d
}

// ---- Gradle, Maven, buildpacks

var (
	gradleToolchain = regexp.MustCompile(`JavaLanguageVersion\.of\(\s*["']?(\d{1,2})["']?\s*\)`)
	gradleRelease   = regexp.MustCompile(`(?:sourceCompatibility|targetCompatibility|options\.release|release\.set)\s*[=(]\s*(?:JavaVersion\.VERSION_|["'])?(\d{1,2})\b`)
	bpJVM           = regexp.MustCompile(`BP_JVM_VERSION["']?\s*(?:[:=]|to|>)\s*["']?(\d{1,2}(?:\.\d+)*)`)
	jibFrom         = regexp.MustCompile(`(?:from\s*\{[^}]*?image\s*=\s*|jib\.from\.image\s*=\s*|<from>\s*<image>\s*)["']?([A-Za-z0-9][\w./:@-]*)`)
	mavenToolchain  = regexp.MustCompile(`<version>\s*\[?(\d{1,2})(?:,\))?\s*</version>`)
	enforcerJava    = regexp.MustCompile(`(?s)<requireJavaVersion>\s*<version>\s*([^<]{1,60})</version>`)
)

// lineToolchain reports a toolchain or release setting that selects a Java
// line with no fix. Lines with a fix are not reported: the toolchain picks
// whichever release of that line is installed.
func (s *scanner) lineToolchain(rel string, line int, feature int, source string) {
	l, ok := knowledge.LineOf(feature)
	if !ok || l.Fixed != nil {
		return
	}
	s.add(Finding{Rule: RuleLine, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: l.Note,
		Message: fmt.Sprintf("%s selects Java %d, a line that received no Java4Shell fix", source, feature),
		Fix:     fmt.Sprintf("Java %d received no fix: move to a supported release with the fix, such as %s.", feature, knowledge.Upgrade(feature)),
		Props:   map[string]string{"source": source, "current": fmt.Sprint(feature)}})
}

func (s *scanner) gradle(rel, text string) {
	for i, l := range lines(text) {
		for _, m := range gradleToolchain.FindAllStringSubmatch(l, -1) {
			n := 0
			fmt.Sscanf(m[1], "%d", &n)
			s.lineToolchain(rel, i+1, n, "the Gradle toolchain")
		}
		if m := bpJVM.FindStringSubmatch(l); m != nil {
			s.buildpack(rel, i+1, m[1])
		}
		s.jib(rel, i+1, l)
	}
}

func (s *scanner) maven(rel, text string) {
	ls := lines(text)
	inToolchain := false
	for i, l := range ls {
		if strings.Contains(l, "<toolchain>") || strings.Contains(l, "<toolchains>") || strings.Contains(l, "<jdk>") {
			inToolchain = true
		}
		if inToolchain {
			if m := mavenToolchain.FindStringSubmatch(l); m != nil && path.Base(rel) == "toolchains.xml" || m != nil && strings.Contains(strings.Join(ls[max(0, i-3):i], "\n"), "<jdk>") {
				n := 0
				fmt.Sscanf(m[1], "%d", &n)
				s.lineToolchain(rel, i+1, n, "the Maven toolchain")
			}
		}
		if strings.Contains(l, "</toolchain>") || strings.Contains(l, "</jdk>") {
			inToolchain = false
		}
		if m := bpJVM.FindStringSubmatch(l); m != nil {
			s.buildpack(rel, i+1, m[1])
		}
		s.jib(rel, i+1, l)
	}
	for _, m := range enforcerJava.FindAllStringSubmatchIndex(text, -1) {
		floor := strings.TrimSpace(text[m[2]:m[3]])
		line := strings.Count(text[:m[2]], "\n") + 1
		lo := strings.TrimLeft(floor, "[(")
		lo, _, _ = strings.Cut(lo, ",")
		v, ok := knowledge.Parse(lo)
		if !ok || v.Feature() < 17 {
			continue
		}
		fx := knowledge.FixedVersion(v.Feature())
		if fx == "" {
			continue
		}
		fv, _ := knowledge.Parse(fx)
		if knowledge.Compare(v.Nums, fv.Nums) < 0 && strings.Count(lo, ".") >= 2 {
			s.add(Finding{Rule: RuleJavaPin, File: rel, Line: line, Level: "note", Status: StatusUnknown,
				Reason:  "the Maven Enforcer floor lets a build run on a release without the fix; it does not choose the release",
				Message: fmt.Sprintf("the Maven Enforcer requireJavaVersion floor %s is below %s, the first release with the Java4Shell fix", floor, fx),
				Fix:     fmt.Sprintf("Raise the floor to %s so builds fail on a JDK without the fix.", fx),
				Props:   map[string]string{"source": "maven-enforcer", "current": floor, "fixed_in": fx}})
		}
	}
}

func (s *scanner) projectToml(rel, text string) {
	for i, l := range lines(text) {
		if m := bpJVM.FindStringSubmatch(l); m != nil {
			s.buildpack(rel, i+1, m[1])
		}
		if strings.HasSuffix(rel, "jib.yaml") {
			if m := regexp.MustCompile(`^\s*image\s*:\s*["']?([A-Za-z0-9][\w./:@-]*)`).FindStringSubmatchIndex(l); m != nil {
				s.jibRef(rel, i+1, m[2], l[m[2]:m[3]])
			}
		}
	}
}

// buildpack judges BP_JVM_VERSION: Paketo installs the newest release of
// that line (BellSoft Liberica by default) when the image is built.
func (s *scanner) buildpack(rel string, line int, ver string) {
	n := 0
	fmt.Sscanf(ver, "%d", &n)
	if l, ok := knowledge.LineOf(n); ok && l.Fixed == nil {
		s.lineToolchain(rel, line, n, "BP_JVM_VERSION (Cloud Native Buildpacks)")
		return
	}
	if strings.Count(ver, ".") >= 2 {
		s.judgeVersion(rel, line, 0, ver, "BP_JVM_VERSION (Cloud Native Buildpacks)", "")
	}
}

func (s *scanner) jib(rel string, line int, l string) {
	m := jibFrom.FindStringSubmatchIndex(l)
	if m == nil {
		return
	}
	s.jibRef(rel, line, m[2], l[m[2]:m[3]])
}

// jibRef judges a Jib base image like an image reference.
func (s *scanner) jibRef(rel string, line, col int, image string) {
	r := refs.Ref{File: rel, Line: line, Column: col + 1, Kind: "jib", Context: "jib.from.image", Text: image, Image: image,
		Parts: []refs.Part{{Text: image, File: rel, Line: line, Column: col + 1}}, EditFile: rel, EditLine: line, EditText: image}
	s.judgeRef(r, s.opts)
}

// ---- Dockerfiles: OS packages and the mitigation a stage sets

var (
	aptJava  = regexp.MustCompile(`\b(openjdk-(\d{1,2})-(?:jre|jdk)(?:-headless)?)(?:=([^\s;&|]+))?`)
	apkJava  = regexp.MustCompile(`\b(openjdk(\d{1,2})(?:-jre|-jdk|-jre-headless|-jmods)?)(?:[=~><]+([^\s;&|]+))?`)
	rpmJava  = regexp.MustCompile(`\b(java-(\d{1,2})-(?:openjdk|amazon-corretto)(?:-headless|-devel)?)(?:-(\d[\w.:-]*))?`)
	envJTO   = regexp.MustCompile(`(?i)^\s*ENV\s+`)
	fromLine = regexp.MustCompile(`(?i)^\s*FROM\s`)
)

func (s *scanner) dockerfile(rel, text string) {
	ls := lines(text)
	from := 0
	for i := 0; i < len(ls); i++ {
		l := ls[i]
		// Join continuation lines for matching; report the first line.
		full := l
		j := i
		for strings.HasSuffix(strings.TrimRight(ls[j], " \t"), "\\") && j+1 < len(ls) {
			j++
			full = strings.TrimSuffix(strings.TrimRight(full, " \t"), "\\") + " " + ls[j]
		}
		trim := strings.TrimSpace(full)
		switch {
		case fromLine.MatchString(trim):
			from = i + 1
		case envJTO.MatchString(trim):
			var o jvm.Options
			body := envJTO.ReplaceAllString(trim, "")
			for _, kv := range jvm.Words(body) {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					continue
				}
				for _, n := range jvm.EnvVars {
					if k == n {
						o.Apply(v, "ENV "+k+" in "+rel)
					}
				}
			}
			if ok, how := o.Mitigates(); ok && from > 0 {
				s.mitigated[fmt.Sprintf("%s:%d", rel, from)] = how
			}
		case strings.HasPrefix(strings.ToUpper(trim), "RUN "):
			s.packages(rel, i+1, trim)
		}
		i = j
	}
}

// packages finds distribution OpenJDK packages a RUN line installs.
func (s *scanner) packages(rel string, line int, run string) {
	lower := run
	installs := strings.Contains(lower, "apt-get install") || strings.Contains(lower, "apt install") || strings.Contains(lower, "apk add") ||
		strings.Contains(lower, "dnf install") || strings.Contains(lower, "yum install") || strings.Contains(lower, "microdnf install") ||
		strings.Contains(lower, "zypper in")
	if !installs {
		return
	}
	type hit struct{ name, ver string }
	var hits []struct {
		hit
		feature int
		mgr     string
	}
	for _, m := range aptJava.FindAllStringSubmatch(run, -1) {
		n := 0
		fmt.Sscanf(m[2], "%d", &n)
		hits = append(hits, struct {
			hit
			feature int
			mgr     string
		}{hit{m[1], m[3]}, n, "apt"})
	}
	for _, m := range apkJava.FindAllStringSubmatch(run, -1) {
		n := 0
		fmt.Sscanf(m[2], "%d", &n)
		hits = append(hits, struct {
			hit
			feature int
			mgr     string
		}{hit{m[1], m[3]}, n, "apk"})
	}
	for _, m := range rpmJava.FindAllStringSubmatch(run, -1) {
		n := 0
		fmt.Sscanf(m[2], "%d", &n)
		hits = append(hits, struct {
			hit
			feature int
			mgr     string
		}{hit{m[1], m[3]}, n, "rpm"})
	}
	for _, h := range hits {
		if h.feature < 17 {
			continue // Java 8 and 11 packages are not affected
		}
		props := map[string]string{"package": h.name, "manager": h.mgr}
		l, _ := knowledge.LineOf(h.feature)
		if l.Fixed == nil {
			s.add(Finding{Rule: RuleLine, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: l.Note,
				Message: fmt.Sprintf("installs %s, a Java %d package: that line received no Java4Shell fix", h.name, h.feature),
				Fix:     fmt.Sprintf("Install a supported Java package with the fix instead, such as %s.", knowledge.Upgrade(h.feature)), Props: props})
			continue
		}
		fx := knowledge.FixedVersion(h.feature)
		props["fixed_in"] = fx
		if h.ver != "" {
			props["current"] = h.ver
			up := h.ver
			if i := strings.IndexByte(up, ':'); i >= 0 {
				up = up[i+1:]
			}
			up = strings.ReplaceAll(up, "_p", "+")
			if v, ok := knowledge.Parse(up); ok {
				if st, why := knowledge.Judge(v); st == knowledge.Vulnerable {
					s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: why,
						Message: fmt.Sprintf("pins %s to %s, without the Java4Shell fix", h.name, h.ver),
						Fix:     fmt.Sprintf("Pin %s to a package of Java %s or later once your distribution publishes it (none had as of %s), then rebuild. Until then set ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in this stage.", h.name, fx, knowledge.Checked),
						Props:   props})
				}
			}
			continue
		}
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "warning", Status: StatusVulnerable,
			Reason:  fmt.Sprintf("Debian, Ubuntu and Alpine had published no %s package with the fix as of %s (Red Hat's status was not checked), so a build today installs a release without it", fx, knowledge.Checked),
			Message: fmt.Sprintf("installs %s without a version: it gets whatever the distribution has, which had no Java4Shell fix yet", h.name),
			Fix:     fmt.Sprintf("Rebuild once the distribution publishes Java %s or later and check the installed version; until then set ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in this stage.", fx),
			Props:   props})
	}
}

// ---- YAML helpers

func walkYAML(n *yaml.Node, depth int, fn func(m *yaml.Node)) {
	if n == nil || depth > 64 {
		return
	}
	if n.Kind == yaml.MappingNode {
		fn(n)
	}
	for _, c := range n.Content {
		walkYAML(c, depth+1, fn)
	}
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
