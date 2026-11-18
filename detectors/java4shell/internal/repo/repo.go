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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	ref  *refs.Ref
	edit *pinEdit
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
	for _, u := range s.unparsed {
		dup := false
		for _, sk := range s.skips {
			dup = dup || sk.File == u.File && sk.Line == 0
		}
		if !dup {
			s.skips = append(s.skips, u)
		}
	}
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
	// unparsed are Dockerfiles the instruction parser refused.
	unparsed []Skip
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
//
// ga is true for a name that pins one release even without an update: asdf
// openjdk-21 and sdkman 21-tem are 21 GA. verText may end in OpenJDK's
// build (+26) and be a pre-release (21-ea+26).
func (s *scanner) judgeVersion(rel string, line int, ga bool, verText, source, vendor string) {
	tv := TagVersion{Text: verText, Exact: ga || strings.Count(verText, ".") >= 2, OpenJDKBuild: -1}
	nums := verText
	if base, b, ok := strings.Cut(verText, "+"); ok {
		// setup-java 17.0.21.1+1: OpenJDK's build.
		nums = base
		if n, err := strconv.Atoi(b); err == nil && n >= 0 {
			tv.OpenJDKBuild = n
		}
	}
	if m := preReleaseSuffix.FindStringIndex(nums); m != nil {
		nums, tv.EA = nums[:m[0]], true
	}
	for _, p := range strings.Split(nums, ".") {
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
	if knowledge.NotJava(tv.Nums) && !isGraal(vendor) {
		s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Reason: knowledge.NotJavaWhy(verText),
			Message: fmt.Sprintf("%s selects %s, which is not a Java version: not checked for the Java4Shell fix", source, verText),
			Fix:     "Check which Java release this selects: 17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 and later of the same update have the fix.",
			Props:   props})
		return
	}
	if isGraal(vendor) {
		s.graalVersion(rel, line, tv, st, why, source, graalDist(vendor), props)
		return
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
		msg := fmt.Sprintf("%s selects Java %s, without the Java4Shell fix", source, verText)
		if rule == RuleLine {
			msg = fmt.Sprintf("%s selects Java %s, a line that received no Java4Shell fix", source, verText)
		}
		s.add(Finding{Rule: rule, File: rel, Line: line, Level: level, Status: StatusVulnerable, Reason: why,
			Message: msg,
			Fix:     pinFix(tv.Nums[0], source), Props: props})
	case knowledge.Unknown:
		l, ok := knowledge.LineOf(tv.Nums[0])
		if ok && l.Fixed == nil {
			s.add(Finding{Rule: RuleLine, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: l.Note,
				Message: fmt.Sprintf("%s selects Java %s, a line that received no Java4Shell fix", source, verText),
				Fix:     pinFix(tv.Nums[0], source), Props: props})
		} else if tv.Exact {
			// A pinned release the data does not settle (17.0.22, a later
			// update): not checked, as an image tag of it is.
			s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Reason: why,
				Message: fmt.Sprintf("%s selects Java %s: not checked for the Java4Shell fix", source, verText),
				Fix:     fmt.Sprintf("Check that Java %s includes %s.", verText, knowledge.BugRef), Props: props})
		}
	}
}

// preReleaseSuffix is a pre-release marker in a version name: 21-ea,
// 17.0.21.1-ea, 22-beta.
var preReleaseSuffix = regexp.MustCompile(`(?i)-(?:ea|beta|rc).*$`)

func pinFix(feature int, source string) string {
	if fx := knowledge.FixedVersion(feature); fx != "" {
		return fmt.Sprintf("Select Java %s or later of the same update in %s once your vendor publishes it (%s), and reinstall.", fx, source, knowledge.VendorStatus())
	}
	return fmt.Sprintf("Java %d received no fix: move %s to a supported release with the fix, such as %s.", feature, source, knowledge.Upgrade(feature))
}

func (s *scanner) javaVersionFile(rel, text string) {
	for i, l := range lines(text) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		// jenv names: temurin64-21.0.13, openjdk64-17.0.21, 21.0.13.
		idx := jenvName.FindStringSubmatchIndex(l)
		if idx == nil {
			return
		}
		m := jenvName.FindStringSubmatch(l)
		ver := m[2]
		if strings.HasPrefix(strings.ToLower(m[1]), "corretto") {
			ver = CorrettoJava(ver)
		}
		ver += plusBuild(l[idx[5]:])
		s.judgeVersion(rel, i+1, false, ver, ".java-version", vendorWord(l))
		return // jenv reads the first line
	}
}

var jenvName = regexp.MustCompile(`^(?:([A-Za-z][A-Za-z.]*?)(?:64)?-)?(\d{1,3}(?:\.\d{1,9}){0,5})(?:$|[^\d.])`)

// ownNumbers notes a pin written in a vendor's own version numbers
// (Zulu 21.50.19, GraalVM 22.3.r17), which do not name the Java update.
func (s *scanner) ownNumbers(rel string, line int, value, source string) {
	s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown,
		Reason:  "the vendor's own version number does not name the Java update",
		Message: fmt.Sprintf("%s selects %s, written in the vendor's own version numbers: not checked for the Java4Shell fix", source, refs.CleanText(value, 80)),
		Fix:     "Check which Java update this release is built on: 17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 and later of the same update have the fix.",
		Props:   map[string]string{"source": source, "current": refs.CleanText(value, 80)}})
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
		if isGraal(m[2]) {
			if g, java, ok := graalNamed(m[1]); ok {
				s.graalOwn(rel, i+1, g, java, m[2] == "grl", strings.TrimSpace(strings.SplitN(l, "=", 2)[1]), ".sdkmanrc")
				continue
			}
		}
		if strings.Contains(m[1], ".r") || m[2] == "grl" || isGraal(m[2]) && strings.Count(m[1], ".") < 2 {
			// GraalVM 22.3.r17 and the like: GraalVM's numbers.
			s.ownNumbers(rel, i+1, strings.TrimSpace(strings.SplitN(l, "=", 2)[1]), ".sdkmanrc")
			continue
		}
		s.judgeVersion(rel, i+1, true, m[1], ".sdkmanrc", vendor)
	}
}

// asdfJava reads asdf-java and mise names: temurin-21.0.5+11.0.LTS,
// corretto-21.0.5.11.1, openjdk-21.0.2, sapmachine-21.0.5, temurin-jre-musl-21.0.5,
// liberica-lite-21.0.5, zulu-21.38.21
// (a Zulu version, not a Java version: not judged).
var asdfJava = regexp.MustCompile(`^(?:(adoptopenjdk|temurin|corretto|openjdk|sapmachine|liberica|microsoft|oracle|semeru-openj9|semeru|dragonwell|kona|zulu|graalvm|graalvm-community|oracle-graalvm|mandrel|jetbrains|java-se-ri)-)?(?:(?:jre|jdk|openj9|musl|lite|javafx|fx|crac)-)*(\d[\d.]*)`)

// mise is true for a mise file: mise resolves a short version (temurin-17,
// 21) to the newest release when it installs, where asdf takes the name as
// one release (openjdk-21 is 21 GA).
func (s *scanner) asdfValue(rel string, line int, value, source string, mise bool) {
	m := asdfJava.FindStringSubmatch(value)
	if m == nil {
		return
	}
	switch m[1] {
	case "graalvm", "mandrel":
		if g, java, ok := graalNamed(value); ok {
			s.graalOwn(rel, line, g, java, m[1] == "graalvm", value, source)
			return
		}
	}
	idx := asdfJava.FindStringSubmatchIndex(value)
	if rest := value[idx[5]:]; strings.Count(strings.TrimSuffix(m[2], "."), ".") < 2 && !anyBuildRE.MatchString(rest) && !asdfPreRelease.MatchString(rest) &&
		(mise || !asdfGANames[m[1]]) {
		s.movingPin(rel, line, atoi(m[2]), m[1], value, source)
		return
	}
	switch m[1] {
	case "zulu":
		// Zulu's own numbers start with the Java line (zulu-22.32.15 is
		// JDK 22): a line that received no fix is vulnerable whatever the
		// rest says; others are not checked.
		if f := atoi(m[2]); f > 17 {
			if l, ok := knowledge.LineOf(f); ok && l.Fixed == nil {
				s.lineToolchain(rel, line, f, source+" ("+refs.CleanText(value, 60)+", Azul Zulu)")
				return
			}
		}
		s.ownNumbers(rel, line, value, source)
		return
	case "jetbrains":
		// JetBrains Runtime: 17.0.9b1087.7 is Java 17.0.9 and JetBrains'
		// build. Reported where the Java update is older than the fixed
		// one; JetBrains' fixed builds are not known, so nothing is cleared.
		// The update the fix came in (17.0.21) is not judged: JetBrains
		// may backport into it, as Red Hat does.
		if v, ok := knowledge.Parse(m[2]); ok && len(v.Nums) >= 3 {
			fx, _ := knowledge.Parse(knowledge.FixedVersion(v.Feature()))
			if st, _ := knowledge.Judge(v); st == knowledge.Vulnerable && (len(fx.Nums) < 3 || knowledge.Compare(v.Nums[:3], fx.Nums[:3]) < 0) {
				s.judgeVersion(rel, line, true, m[2], source, m[1])
				return
			}
		}
		s.ownNumbers(rel, line, value, source)
		return
	case "graalvm", "mandrel":
		s.ownNumbers(rel, line, value, source) // their own version numbers
		return
	}
	ver := strings.TrimSuffix(m[2], ".")
	if m[1] == "corretto" {
		ver = CorrettoJava(ver)
	}
	if !strings.HasSuffix(m[2], ".") {
		// temurin-17.0.21.1+1: OpenJDK's build after +; openjdk-21-ea+26:
		// a pre-release and its build.
		// Liberica writes the marker after the build (+2-ea).
		idx := asdfJava.FindStringSubmatchIndex(value)
		rest := value[idx[5]:]
		if asdfPreRelease.MatchString(rest) {
			ver += "-ea"
		}
		if b := anyBuildRE.FindStringSubmatch(rest); b != nil {
			ver += "+" + b[1]
		}
	}
	s.judgeVersion(rel, line, true, ver, source, m[1])
}

// asdfGANames are the asdf-java names whose short form is one release,
// the line's GA build (openjdk-21, sapmachine-21, java-se-ri-22).
var asdfGANames = map[string]bool{"openjdk": true, "sapmachine": true, "java-se-ri": true}

// movingPin judges a version-manager pin that installs the newest release
// of a Java line when it runs (mise java@temurin-17, java@21): by the
// line, and for a line with a fix by whether the vendor's newest release
// had it when the data was checked, as setup-java's moving versions are.
func (s *scanner) movingPin(rel string, line, feature int, vendor, value, source string) {
	if feature < 17 {
		return // Java 8 to 16: no decoder
	}
	props := map[string]string{"source": source, "current": refs.CleanText(value, 80)}
	l, ok := knowledge.LineOf(feature)
	switch {
	case !ok:
		s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  fmt.Sprintf("Java %d is not in this detector's release data (%s)", feature, knowledge.Checked),
			Message: fmt.Sprintf("%s selects %s: not checked for the Java4Shell fix", source, refs.CleanText(value, 80))})
		return
	case l.Fixed == nil:
		s.lineToolchain(rel, line, feature, source+" ("+refs.CleanText(value, 60)+")")
		return
	}
	fx := knowledge.FixedVersion(feature)
	props["fixed_in"] = fx
	who := ""
	switch {
	case vendor == "corretto" || vendor == "sapmachine":
		return // their newest release has the fix: installed today, it is fixed
	case vendor == "temurin" || vendor == "adoptopenjdk":
		who = "Eclipse Temurin"
	case vendor == "microsoft" && microsoftLines[feature]:
		who = "Microsoft"
	case isGraal(vendor):
		who = "GraalVM (Oracle and the GraalVM project)"
	}
	if who == "" {
		s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  fmt.Sprintf("the version installs the newest %s Java %d when it runs, and whether that release had the fix was not checked", orAny(vendor), feature),
			Message: fmt.Sprintf("%s selects %s, the newest release of Java %d at install time: not checked for the Java4Shell fix", source, refs.CleanText(value, 80), feature),
			Fix:     fmt.Sprintf("Check that the installed release is Java %s or later of the same update.", fx)})
		return
	}
	s.add(Finding{Rule: RuleJavaPin, File: rel, Line: line, Level: "warning", Status: StatusVulnerable, Props: props,
		Reason:  fmt.Sprintf("the version installs the newest %s Java %d when it runs, and %s had published no release with the fix as of %s", orAny(vendor), feature, who, knowledge.Checked),
		Message: fmt.Sprintf("%s selects %s, the newest release of Java %d at install time, which had no Java4Shell fix yet", source, refs.CleanText(value, 80), feature),
		Fix:     fmt.Sprintf("Reinstall once %s publishes Java %s or later, or select corretto or sapmachine, whose newest Java %d has the fix.", who, fx, feature)})
}

// plusBuild returns "+N" when rest starts with OpenJDK's build (+11 in
// 21.0.5+11.0.LTS), "" otherwise.
func plusBuild(rest string) string {
	if m := plusBuildRE.FindStringSubmatch(rest); m != nil {
		return "+" + m[1]
	}
	return ""
}

var plusBuildRE = regexp.MustCompile(`^\+(\d{1,9})`)

// anyBuildRE is OpenJDK's build anywhere in what follows a version name's
// numbers: +26 in -ea+26, +2 in +2-ea.
var anyBuildRE = regexp.MustCompile(`\+(\d{1,9})`)

// asdfPreRelease is a pre-release marker after an asdf version.
var asdfPreRelease = regexp.MustCompile(`(?i)-(?:ea|beta|rc)`)

// CorrettoJava turns an Amazon Corretto version into the Java version it
// ships. Corretto has written its build number in the fourth place
// (21.0.5.11.1: Java 21.0.5, build 11) and, since the out-of-band releases,
// the OpenJDK patch number there (21.0.13.1.2: Java 21.0.13.1, build 2).
// OpenJDK patch numbers are small, so a fourth number above 3 is a build.
//
// A fifth number after a patch number is kept: 17.0.21.1.1 is build 1 of
// 17.0.21.1, which predates the fix.
func CorrettoJava(ver string) string {
	parts := strings.Split(ver, ".")
	if len(parts) >= 4 {
		n := 0
		fmt.Sscanf(parts[3], "%d", &n)
		if n > 3 {
			return strings.Join(parts[:3], ".")
		}
	}
	return ver
}

func (s *scanner) toolVersions(rel, text string) {
	for i, l := range lines(text) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "java" {
			s.asdfValue(rel, i+1, f[1], ".tool-versions", false)
		}
	}
}

var miseJava = regexp.MustCompile(`^\s*java\s*=\s*["']([^"']+)["']`)

func (s *scanner) mise(rel, text string) {
	for i, l := range lines(text) {
		if m := miseJava.FindStringSubmatch(l); m != nil {
			s.asdfValue(rel, i+1, m[1], path.Base(rel), true)
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

// notFixedYet are the distributions (setup-java names) whose newest release
// of each fixed line did not have the fix when the data was checked.
var notFixedYet = map[string]string{"temurin": "Eclipse Temurin", "adopt": "Eclipse Temurin", "adopt-hotspot": "Eclipse Temurin", "microsoft": "Microsoft"}

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
	if strings.HasSuffix(ver, "-ea") {
		return // an early-access build: not a release this data judges
	}
	ver = strings.TrimSuffix(ver, ".x")
	m := versionInText.FindString(ver)
	if m == "" || m != ver && !strings.HasPrefix(ver, m+"+") {
		return
	}
	if dist == "semeru" {
		return
	}
	before := len(s.findings)
	judged := m
	if b, ok := strings.CutPrefix(ver, m+"+"); ok && b != "" && strings.Trim(b, "0123456789") == "" {
		judged = ver // the build decides at a fixed release's boundary
	}
	s.judgeVersion(rel, v.Line, false, judged, "actions/setup-java", dist)
	if len(s.findings) == before {
		s.movingSetupJava(rel, v, m, dist)
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

// movingSetupJava judges a moving setup-java version of a line with a fix
// ("21"): it installs the distribution's newest release of that line when
// the job runs.
func (s *scanner) movingSetupJava(rel string, v *yaml.Node, ver, dist string) {
	if strings.Count(ver, ".") >= 2 {
		return
	}
	feature := atoi(ver)
	l, ok := knowledge.LineOf(feature)
	if !ok || l.Fixed == nil || publishedFix[dist] {
		return
	}
	fx := knowledge.FixedVersion(feature)
	props := map[string]string{"source": "actions/setup-java", "current": ver, "distribution": dist, "fixed_in": fx}
	if who := notFixedYet[dist]; who != "" && (dist != "microsoft" || microsoftLines[feature]) {
		s.add(Finding{Rule: RuleJavaPin, File: rel, Line: v.Line, Level: "warning", Status: StatusVulnerable, Props: props,
			Reason:  fmt.Sprintf("%s had published no Java %s as of %s, so the job installs a release without the fix", who, fx, knowledge.Checked),
			Message: fmt.Sprintf("actions/setup-java installs the newest %s Java %d, which had no Java4Shell fix yet", orAny(dist), feature),
			Fix:     fmt.Sprintf("Rerun once %s publishes Java %s, or use distribution corretto or sapmachine, whose newest Java %d has the fix.", who, fx, feature)})
		return
	}
	s.add(Finding{Rule: RuleNotChecked, File: rel, Line: v.Line, Level: "note", Status: StatusUnknown, Props: props,
		Reason:  fmt.Sprintf("whether %s had published Java %s could not be checked", orAny(dist), fx),
		Message: fmt.Sprintf("actions/setup-java installs the newest %s Java %d: not checked for the Java4Shell fix", orAny(dist), feature),
		Fix:     fmt.Sprintf("Check that the installed release is Java %s or later.", fx)})
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
		s.judgeVersion(rel, line, false, ver, "BP_JVM_VERSION (Cloud Native Buildpacks)", "")
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
	// installRE finds a package tool on a RUN line; installArgs decides
	// whether it installs.
	installRE = regexp.MustCompile(`\b(?:apt-get|aptitude|apt|apk|dnf5?|yum|microdnf|tdnf|zypper|rpm|dpkg)\b`)
	aptJava   = regexp.MustCompile(`\b(openjdk-(\d{1,2})-(?:jre|jdk)(?:-headless)?)\b(=([^\s;&|]+))?`)
	apkJava   = regexp.MustCompile(`\b(openjdk(\d{1,2})(?:-jre|-jdk|-jre-headless|-jmods)?)(?:([=~><]+)([^\s;&|]+))?`)
	rpmJava   = regexp.MustCompile(`\b(java-(\d{1,2})-(openjdk|amazon-corretto)(?:-headless|-devel|-jdk)?)(?:-(\d[\w.:*?+~-]*))?`)
	// rpmLatest is Fedora's and EPEL's java-latest-openjdk: the newest
	// release the distribution carries, named by no release.
	rpmLatest = regexp.MustCompile(`^java-latest-openjdk(?:-headless|-devel|-jmods)?(?:-\d[\w.:*?-]*)?$`)
	// rpmInstallFlag is an rpm option that installs or upgrades package
	// files; a query (-qip) or an erase (-e) is not an install.
	// dpkgInstallFlag is dpkg's install option (-i, --install).
	dpkgInstallFlag = regexp.MustCompile(`^(?:-[a-zA-Z]*i[a-zA-Z]*|--install)$`)
	rpmInstallFlag  = regexp.MustCompile(`^(?:-[a-dfh-pr-zA-UW-Z]*[iUF][a-dfh-pr-zA-UW-Z]*|--install|--upgrade|--freshen|--reinstall)$`)
	vendorJava      = regexp.MustCompile(`\b((temurin|zulu|msopenjdk|sapmachine)-?(\d{1,2})(?:-ca)?(?:-(?:jdk|jre))?(?:-headless)?)\b(=([^\s;&|]+))?`)
	defaultJava     = regexp.MustCompile(`\b(default-(?:jre|jdk)(?:-headless)?)\b`)
	envJTO          = regexp.MustCompile(`(?i)^\s*ENV\s+`)
	cmdLine         = regexp.MustCompile(`(?i)^\s*(?:ENTRYPOINT|CMD)\s+`)
	fromLine        = regexp.MustCompile(`(?i)^\s*FROM\s`)
)

func (s *scanner) dockerfile(rel, text string) {
	// The instructions as the builder reads them: continuation lines joined
	// (comment and blank lines inside one dropped), the escape directive,
	// JSON arguments, heredoc bodies, ONBUILD.
	ins, err := refs.Instructions([]byte(text))
	if err != nil {
		// The image reference scan records the same file when it cannot
		// parse it: one record (scanList).
		s.unparsed = append(s.unparsed, Skip{File: rel, Reason: "the Dockerfile could not be parsed (" + refs.CleanText(err.Error(), 120) + "): the packages it installs are not checked"})
		return
	}
	from := 0
	stageStart := len(s.findings)
	// endStage marks the packages a stage installs as mitigated when the
	// stage sets the mitigation (before or after the install: ENV applies
	// to the image the stage makes).
	stageEnv := map[string]string{}
	var stageCmd []string // ENTRYPOINT and CMD words of the stage
	endStage := func() {
		o := undo(jvm.FromEnv(withoutJavaOptions(stageEnv), nil, 17, nil), stageCmd, stageEnv)
		ok, how := o.Mitigates()
		if !ok || from == 0 {
			return
		}
		how = strings.Replace(how, "(from ", "(from ENV in "+rel+": ", 1)
		s.mitigated[fmt.Sprintf("%s:%d", rel, from)] = how
		for k := stageStart; k < len(s.findings); k++ {
			f := &s.findings[k]
			if f.File == rel && f.Rule == RulePackage && f.Status == StatusVulnerable {
				f.Status = StatusMitigated
				f.Props["mitigation"] = how
				f.Reason += "; " + how
				f.Message += ", mitigated by the stage's JVM options until it is updated"
			}
		}
	}
	defer endStage()
	// vars are the ARG defaults and ENV values the file sets, for package
	// names a RUN takes from a variable.
	vars := map[string]string{}
	for _, in := range ins {
		switch in.Cmd {
		case "from":
			endStage()
			from, stageStart, stageEnv, stageCmd = in.Line, len(s.findings), map[string]string{}, nil
		case "cmd", "entrypoint":
			stageCmd = append(stageCmd, commandWords(in.Args)...)
		case "arg":
			for _, kv := range jvm.Words(in.Args) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					vars[k] = v
				}
			}
		case "env":
			// The last ENV of each variable in the stage is what the
			// image keeps; the mitigation is decided when the stage ends.
			for _, kv := range jvm.Words(in.Args) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					stageEnv[k], vars[k] = v, v
				}
			}
		case "run":
			run := in.Args
			if in.JSON != nil {
				run = strings.Join(jvm.CommandWords(in.JSON), " ")
			}
			s.packages(rel, in.Line, run, vars)
			for _, body := range in.Heredocs {
				s.packages(rel, in.Line, heredocCommands(body), vars)
			}
		}
	}
}

// heredocCommands turns a heredoc's script into one command line: comment
// lines dropped, continuation lines joined, lines separated by ";".
func heredocCommands(body string) string {
	var out []string
	cur := ""
	for _, l := range lines(body) {
		t := strings.TrimSpace(l)
		if cur == "" && (t == "" || strings.HasPrefix(t, "#")) {
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

// packages finds the OpenJDK packages a RUN line installs: distribution
// packages and the vendors' own (Temurin, Corretto, Zulu, Microsoft,
// SapMachine), with or without a version.
func (s *scanner) packages(rel string, line int, run string, vars map[string]string) {
	if !installRE.MatchString(run) {
		return
	}
	var hits []pkgHit
	var opaque []string
	for _, arg := range installArgs(expandVars(run, vars), 0) {
		if strings.HasPrefix(arg, opaqueArg) {
			opaque = append(opaque, strings.TrimPrefix(arg, opaqueArg))
			continue
		}
		fromFile := strings.HasPrefix(arg, fileArg)
		arg = strings.TrimPrefix(arg, fileArg)
		before := len(hits)
		switch {
		case strings.HasPrefix(arg, unreadableArg):
			hits = append(hits, pkgHit{name: strings.TrimPrefix(arg, unreadableArg), mgr: "rpm", vendor: "distribution", unreadable: true})
		case zypperArg.MatchString(arg):
			m := zypperArg.FindStringSubmatch(arg)
			v := "distribution"
			if m[3] == "amazon-corretto" {
				v = "corretto"
			}
			op := m[4]
			if op == "=" {
				op = ""
			}
			hits = append(hits, pkgHit{name: m[1], feature: atoi(m[2]), op: op, ver: m[5], mgr: "rpm", vendor: v})
		case aptArg.MatchString(arg):
			m := aptArg.FindStringSubmatch(arg)
			hits = append(hits, pkgHit{name: m[1], feature: atoi(m[2]), op: opOf(m[3]), ver: m[4], mgr: "apt", vendor: "distribution"})
		case apkArg.MatchString(arg):
			m := apkArg.FindStringSubmatch(arg)
			hits = append(hits, pkgHit{name: m[1], feature: atoi(m[2]), op: m[3], ver: m[4], mgr: "apk", vendor: "distribution"})
		case rpmArg.MatchString(arg):
			m := rpmArg.FindStringSubmatch(arg)
			v := "distribution"
			if m[3] == "amazon-corretto" {
				v = "corretto"
			}
			hits = append(hits, pkgHit{name: m[1], feature: atoi(m[2]), ver: m[4], mgr: "rpm", vendor: v})
		case vendorArg.MatchString(arg):
			m := vendorArg.FindStringSubmatch(arg)
			hits = append(hits, pkgHit{name: m[1], feature: atoi(m[3]), op: opOf(m[4]), ver: m[5], mgr: "package", vendor: m[2]})
		case defaultArg.MatchString(arg):
			hits = append(hits, pkgHit{name: arg, mgr: "apt", vendor: "distribution"})
		case apkCorretto.MatchString(arg):
			m := apkCorretto.FindStringSubmatch(arg)
			hits = append(hits, pkgHit{name: m[1], feature: atoi(m[2]), op: m[3], ver: m[4], mgr: "apk", vendor: "corretto"})
		case rpmLatest.MatchString(arg):
			hits = append(hits, pkgHit{name: arg, mgr: "rpm", vendor: "distribution", latest: true})
		case varJavaArg.MatchString(arg):
			// openjdk-${V}-jre-headless, java-${V}-openjdk: the Java
			// release comes from a variable.
			hits = append(hits, pkgHit{name: arg, mgr: "package", vendor: "distribution", varName: true})
		}
		if len(hits) > before {
			continue
		}
		// A vendor's package no reader above knows: its file name or rpm
		// name may carry the Java version (Oracle, Zulu, Temurin, Liberica
		// and SapMachine rpms); otherwise a Java package file is not checked.
		if openJ9Name.MatchString(arg) {
			continue // IBM Semeru: OpenJ9, not HotSpot
		}
		if v := vendorFileVersion(arg); v != "" && javaWord.MatchString(arg) {
			hits = append(hits, pkgHit{name: arg, mgr: "rpm", vendor: "distribution", ver: v, vendorFile: true})
		} else if fromFile && javaWord.MatchString(arg) {
			hits = append(hits, pkgHit{name: arg, mgr: "rpm", vendor: "distribution", unreadable: true})
		}
	}
	for _, h := range hits {
		s.judgePackage(rel, line, h)
	}
	if len(opaque) > 0 {
		// The package list is not in this file: a gap, not a finding
		// about Java.
		s.skips = append(s.skips, Skip{File: rel, Line: line, Reason: fmt.Sprintf("installs packages named by %s, which this file does not set (a variable without a value here, or a command's output): not checked for Java packages",
			refs.CleanText(strings.Join(opaque, " "), 120))})
	}
}

// opaqueArg marks an install argument whose package names this scan
// cannot read: a variable the file does not set, or a command's output.
const opaqueArg = "\x00opaque:"

var varRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandVars puts in the values the Dockerfile's ARG and ENV lines give
// (${NAME}, $NAME, ${NAME:-default}); a variable the file does not set
// stays as written.
func expandVars(run string, vars map[string]string) string {
	if !strings.Contains(run, "$") {
		return run
	}
	return varRef.ReplaceAllStringFunc(run, func(m string) string {
		g := varRef.FindStringSubmatch(m)
		name := g[1] + g[3]
		if v, ok := vars[name]; ok && v != "" {
			return v
		}
		if g[2] != "" {
			return g[2]
		}
		return m
	})
}

// anchored matches the whole of one argument.
func anchored(re *regexp.Regexp) *regexp.Regexp {
	return regexp.MustCompile(`^(?:` + strings.TrimPrefix(re.String(), `\b`) + `)$`)
}

// varJavaArg is a Java package name with a variable where the release
// is: openjdk-${V}-jre-headless, openjdk$V, java-${V}-openjdk, temurin-${V}-jdk.
var varJavaArg = regexp.MustCompile(`^(?:openjdk-?|java-|temurin-|zulu|msopenjdk-|sapmachine-)\$\{?[A-Za-z_][A-Za-z0-9_]*\}?(?:-[\w.-]*)?$`)

var (
	aptArg     = anchored(aptJava)
	apkArg     = anchored(apkJava)
	rpmArg     = anchored(rpmJava)
	vendorArg  = anchored(vendorJava)
	defaultArg = anchored(defaultJava)
)

var (
	pkgTools = map[string]bool{"apt-get": true, "aptitude": true, "apt": true, "apk": true, "dnf": true, "dnf5": true, "yum": true, "microdnf": true, "tdnf": true, "zypper": true, "rpm": true, "dpkg": true}
	pkgVerbs = map[string]bool{"install": true, "add": true, "in": true, "reinstall": true, "localinstall": true}
	// pkgValueFlags are package-manager options followed by a separate value.
	pkgValueFlags = map[string]bool{"-t": true, "-o": true, "-X": true, "--repository": true, "--virtual": true, "-c": true, "--root": true,
		"-p": true, "--target-release": true, "--option": true, "--repo": true, "--setopt": true, "--enablerepo": true, "--disablerepo": true,
		"--installroot": true, "--releasever": true, "--dbpath": true, "--prefix": true}
)

var (
	rpmArchRE = regexp.MustCompile(`\.(?:x86_64|aarch64|noarch|i686|i386|ppc64le|s390x)$`)
	debArchRE = regexp.MustCompile(`:(?:amd64|arm64|i386|armhf|ppc64el|s390x|all|any|native)$`)
)

// packageName strips what a package argument adds to the name: an rpm
// .arch, a Debian :arch or /target-release (openjdk-17-jdk/bookworm-backports),
// keeping a "=version" pin. It returns "" for something that is not a
// package argument (a path).
func packageName(w string) string {
	name, ver, pinned := strings.Cut(w, "=")
	// An apk repository tag: openjdk21-jre-headless@edge.
	if i := strings.IndexByte(name, '@'); i > 0 {
		name = name[:i]
	}
	if i := strings.IndexByte(name, '/'); i >= 0 {
		if strings.Count(name, "/") > 1 || i == 0 {
			return "" // a path
		}
		name = name[:i]
	}
	name = debArchRE.ReplaceAllString(name, "")
	if pinned {
		return name + "=" + ver
	}
	return rpmArchRE.ReplaceAllString(name, "")
}

// unreadableArg marks a package file installArgs found but could not
// name.
const unreadableArg = "\x00unreadable:"

// apkCorretto is Amazon's Alpine package: amazon-corretto-17,
// amazon-corretto-17=17.0.20.13.1-r0.
var apkCorretto = regexp.MustCompile(`^(amazon-corretto-(\d{1,2})(?:-jre|-jdk)?)(?:([=~><]+)(\S+))?$`)

// zypperArg is zypper's java-17-openjdk=17.0.21.0 (or >=, <...).
var zypperArg = regexp.MustCompile(`^(java-(\d{1,2})-(openjdk|amazon-corretto)(?:-headless|-devel|-jdk)?)(=|>=|<=|>|<)(\S+)$`)

// javaWord is a word a Java package file or URL carries.
var javaWord = regexp.MustCompile(`(?i)java|jdk|jre|corretto|temurin|zulu`)

// globCandidates are names a Java package file could have, for deciding
// whether a pattern (*.rpm) could match one.
var globCandidates = []string{"java-17-openjdk-headless-17.0.21.0.9-1.el9.x86_64.rpm", "java-21-amazon-corretto-devel-21.0.13.1.2-1.x86_64.rpm",
	"java-latest-openjdk-25.0.1.0.8-1.rolling.fc41.x86_64.rpm", "jdk-17.0.9_linux-x64_bin.rpm", "zulu17.46.19-ca-jdk17.0.9-linux.x86_64.rpm",
	"temurin-17-jdk-17.0.13.0.0.11-2.x86_64.rpm", "bellsoft-jdk17.0.9+11-linux-amd64.rpm", "sapmachine-jdk-17.0.9-1.x86_64.rpm"}

// rpmFileArg reads a package file argument (local or a URL, with any
// ?query or #fragment): name-version-release.arch.rpm gives the package
// name and version; a pattern that could match a Java package, or a Java
// URL whose file name is not given, is returned marked unreadable. ok is
// false for an argument that is not a package file.
func rpmFileArg(w string) (string, bool) {
	u := w
	url := strings.Contains(w, "://")
	if i := strings.IndexAny(u, "?#"); url && i >= 0 {
		u = u[:i]
	}
	base := path.Base(u)
	if pre, _, pin := strings.Cut(w, "="); !url && pin && !strings.Contains(w, "/") && !strings.Contains(strings.ToLower(pre), ".rpm") && !strings.Contains(strings.ToLower(pre), ".deb") {
		return "", false // a version pin (openjdk-17-jdk=17.*), not a file
	}
	if !url && strings.ContainsAny(base, "*?[") {
		// A pattern (*.rpm, jdk*.rpm, /rpms/*, java-17-*): not checked when
		// it could match a Java package file.
		if javaWord.MatchString(base) {
			return unreadableArg + w, true
		}
		for _, c := range globCandidates {
			if ok, _ := path.Match(base, c); ok {
				return unreadableArg + w, true
			}
		}
		return "", strings.HasSuffix(strings.ToLower(base), ".rpm") || strings.Contains(w, "/")
	}
	if strings.HasSuffix(strings.ToLower(base), ".rpm") {
		return fileArg + rpmArchRE.ReplaceAllString(base[:len(base)-len(".rpm")], ""), true
	}
	if strings.HasSuffix(strings.ToLower(base), ".deb") {
		return fileArg + debFileName(base[:len(base)-len(".deb")]), true
	}
	if url && javaWord.MatchString(w) {
		return unreadableArg + w, true
	}
	return "", false
}

// debFileName turns a Debian package file's name (name_version_arch) into
// a name=version pin a reader knows; a vendor's file name
// (jdk-17.0.9_linux-x64_bin) is kept as it is.
func debFileName(raw string) string {
	if p := strings.Split(raw, "_"); len(p) == 3 {
		if c := p[0] + "=" + p[1]; aptArg.MatchString(c) || vendorArg.MatchString(c) {
			return c
		}
	}
	return raw
}

// openJ9Name is an IBM Semeru or OpenJ9 package: not HotSpot, not affected.
var openJ9Name = regexp.MustCompile(`(?i)semeru|openj9`)

// fileArg marks a package name read from a package file's name: one no
// reader knows is still a Java package if its name says so.
const fileArg = "\x00file:"

// vendorFile finds the Java version in a vendor's package name or file
// name: jdk-17.0.9_linux-x64_bin (Oracle), zulu17.46.19-ca-jdk17.0.9-linux,
// temurin-17-jdk-17.0.13.0.0.11-2, bellsoft-jdk17.0.9+11-linux-amd64,
// sapmachine-jdk-17.0.9-1.
var vendorFile = regexp.MustCompile(`(?i)(?:^|[-_])(?:jdk|jre)-?(\d{1,2}(?:\.\d{1,9}){1,5}(?:\+\d{1,9})?)(?:$|[-_])`)

// vendorFileVersion reads a vendor package's Java version, "" when it has
// none. Temurin's rpm writes six numbers, the build last
// (17.0.13.0.0.11 is 17.0.13+11).
func vendorFileVersion(name string) string {
	m := vendorFile.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	v := m[1]
	if p := strings.Split(v, "."); len(p) == 6 && !strings.Contains(v, "+") && strings.HasPrefix(strings.ToLower(name), "temurin") {
		v = strings.Join(p[:4], ".") + "+" + p[5]
	}
	return v
}

// installArgs returns the package arguments of the install commands on a
// RUN line: the words after "<tool> [flags] install|add", without flags,
// their values, paths and URLs.
func installArgs(run string, depth int) []string {
	var out []string
	for _, cmd := range jvm.SplitCommands(run) {
		words := jvm.Words(cmd)
		// A group or subshell: ( apt-get install x ), { ...; }.
		for k, w := range words {
			if t := strings.TrimLeft(w, "({"); t != "" {
				w = t
			}
			if !strings.Contains(w, "(") {
				if t := strings.TrimRight(w, ")"); t != "" {
					w = t
				}
			}
			words[k] = w
		}
		// sh -c "apt-get install ...": the text is a script of its own.
		if text, ok := shellText(words); ok && depth < 4 {
			out = append(out, installArgs(text, depth+1)...)
			continue
		}
		// The tool: not a flag's value (RUN --mount=...,target=/var/cache/apt).
		i := 0
		for i < len(words) && (strings.HasPrefix(words[i], "-") || !pkgTools[path.Base(words[i])]) {
			i++
		}
		if i == len(words) {
			continue
		}
		tool := path.Base(words[i])
		i++
		installs := false
		for i < len(words) && strings.HasPrefix(words[i], "-") {
			if tool == "rpm" && rpmInstallFlag.MatchString(words[i]) || tool == "dpkg" && dpkgInstallFlag.MatchString(words[i]) {
				installs = true
			}
			if pkgValueFlags[words[i]] {
				i++
			}
			i++
		}
		if tool == "rpm" || tool == "dpkg" {
			// rpm -ivh file.rpm, dpkg -i file.deb: the package files follow
			// the flags.
			if !installs {
				continue
			}
			i--
		} else if i >= len(words) || !pkgVerbs[words[i]] {
			continue
		}
		for j := i + 1; j < len(words); j++ {
			w := redirect.ReplaceAllString(words[j], "")
			if w == "" {
				continue
			}
			if strings.HasPrefix(w, "$") || strings.HasPrefix(w, "`") {
				// A package name this file does not give.
				out = append(out, opaqueArg+w)
				continue
			}
			if !strings.HasPrefix(w, "-") {
				if a, ok := rpmFileArg(w); ok {
					if a != "" {
						out = append(out, a)
					}
					continue
				}
			}
			switch {
			case tool == "rpm" || tool == "dpkg":
				if pkgValueFlags[w] {
					j++
				}
			case pkgValueFlags[w]:
				j++
			case strings.HasPrefix(w, "-"), strings.Contains(w, "://"), strings.HasPrefix(w, "/"), strings.HasPrefix(w, "$"):
			default:
				if a := packageName(w); a != "" {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

// redirect is a redirection written onto a word: openjdk-17-jdk>/dev/null,
// x 2>&1. (apk and zypper write version ranges with > and <, followed by
// a version, not by a path or a descriptor.)
var redirect = regexp.MustCompile(`(?:>>?|<)[/&].*$|(?:>>?|<)$`)

// shellText returns the script of a "sh -c TEXT" command (also -ec, -lc
// and the like, behind env or a path).
func shellText(words []string) (string, bool) {
	for i := 0; i < len(words) && i < 4; i++ {
		switch path.Base(words[i]) {
		case "sh", "bash", "ash", "dash", "zsh", "ksh":
			for j := i + 1; j < len(words); j++ {
				w := words[j]
				if !strings.HasPrefix(w, "-") || strings.HasPrefix(w, "--") {
					return "", false
				}
				if strings.HasSuffix(w, "c") && j+1 < len(words) {
					return words[j+1], true
				}
			}
			return "", false
		}
		if !strings.Contains(words[i], "=") && path.Base(words[i]) != "env" && path.Base(words[i]) != "exec" {
			return "", false
		}
	}
	return "", false
}

// pkgHit is one Java package an install names.
type pkgHit struct {
	name, op, ver, mgr string
	vendor             string // distribution, corretto, temurin, zulu, msopenjdk, sapmachine
	feature            int    // 0: the distribution's default (default-jre)
	varName            bool   // the name holds a variable where the release is
	latest             bool   // java-latest-openjdk: no release in the name
	unreadable         bool   // a package file whose name cannot be read
	vendorFile         bool   // a vendor package read by vendorFileVersion
}

func opOf(v string) string {
	if v != "" {
		return "="
	}
	return ""
}

func atoi(s string) int {
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}

// rpmNumbers counts the numbers of an rpm version, without its epoch and
// release: 17.0.21.0.9-1.el9 has five.
func rpmNumbers(evr string) int {
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		evr = evr[i+1:]
	}
	v, _, _ := strings.Cut(evr, "-")
	return strings.Count(v, ".") + 1
}

// microsoftLines are the Java lines Microsoft publishes with the decoder.
var microsoftLines = map[int]bool{17: true, 21: true, 25: true}

var vendorNames = map[string]string{"distribution": "the distribution", "corretto": "Amazon Corretto", "temurin": "Eclipse Temurin",
	"zulu": "Azul Zulu", "msopenjdk": "Microsoft", "sapmachine": "SapMachine"}

// preRelease reports a Debian or rpm pre-release version: 21.0.13.1~2ea-1
// sorts before 21.0.13.1 and is not the release.
func preRelease(ver string) bool { return strings.Contains(ver, "~") }

// pinnedVersion is the Java version a package pin fixes, or "" for a pin
// that matches several releases (17.*, ~17, 17).
func pinnedVersion(h pkgHit) string {
	if h.ver == "" || strings.Contains(h.ver, "$") || strings.ContainsAny(h.ver, "*?[") || strings.Contains(h.op, "~") || strings.ContainsAny(h.op, "<>") {
		return ""
	}
	up := h.ver
	if i := strings.IndexByte(up, ':'); i >= 0 {
		up = up[i+1:]
	}
	up = strings.ReplaceAll(up, "_p", "+")
	switch {
	case h.vendor == "corretto":
		// Without the rpm or deb release: 17.0.21+9-1.amzn2023.1. A
		// four-number version whose fourth is a patch number puts the build
		// in the release: 17.0.21.1-1 is 17.0.21.1 build 1.
		base, release, _ := strings.Cut(up, "-")
		up = CorrettoJava(base)
		if p := strings.Split(base, "."); len(p) == 4 && !strings.Contains(base, "+") && atoi(p[3]) <= 3 {
			if b, _, _ := strings.Cut(release, "."); b != "" && strings.Trim(b, "0123456789") == "" {
				up += "+" + b
			}
		}
	case h.mgr == "rpm":
		// Red Hat and Fedora append the build: 17.0.21.0.9 is 17.0.21+9.
		up = knowledge.RPMUpstream(h.ver)
	}
	v, ok := knowledge.Parse(up)
	if !ok || len(v.Nums) < 3 {
		return ""
	}
	return up
}

func (s *scanner) judgePackage(rel string, line int, h pkgHit) {
	if h.varName {
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown,
			Props:   map[string]string{"package": h.name, "manager": h.mgr},
			Reason:  "the Java release in the package name comes from a variable set outside this line",
			Message: fmt.Sprintf("installs %s, a package whose Java release this scan cannot read: not checked for the Java4Shell fix", refs.CleanText(h.name, 80)),
			Fix:     "Check which Java release the variable selects: 17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 and later of the same update have the fix."})
		return
	}
	if h.vendorFile {
		// Vendor numbering is not checked here: a version the release data
		// judges vulnerable is reported, anything else is not checked.
		v, _ := knowledge.Parse(h.ver)
		st, why := knowledge.Judge(v)
		props := map[string]string{"package": refs.CleanText(h.name, 120), "manager": h.mgr, "current": h.ver}
		switch st {
		case knowledge.NotAffected:
		case knowledge.Vulnerable:
			s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: why, Props: props,
				Message: fmt.Sprintf("installs %s (Java %s), without the Java4Shell fix", refs.CleanText(h.name, 120), h.ver),
				Fix:     "Install the vendor's package of a Java release with the fix (17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 and later of the same update) once it is published, then rebuild. Until then set ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in this stage."})
		default:
			s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
				Reason:  fmt.Sprintf("the package names Java %s in its vendor's own numbering, which this detector does not judge fixed: %s", h.ver, why),
				Message: fmt.Sprintf("installs %s (Java %s): not checked for the Java4Shell fix", refs.CleanText(h.name, 120), h.ver),
				Fix:     "Check the vendor's release notes for the Java4Shell fix (CVE-2026-114938)."})
		}
		return
	}
	if h.unreadable {
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown,
			Props:   map[string]string{"package": refs.CleanText(h.name, 120), "manager": h.mgr},
			Reason:  "a Java package file this scan cannot read: a pattern, a URL that does not give the file name, or a name no reader here knows",
			Message: fmt.Sprintf("installs %s, a package file whose name this scan cannot read: not checked for the Java4Shell fix", refs.CleanText(h.name, 120)),
			Fix:     "Check which Java package the file is: 17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 and later of the same update, or the distribution's backport, have the fix."})
		return
	}
	if h.latest {
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown,
			Props:   map[string]string{"package": h.name, "manager": h.mgr},
			Reason:  "java-latest-openjdk installs the newest OpenJDK the distribution (Fedora, EPEL) carries, named by no release, and those distributions' status was not checked",
			Message: fmt.Sprintf("installs %s, whose Java release this scan cannot read: not checked for the Java4Shell fix", refs.CleanText(h.name, 80)),
			Fix:     "Check the installed release: 25.0.5.1 or 27.0.1.1 and later of the same update have the fix; 26 received none."})
		return
	}
	if h.feature > 0 && h.feature < 17 {
		return // Java 8 and 11 packages are not affected
	}
	props := map[string]string{"package": h.name, "manager": h.mgr}
	who := vendorNames[h.vendor]
	if h.vendor == "msopenjdk" && h.feature > 0 && !microsoftLines[h.feature] {
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  fmt.Sprintf("Microsoft publishes no Java %d, so its status for it was not checked", h.feature),
			Message: fmt.Sprintf("installs %s, a Microsoft package of a Java line Microsoft does not ship: not checked for the Java4Shell fix", h.name),
			Fix:     "Check which Java release the package installs."})
		return
	}
	if h.feature > 0 {
		l, ok := knowledge.LineOf(h.feature)
		switch {
		case !ok:
			s.add(Finding{Rule: RuleNotChecked, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
				Reason:  fmt.Sprintf("Java %d is not in this detector's release data (%s)", h.feature, knowledge.Checked),
				Message: fmt.Sprintf("installs %s, a Java %d package this detector has no release data for", h.name, h.feature)})
			return
		case l.Fixed == nil:
			s.add(Finding{Rule: RuleLine, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: l.Note,
				Message: fmt.Sprintf("installs %s, a Java %d package: that line received no Java4Shell fix", h.name, h.feature),
				Fix:     fmt.Sprintf("Install a supported Java package with the fix instead, such as %s.", knowledge.Upgrade(h.feature)), Props: props})
			return
		}
		props["fixed_in"] = knowledge.FixedVersion(h.feature)
	}
	fx := props["fixed_in"]
	if fx == "" {
		fx = "a release with the fix"
	}
	if st, why, ok := redHatPin(h); ok {
		props["current"] = h.ver
		if st == knowledge.Vulnerable {
			s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: why,
				Message: fmt.Sprintf("pins %s to %s, without the Java4Shell fix", h.name, h.ver),
				Fix:     rpmFix(h.name),
				Props:   props})
		}
		return
	}
	if up := pinnedVersion(h); up != "" {
		props["current"] = h.ver
		v, _ := knowledge.Parse(up)
		if preRelease(h.ver) {
			v.EA = true
		}
		st, why := knowledge.Judge(v)
		if st == knowledge.Fixed && h.mgr == "rpm" && h.vendor == "distribution" && rpmNumbers(h.ver) != 5 {
			// Red Hat and Fedora write five numbers; another count
			// (openEuler's 17.0.21.2, a six-number version) may hold a
			// build where the patch release would be.
			st, why = knowledge.Unknown, fmt.Sprintf("%s does not have Red Hat's five numbers: its fourth number may be a build, not the OpenJDK patch release", h.ver)
		}
		if st == knowledge.Unknown {
			s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Reason: why, Props: props,
				Message: fmt.Sprintf("pins %s to %s, a version this detector's release data does not settle: not checked for the Java4Shell fix", h.name, h.ver),
				Fix:     fmt.Sprintf("Check that %s %s includes the fix (Java %s or later of the same update, or the distribution's backport).", h.name, h.ver, fx)})
			return
		}
		if st == knowledge.Vulnerable {
			fix := fmt.Sprintf("Pin %s to a package of Java %s or later once %s publishes it, then rebuild. Until then set ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in this stage.", h.name, fx, who)
			if h.mgr == "rpm" && h.vendor == "distribution" {
				why += "; " + knowledge.RedHatStatus()
				fix = rpmFix(h.name)
			}
			s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "error", Status: StatusVulnerable, Reason: why,
				Message: fmt.Sprintf("pins %s to %s, without the Java4Shell fix", h.name, h.ver),
				Fix:     fix, Props: props})
		}
		return
	}
	if h.ver != "" {
		props["current"] = h.ver
	}
	if h.mgr == "rpm" && h.vendor == "distribution" && strings.ContainsAny(h.ver, "*?") {
		// Red Hat's fixed build can keep the upstream version, so a pattern
		// such as 17.0.21* may match fixed and unfixed builds.
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  "the version is a pattern that can match builds with and without the fix (Red Hat's backports keep the upstream version)",
			Message: fmt.Sprintf("installs %s matching %s: not checked for the Java4Shell fix", h.name, refs.CleanText(h.ver, 60)),
			Fix:     rpmFix(h.name)})
		return
	}
	if strings.Contains(h.ver, "$") {
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  "the version comes from a variable set outside this line",
			Message: fmt.Sprintf("installs %s pinned to %s, a version this scan cannot read: not checked for the Java4Shell fix", h.name, refs.CleanText(h.ver, 60)),
			Fix:     fmt.Sprintf("Check that the version the variable gives is Java %s or later.", fx)})
		return
	}
	what := "without a version"
	if h.ver != "" {
		what = "with a version range (" + h.op + h.ver + ")"
	}
	published, rhFixed := redHatPublished(h.name)
	switch {
	case h.mgr == "rpm" && h.vendor == "distribution" && rhFixed:
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  fmt.Sprintf("Red Hat published fixed builds (%s): an image built after that gets one, one built or cached before does not", published),
			Message: fmt.Sprintf("installs %s %s: whether the image has the Java4Shell fix depends on when it was built", h.name, what),
			Fix:     fmt.Sprintf("Rebuild without the layer cache and check that %s is Red Hat's fixed build or later.", h.name)})
		return
	}
	switch h.vendor {
	case "corretto", "sapmachine":
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  fmt.Sprintf("%s published Java %s on %s: an image built after that gets it, one built or cached before does not", who, fx, knowledge.VendorFixPublished),
			Message: fmt.Sprintf("installs %s %s: whether the image has the Java4Shell fix depends on when it was built", h.name, what),
			Fix:     fmt.Sprintf("Rebuild without the layer cache, or pin %s to Java %s or later.", h.name, fx)})
	case "zulu":
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "note", Status: StatusUnknown, Props: props,
			Reason:  fmt.Sprintf("%s's fixed release could not be checked (%s)", who, knowledge.Checked),
			Message: fmt.Sprintf("installs %s %s: not checked for the Java4Shell fix", h.name, what),
			Fix:     fmt.Sprintf("Check that %s's package is Java %s or later, then rebuild.", who, fx)})
	default:
		reason := fmt.Sprintf("Debian, Ubuntu and Alpine had published no %s package with the fix as of %s, so a build today installs a release without it", fx, knowledge.Checked)
		fix := fmt.Sprintf("Rebuild once %s publishes Java %s or later and check the installed version; until then set ENV JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics in this stage.", who, fx)
		if h.mgr == "rpm" && h.vendor == "distribution" {
			reason = fmt.Sprintf("%s, and Debian, Ubuntu and Alpine no %s package with the fix (other rpm distributions such as Fedora and SUSE were not checked), so a build today installs a release without it", knowledge.RedHatStatus(), fx)
			fix = rpmFix(h.name)
		}
		msg := fmt.Sprintf("installs %s %s: it gets whatever the distribution has, which had no Java4Shell fix yet", h.name, what)
		if h.vendor == "temurin" || h.vendor == "msopenjdk" {
			reason = fmt.Sprintf("%s had published no %s release as of %s, so a build today installs a release without it", who, fx, knowledge.Checked)
			msg = fmt.Sprintf("installs %s %s: %s had no Java4Shell fix yet", h.name, what, who)
		}
		if h.feature == 0 {
			msg = fmt.Sprintf("installs %s, the distribution's default OpenJDK (17 or later on current Debian and Ubuntu releases), which had no Java4Shell fix yet", h.name)
		}
		s.add(Finding{Rule: RulePackage, File: rel, Line: line, Level: "warning", Status: StatusVulnerable, Reason: reason, Message: msg, Props: props, Fix: fix})
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

// commandWords reads a Dockerfile ENTRYPOINT or CMD: the JSON form or the
// shell form.
func commandWords(text string) []string {
	text = strings.TrimSpace(text)
	var arr []string
	if strings.HasPrefix(text, "[") && json.Unmarshal([]byte(text), &arr) == nil {
		return jvm.CommandWords(arr)
	}
	return jvm.Words(text)
}

// withoutJavaOptions drops _JAVA_OPTIONS, which undo applies last.
func withoutJavaOptions(env map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range env {
		if k != "_JAVA_OPTIONS" {
			out[k] = v
		}
	}
	return out
}

// undo applies what a command can turn back on (its words count wherever
// the java it starts is) and then _JAVA_OPTIONS, which HotSpot applies
// last. A java @argfile makes the result unknowable: no mitigation.
func undo(o jvm.Options, cmd []string, env map[string]string) jvm.Options {
	b64, avx, argfile := jvm.Undoes(cmd)
	if argfile {
		return jvm.Options{}
	}
	if b64 {
		o.ApplyWord("-XX:+UseBASE64Intrinsics", "the command")
	}
	if avx {
		o.ApplyWord("-XX:UseAVX=3", "the command")
	}
	if v, ok := env["_JAVA_OPTIONS"]; ok {
		o.Apply(v, "_JAVA_OPTIONS")
	}
	return o
}
