// Package java4shell is the detector for Java4Shell (CVE-2026-114938): an
// out-of-bounds write in HotSpot's AVX-512 VBMI Base64 decoder on x86-64
// (JDK-8393212), fixed in OpenJDK 17.0.21.1, 21.0.13.1, 25.0.5.1 and
// 27.0.1.1 on 2026-11-15. The decoder came with JDK 18 and 17.0.6; Java 8,
// 11 and 17.0.0 to 17.0.5 do not have it.
//
// It finds Java runtimes in filesystems and container images by their VM
// library (libjvm.so, jvm.dll, libjvm.dylib) and judges each by what the
// library proves: its CPU architecture, the version compiled into it and
// whether it carries the AVX-512 VBMI decode stubs, with the release file as
// a second witness. JVM options that keep the decoder from being generated
// (-XX:-UseBASE64Intrinsics, -XX:UseAVX=2 or lower) are reported as a
// mitigation, never as a fix. In a source tree it finds the Java images,
// versions and packages a project pins, and fix moves them to fixed
// releases.
//
// internal/knowledge, internal/jvm, internal/assess and internal/repo know
// nothing about the engine; this file adapts them.
package java4shell

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/archive"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// ID is the detector's ID.
const ID = "java4shell"

// Kind IDs.
const (
	KindRuntime = assess.KindRuntime
	KindBundled = assess.KindBundled
)

// Detector implements engine.Detector, engine.Reader, engine.RepoScanner and
// engine.Fixer.
type Detector struct{}

func init() { engine.Register(&Detector{}) }

const about = " HotSpot's AVX-512 VBMI Base64 decoder (x86-64, JDK 18 and later, 17.0.6 and later, and Oracle's Java 8" +
	" Performance Pack) writes up to 64 bytes past its output when the input ends in a padded fragment shorter than four" +
	" characters (64 'A' then '=' is enough), so a Java program that decodes untrusted Base64 (tokens, headers," +
	" certificates, JSON) can have its heap corrupted once the decoder is compiled: pre-authentication remote code" +
	" execution was shown on default Keycloak, Jira, Confluence, Artifactory, Jenkins and PingFederate. It runs on CPUs" +
	" with AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2 (Intel Ice Lake and later, AMD Zen 4 and later, common on cloud" +
	" instances). Fixed in OpenJDK 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 (JDK-8393212); Java 18 to 20, 22 to 24" +
	" and 26 received no fix. -XX:-UseBASE64Intrinsics (or, on x86-64 only, -XX:UseAVX=2) keeps the decoder from being" +
	" generated until the runtime is updated."

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	cwe := []string{"CWE-787"}
	return engine.Manifest{
		ID:    ID,
		Title: "Java4Shell: HotSpot AVX-512 Base64 decoder out-of-bounds write (" + knowledge.CVE + ")",
		CVEs:  []string{knowledge.CVE},
		Advisories: []string{
			"https://calif.io/java4shell/",
			"https://openjdk.org/groups/vulnerability/advisories/2026-11-17",
			"https://www.oracle.com/security-alerts/cspunov2026.html",
			"https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b",
			"https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability",
			"https://github.com/corretto/corretto-21/blob/21.0.13.1.2/CHANGELOG.md",
		},
		Disclosed: "2026-11-17",
		Targets:   []engine.TargetKind{engine.Filesystem, engine.Image, engine.Repository},
		Kinds: append([]engine.Kind{
			{ID: KindRuntime, Title: "Java runtime vulnerable to Java4Shell", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
				Description: "A HotSpot Java runtime for x86-64 with the AVX-512 VBMI Base64 decoder and without the fix: an installed JDK or JRE, a packaged OpenJDK, a jlink image or a runtime in a container image." + about},
			{ID: KindBundled, Title: "Java runtime bundled in a product is vulnerable to Java4Shell", Level: "error", SecuritySeverity: "9.2", CWEs: cwe,
				Description: "A Java runtime that a product ships inside its own install directory (Atlassian Jira and Confluence, Elasticsearch, Artifactory, JetBrains IDEs and others) without the fix. Updating the operating system's Java does not fix it: upgrade the product." + about},
		}, repoKinds()...),
		Tags: []string{"security", "java", "openjdk", "hotspot", "Java4Shell"},
		Data: "OpenJDK fixed releases (17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1), the releases that introduced the decoder, and vendor and distribution status, checked " + knowledge.Checked,
	}
}

// Load checks the release data.
func (d *Detector) Load() error {
	prev := 0
	for _, l := range knowledge.Lines {
		if l.Feature <= prev || l.Fixed == nil && l.Note == "" || l.Fixed != nil && l.Fixed[0] != l.Feature {
			return fmt.Errorf("release data for Java %d contradicts itself", l.Feature)
		}
		prev = l.Feature
	}
	return nil
}

// Wants reads VM libraries, release files, the files that set JVM options,
// package databases, crash logs and startup scripts.
func (d *Detector) Wants(p string, head []byte, _ bool) bool {
	base := path.Base(p)
	switch {
	case jvm.IsLibraryName(base):
		return archive.IsExecutable(head)
	case base == "release", keep(p), jvm.SettingKind(p) != "", hsErr.MatchString(base):
		return true
	}
	return isScript(head)
}

var hsErr = regexp.MustCompile(`^hs_err_pid\d{1,10}\.log$`)

func isScript(head []byte) bool { return len(head) > 2 && head[0] == '#' && head[1] == '!' }

// keep reports the package databases owners are read from.
func keep(p string) bool {
	switch p {
	case "/lib/apk/db/installed", "/usr/lib/apk/db/installed", "/var/lib/dpkg/status":
		return true
	}
	return assess.IsDpkgList(p)
}

// Limits on what one target keeps.
const (
	maxKept    = 16 << 20 // a package database
	maxScript  = 256 << 10
	maxHsErr   = 4 << 20
	maxHsErrs  = 64
	maxLibs    = 4096
	maxSetting = 1 << 20
)

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(kind engine.TargetKind) engine.Scan {
	return &scan{kind: kind, releases: map[string]jvm.Release{}, badReleases: map[string]string{},
		kept: map[string][]byte{}, lists: map[string][]byte{}, scripts: map[string]map[string]bool{}}
}

type scan struct {
	kind        engine.TargetKind
	libs        []*jvm.Library
	releases    map[string]jvm.Release
	badReleases map[string]string
	settings    []jvm.Setting
	kept        map[string][]byte
	lists       map[string][]byte
	scripts     map[string]map[string]bool
	crashes     []crash
	dropped     int
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if f.Member {
		return nil // installed runtimes only, not copies inside archives
	}
	base := path.Base(f.Path)
	switch {
	case jvm.IsLibraryName(base):
		if l, ok := jvm.Inspect(f.Path, f.Data); ok {
			if len(s.libs) >= maxLibs {
				s.dropped++
				return []engine.Skip{{Path: f.Path, Reason: fmt.Sprintf("more than %d Java VM libraries in one target; not checked", maxLibs)}}
			}
			s.libs = append(s.libs, l)
		}
		return nil
	case base == "release":
		if !archive.IsExecutable(f.Data) {
			if r, ok := jvm.ParseRelease(f.Data); ok {
				s.releases[path.Dir(f.Path)] = r
			} else if len(f.Data) > 64<<10 && bytes.Contains(f.Data[:min(len(f.Data), 4096)], []byte("JAVA_VERSION")) {
				s.badReleases[path.Dir(f.Path)] = "its release file is larger than 64 KiB and was not read"
			}
		}
		return nil
	case hsErr.MatchString(base):
		if len(s.crashes) < maxHsErrs && len(f.Data) <= maxHsErr {
			s.crashes = append(s.crashes, readCrash(f.Path, f.Data))
		}
		return nil
	}
	if k := jvm.SettingKind(f.Path); k != "" && len(f.Data) <= maxSetting {
		if st, ok := jvm.ReadSetting(f.Path, f.Data); ok {
			s.settings = append(s.settings, st)
		}
	}
	if keep(f.Path) && len(f.Data) <= maxKept {
		if assess.IsDpkgList(f.Path) {
			s.lists[strings.TrimSuffix(path.Base(f.Path), ".list")] = f.Data
		} else {
			s.kept[f.Path] = f.Data
		}
	}
	if isScript(f.Data) && len(f.Data) <= maxScript {
		vars := map[string]bool{}
		for _, n := range jvm.ScriptVars {
			if bytes.Contains(f.Data, []byte("$"+n)) || bytes.Contains(f.Data, []byte("${"+n)) {
				vars[n] = true
			}
		}
		if len(vars) > 0 {
			s.scripts[f.Path] = vars
		}
	}
	return nil
}

func (s *scan) Finish(ctx engine.TargetContext) []engine.Finding {
	if s.kind == engine.Filesystem {
		if c, ok := thisCPU(); ok {
			ctx.Annotate("java4shell_scanner_cpu", c)
		}
	}
	if len(s.crashes) > 0 {
		ctx.Annotate("java4shell_crash_logs", s.crashes)
	}
	if len(s.libs) == 0 {
		return nil
	}
	links, _ := ctx.Links()
	res := resolver{links: links}
	owners := map[string]assess.Package{}
	for _, db := range []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"} {
		if b := s.kept[db]; b != nil {
			for k, v := range assess.APKOwners(b) {
				owners[k] = v
			}
		}
	}
	if st := s.kept["/var/lib/dpkg/status"]; st != nil {
		for k, v := range assess.DpkgOwners(st, s.lists) {
			owners[k] = v
		}
	}
	in := assess.Input{
		Libraries:   s.libs,
		Releases:    s.releases,
		BadReleases: s.badReleases,
		Settings:    s.settings,
		Owners:      owners,
		Resolve:     res.resolve,
		Scripts:     s.scripts,
	}
	if s.kind == engine.Image {
		in.Env = ctx.Env()
		if in.Env == nil {
			in.Env = []string{}
		}
		in.Command = ctx.Command()
	}
	cpu, haveCPU := thisCPU()
	var out []engine.Finding
	for _, x := range assess.Run(in) {
		f := finding(x)
		if haveCPU && s.kind == engine.Filesystem && x.Status == assess.Vulnerable {
			f.Facts["scanner_cpu_runs_it"] = yes(cpu.Affected)
		}
		out = append(out, f)
	}
	return out
}

var verdicts = map[assess.Status]engine.Verdict{
	assess.Vulnerable:  engine.Vulnerable,
	assess.Fixed:       engine.Fixed,
	assess.NotAffected: engine.Fixed,
	assess.Mitigated:   engine.Inactive,
	assess.Unknown:     engine.Unknown,
}

func finding(x assess.Finding) engine.Finding {
	v, ok := verdicts[x.Status]
	if !ok {
		v = engine.Unknown
	}
	facts := map[string]string{"status": string(x.Status), "arch": string(x.Arch)}
	if x.Version != "" {
		facts["version"], facts["version_from"] = x.Version, x.VersionFrom
	}
	if x.ReleaseVersion != "" {
		facts["release_file_version"] = x.ReleaseVersion
	}
	if x.VM != "" {
		facts["vm"] = x.VM
	}
	if x.Vendor != "" {
		facts["vendor"] = x.Vendor
	}
	if x.Library != nil {
		facts["vm_library"] = x.Library.Path
		facts["vbmi_decoder"] = yes(x.Library.VBMIStubs)
	}
	if x.Product != "" {
		facts["product"] = x.Product
	}
	if x.Package != nil {
		facts["package"] = strings.TrimSpace(x.Package.Name + " " + x.Package.Version)
	}
	if x.JLinked {
		facts["jlink"] = "yes"
	}
	if x.Mitigation != "" {
		facts["mitigation"] = x.Mitigation
	}
	if len(x.MitigatedFor) > 0 {
		sort.Strings(x.MitigatedFor)
		facts["mitigated_only_for"] = strings.Join(x.MitigatedFor, ",")
	}
	if fx := fixedFor(x.Version); fx != "" {
		facts["fixed_in"] = fx
	}
	method := "vm-library"
	if x.VersionFrom == "release-file" {
		method = "release-file"
	}
	return engine.Finding{
		Kind:    x.Kind,
		Path:    x.Path,
		Verdict: v,
		Reason:  x.Reason,
		Message: x.Message,
		Method:  method,
		Facts:   facts,
		CVEs:    []engine.CVEResult{{ID: knowledge.CVE, Verdict: v, Reason: x.Reason}},
		Fix:     x.Fix,
		Details: x,
	}
}

func fixedFor(version string) string {
	v, ok := knowledge.Parse(version)
	if !ok {
		return ""
	}
	return knowledge.FixedVersion(v.Feature())
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// resolver follows symbolic links the way the kernel would, component by
// component, within the target.
type resolver struct{ links map[string]string }

func (r resolver) resolve(p string) string {
	cur := path.Clean("/" + p)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(cur, "/"), "/")
		changed := false
		prefix := "/"
		for i, part := range parts {
			next := path.Join(prefix, part)
			if to, ok := r.links[next]; ok {
				if !strings.HasPrefix(to, "/") {
					to = path.Join(prefix, to)
				}
				cur = path.Clean(path.Join(append([]string{to}, parts[i+1:]...)...))
				changed = true
				break
			}
			prefix = next
		}
		if !changed {
			return cur
		}
	}
	return cur // a loop: as far as it got
}
