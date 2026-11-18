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
// mitigation on a finding that stays vulnerable. In a source tree it finds the Java images,
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
	" with AVX-512F, AVX-512BW, AVX-512 VBMI and BMI2 (Intel server CPUs from Ice Lake on and some client CPUs, not Alder" +
	" Lake or Raptor Lake; AMD Zen 4 and later; common on cloud instances). Fixed in OpenJDK 17.0.21.1, 21.0.13.1, 25.0.5.1" +
	" and 27.0.1.1 (by JDK-8393212, the change the public descriptions of the CVE match); Java 18 to 20, 22 to 24" +
	" and 26 received no fix. Oracle GraalVM for JDK 17 and 21 and GraalVM Enterprise Edition 21.3 are affected too, with no" +
	" fixed GraalVM build known yet. -XX:-UseBASE64Intrinsics (or, on x86-64 only, -XX:UseAVX=2) keeps the decoder from being" +
	" generated until the runtime is updated."

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	cwe := []string{"CWE-787"}
	return engine.Manifest{
		ID:    ID,
		Title: "Java4Shell: HotSpot AVX-512 Base64 decoder out-of-bounds write (" + knowledge.CVE + ")",
		CVEs:  []string{knowledge.CVE},
		Advisories: []string{
			knowledge.OpenJDKAdvisory,
			knowledge.OracleAdvisory,
			"https://calif.io/java4shell/",
			"https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b",
			"https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability",
			"https://github.com/corretto/corretto-21/blob/21.0.13.1.2/CHANGELOG.md",
		},
		Disclosed: knowledge.Disclosed,
		Targets:   []engine.TargetKind{engine.Filesystem, engine.Image, engine.Repository},
		Kinds: append([]engine.Kind{
			{ID: KindRuntime, Title: "Java runtime vulnerable to Java4Shell", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: cwe,
				Description: "A HotSpot Java runtime for x86-64 with the AVX-512 VBMI Base64 decoder and without the fix: an installed JDK or JRE, a packaged OpenJDK, a jlink image or a runtime in a container image." + about},
			{ID: KindBundled, Title: "Java runtime bundled in a product is vulnerable to Java4Shell", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: cwe,
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
		if l.Feature <= prev || l.Fixed == nil && l.Note == "" || l.Fixed != nil && (l.Fixed[0] != l.Feature || l.FixedBuild < 1) {
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

// Limit is the size Visit keeps a file to, so the engine never reads a
// larger one: an os-release, a package database, a start script, a
// settings file or a crash log is never hundreds of MiB. VM libraries are
// read whole, and a release file's size is itself a fact (badReleases).
func (d *Detector) Limit(p string, head []byte, _ bool) int64 {
	base := path.Base(p)
	switch {
	case jvm.IsLibraryName(base), base == "release":
		return 0
	case hsErr.MatchString(base):
		return maxHsErr
	}
	var most int64
	if jvm.SettingKind(p) != "" {
		most = maxSetting
	}
	if keep(p) {
		most = max(most, keptLimit(p))
	}
	if isScript(head) {
		most = max(most, maxScript)
	}
	return most
}

// VisitOverLimit records a file the scan asked for and did not get, over
// its limit or --max-file-size. A JVM settings file not read is a coverage
// gap once a runtime is found (FinishSkips): an option in it can undo a
// mitigation the scan would report. A start script not read keeps a
// mitigation from being reported when the container's command runs it. An
// /etc/os-release not read keeps a Red Hat row from clearing a runtime
// (osID). The other files with a limit are deliberate exclusions: no
// verdict is cleared on them.
func (s *scan) VisitOverLimit(p string, _ int64) []engine.Skip {
	s.notRead(p)
	return nil
}

// VisitUnread records a file or directory the walk could not read, as
// VisitOverLimit does.
func (s *scan) VisitUnread(p string, dir bool) {
	if !dir {
		s.notRead(p)
	} else if len(s.unreadDirs) < maxScripts {
		s.unreadDirs = append(s.unreadDirs, p)
	} else {
		s.unreadAll = true
	}
}

func (s *scan) notRead(p string) {
	if jvm.SettingKind(p) != "" && len(s.overSettings) < maxSettings {
		s.overSettings[p] = true
	}
	if p == "/etc/os-release" {
		s.osUnread = true
	}
	if hsErr.MatchString(path.Base(p)) || p == "/etc/os-release" || p == "/usr/lib/os-release" {
		return
	}
	if len(s.unreadScripts) >= maxScripts {
		s.unreadAll = true
		return
	}
	// Its head is not known here: it may be a start script, which keeps a
	// mitigation from being reported for the command it runs.
	s.unreadScripts[p] = true
}

// FinishSkips reports the JVM settings files not read as coverage gaps
// when the target holds a runtime.
func (s *scan) FinishSkips() []engine.Skip {
	if s.libs.len() == 0 {
		return nil
	}
	var out []engine.Skip
	for p := range s.overSettings {
		out = append(out, engine.Skip{Path: p, Reason: "a JVM settings file not read (over a size limit, or unreadable); its options are not checked"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Forget drops what was kept of p: an image names it again.
func (s *scan) Forget(p string) {
	if b, ok := s.kept[p]; ok {
		s.keptBytes -= len(b)
		delete(s.kept, p)
	}
	if assess.IsDpkgList(p) {
		k := strings.TrimSuffix(path.Base(p), ".list")
		s.keptBytes -= len(s.lists[k])
		delete(s.lists, k)
	}
	if p == "/etc/os-release" {
		s.osUnread = false
	}
	delete(s.scripts, p)
	delete(s.unreadScripts, p)
	delete(s.overSettings, p)
	if path.Base(p) == "release" {
		delete(s.releases, path.Dir(p))
		delete(s.badReleases, path.Dir(p))
	}
	s.libs.drop(p)
	for _, st := range s.settings.drop(p) {
		// Give back what it counted toward the caps.
		if st.SetsOptions() {
			s.optionFiles--
		} else {
			s.plainUnits--
		}
	}
	s.crashes.drop(p)
	s.archives.drop(p)
}

var hsErr = regexp.MustCompile(`^hs_err_pid\d{1,10}\.log$`)

// jdkArchive names a Java runtime download as vendors publish it:
// OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz (Temurin),
// amazon-corretto-21-x64-linux-jdk.tar.gz, zulu21.42.19-ca-jdk21.0.13-linux_x64.tar.gz,
// jdk-21_linux-x64_bin.tar.gz (Oracle), bellsoft-jre21.0.13+11-linux-amd64.tar.gz,
// sapmachine-jre-21.0.13.1_linux-x64_bin.tar.gz, microsoft-jdk-21.0.13-linux-x64.tar.gz,
// ibm-semeru-open-jre_x64_linux_21.0.13_11_openj9-0.53.0.tar.gz, openjdk-21.0.2_linux-x64_bin.tar.gz.
var jdkArchive = regexp.MustCompile(`(?i)^(?:OpenJDK\d{1,2}U-(?:jdk|jre)_|amazon-corretto-\d{1,2}[.\w-]*-(?:jdk|jre)|zulu\d[\w.]*-ca-(?:jdk|jre|fx-jdk|fx-jre)\d|jdk-\d{1,2}[\w.]*_(?:linux|windows|macos|osx)-|bellsoft-(?:jdk|jre)\d|sapmachine-(?:jdk|jre)-\d|microsoft-jdk-\d|ibm-semeru-open-(?:jdk|jre)_|openjdk-\d{1,2}[\w.]*_(?:linux|windows|macos|osx)-|graalvm-(?:community-)?jdk-\d)[^/]*\.(?:tar\.gz|tgz|zip|tar\.xz|tar)$`)

// maxArchivesNoted bounds the runtime downloads recorded per target.
const maxArchivesNoted = 256

// VisitHead records runtime downloads by name and first bytes, without
// reading them: the detector does not unpack archives, and a runtime that
// is not installed is context, not a file left unscanned.
func (s *scan) VisitHead(p string, head []byte) {
	if s.archives.len() < maxArchivesNoted && jdkArchive.MatchString(path.Base(p)) && archive.IsArchive(head) {
		s.archives.add(p, p)
	}
}

func isScript(head []byte) bool { return len(head) > 2 && head[0] == '#' && head[1] == '!' }

// keep reports the package databases owners are read from.
func keep(p string) bool {
	switch p {
	case "/lib/apk/db/installed", "/usr/lib/apk/db/installed", "/var/lib/dpkg/status", "/etc/os-release", "/usr/lib/os-release":
		return true
	}
	return assess.IsDpkgList(p)
}

// keptLimit is the largest package database or os-release kept.
func keptLimit(p string) int64 {
	if p == "/etc/os-release" || p == "/usr/lib/os-release" {
		return maxOSRelease
	}
	return maxKept
}

// Limits on what one target keeps.
const (
	maxKept      = 16 << 20 // a package database
	maxOSRelease = 64 << 10
	maxScript    = 256 << 10
	maxHsErr     = 4 << 20
	maxHsErrs    = 64
	maxLibs      = 4096
	maxSetting   = 1 << 20
	// Caps on what one target can make the detector keep: an image layer
	// of many small files compresses to almost nothing.
	maxReleases = 4096
	maxSettings = 4096
	// Plain systemd units are small records; a host has thousands.
	maxPlainUnits = 1 << 16
	maxLists      = 512
	maxScripts    = 8192
	maxKeptTotal  = 128 << 20
)

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(kind engine.TargetKind) engine.Scan {
	return &scan{kind: kind, releases: map[string]jvm.Release{}, badReleases: map[string]string{},
		kept: map[string][]byte{}, lists: map[string][]byte{}, scripts: map[string]map[string]bool{}, unreadScripts: map[string]bool{}, overSettings: map[string]bool{}}
}

type scan struct {
	kind        engine.TargetKind
	libs        pathList[*jvm.Library]
	releases    map[string]jvm.Release
	badReleases map[string]string
	settings    pathList[jvm.Setting]
	kept        map[string][]byte
	lists       map[string][]byte
	scripts     map[string]map[string]bool
	crashes     pathList[crash]
	dropped     int
	keptBytes   int
	archives    pathList[string] // runtime downloads seen by name, not read
	// unreadScripts may be start scripts and were not read; unreadDirs
	// could not be listed; unreadAll stands for more than were recorded.
	unreadScripts map[string]bool
	unreadDirs    []string
	unreadAll     bool
	// overSettings are JVM settings files not read.
	overSettings map[string]bool
	// osUnread is set when /etc/os-release was met and not read.
	osUnread    bool
	optionFiles int // settings files that set JVM options
	plainUnits  int // systemd units that set none
	// limits records the caps this target reached; a capped scan clears
	// nothing.
	limits []string
}

func (s *scan) limit(what string) {
	for _, l := range s.limits {
		if l == what {
			return
		}
	}
	s.limits = append(s.limits, what)
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if f.Member {
		return nil // installed runtimes only, not copies inside archives
	}
	base := path.Base(f.Path)
	switch {
	case jvm.IsLibraryName(base):
		if l, ok := jvm.Inspect(f.Path, f.Data); ok {
			if s.libs.len() >= maxLibs {
				s.dropped++
				return []engine.Skip{{Path: f.Path, Reason: fmt.Sprintf("more than %d Java VM libraries in one target; not checked", maxLibs)}}
			}
			s.libs.add(f.Path, l)
		}
		return nil
	case base == "release":
		if !archive.IsExecutable(f.Data) {
			if len(s.releases)+len(s.badReleases) >= maxReleases {
				s.limit(fmt.Sprintf("more than %d release files", maxReleases))
				return nil
			}
			if r, ok := jvm.ParseRelease(f.Data); ok {
				s.releases[path.Dir(f.Path)] = r
			} else if len(f.Data) > 64<<10 && bytes.Contains(f.Data[:min(len(f.Data), 4096)], []byte("JAVA_VERSION")) {
				s.badReleases[path.Dir(f.Path)] = "its release file is larger than 64 KiB and was not read"
			}
		}
		return nil
	case hsErr.MatchString(base):
		if s.crashes.len() < maxHsErrs && len(f.Data) <= maxHsErr {
			s.crashes.add(f.Path, readCrash(f.Path, f.Data))
		}
		return nil
	}
	if k := jvm.SettingKind(f.Path); k != "" && len(f.Data) <= maxSetting {
		// Only files that set a JVM option (or, for systemd, a JVM
		// option variable) are kept and counted: a host has thousands of
		// plain units.
		if st, ok := jvm.ReadSetting(f.Path, f.Data); ok {
			switch {
			case st.SetsOptions() && s.optionFiles >= maxSettings:
				s.limit(fmt.Sprintf("more than %d files that set JVM options", maxSettings))
			case st.SetsOptions():
				s.settings.add(f.Path, st)
				s.optionFiles++
			case st.Kind == "systemd" && s.plainUnits >= maxPlainUnits:
				s.limit(fmt.Sprintf("more than %d systemd units", maxPlainUnits))
			case st.Kind == "systemd":
				// A unit without JVM options still replaces or extends
				// another file of the same unit: keep it, uncounted.
				s.settings.add(f.Path, st)
				s.plainUnits++
			}
		}
	}
	if keep(f.Path) && int64(len(f.Data)) <= keptLimit(f.Path) {
		if assess.IsDpkgList(f.Path) {
			// Only the lines owners are looked up by, without splitting
			// the whole list.
			var b []byte
			for rest := f.Data; len(rest) > 0; {
				l := rest
				if i := bytes.IndexByte(rest, '\n'); i >= 0 {
					l, rest = rest[:i], rest[i+1:]
				} else {
					rest = nil
				}
				if bytes.HasSuffix(l, []byte("/libjvm.so")) || bytes.HasSuffix(l, []byte("/release")) {
					b = append(append(b, l...), '\n')
				}
			}
			switch {
			case len(s.lists) >= maxLists:
				s.limit(fmt.Sprintf("more than %d dpkg file lists of Java packages", maxLists))
			case s.keptBytes+len(b) > maxKeptTotal:
				s.limit(fmt.Sprintf("more than %d MiB of package data", maxKeptTotal>>20))
			default:
				s.lists[strings.TrimSuffix(path.Base(f.Path), ".list")] = b
				s.keptBytes += len(b)
			}
		} else if s.keptBytes+len(f.Data) > maxKeptTotal {
			s.limit(fmt.Sprintf("more than %d MiB of package data", maxKeptTotal>>20))
		} else {
			s.kept[f.Path] = f.Data
			s.keptBytes += len(f.Data)
		}
	}
	if isScript(f.Data) && len(f.Data) > maxScript {
		// Read as a settings file or package database only.
		if len(s.unreadScripts) < maxScripts {
			s.unreadScripts[f.Path] = true
		} else {
			s.unreadAll = true
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
			if len(s.scripts) >= maxScripts {
				s.limit(fmt.Sprintf("more than %d start scripts that pass JVM options", maxScripts))
			} else {
				s.scripts[f.Path] = vars
			}
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
	if s.crashes.len() > 0 {
		ctx.Annotate("java4shell_crash_logs", s.crashes.list())
	}
	if s.archives.len() > 0 {
		ctx.Annotate("java4shell_runtime_archives", s.archives.list())
	}
	if osr := osRelease(s.kept["/etc/os-release"], s.kept["/usr/lib/os-release"]); osr != "" {
		ctx.Annotate("java4shell_os", osr)
	}
	if s.libs.len() == 0 {
		if len(s.limits) > 0 {
			ctx.Problem("java4shell: the scan reached its limit on " + strings.Join(s.limits, " and ") + " for one target")
		}
		return nil
	}
	links, hardlinks := ctx.Links()
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
		Libraries:     s.libs.list(),
		Releases:      s.releases,
		BadReleases:   s.badReleases,
		Settings:      s.settings.list(),
		Owners:        owners,
		Resolve:       res.resolve,
		Scripts:       s.scripts,
		UnreadScripts: s.unreadScripts,
		UnreadDirs:    s.unreadDirs,
		UnreadAll:     s.unreadAll,
	}
	in.OSID = s.osID(ctx.Exists, res, hardlinks)
	if s.kind == engine.Image {
		in.Env = ctx.Env()
		if in.Env == nil {
			in.Env = []string{}
		}
		in.Command = ctx.Command()
	}
	cpu, haveCPU := thisCPU()
	capped := ""
	if len(s.limits) > 0 {
		capped = "the scan reached its limit on " + strings.Join(s.limits, " and ") + " for one target, so package owners and JVM options may be missing: nothing is cleared"
		ctx.Problem("java4shell: " + capped)
	}
	var out []engine.Finding
	for _, x := range assess.Run(in) {
		f := finding(x)
		if capped != "" && f.Verdict.Cleared() {
			f.Verdict, f.Reason = engine.Unknown, f.Reason+"; but "+capped
			f.CVEs = []engine.CVEResult{{ID: knowledge.CVE, Verdict: f.Verdict, Reason: f.Reason}}
		}
		if haveCPU && s.kind == engine.Filesystem && x.Status == assess.Vulnerable {
			f.Facts["scanner_cpu_runs_it"] = yes(cpu.Affected)
		}
		out = append(out, f)
	}
	return out
}

// osID is the target's os-release ID for a verdict (a Red Hat row clears
// a runtime only on RHEL), "" when it is not known. The system reads
// /usr/lib/os-release only when /etc/os-release does not exist, so
// /usr/lib/os-release speaks for the target only when no file is at
// /etc/os-release, or a link there leads to it. A file at /etc/os-release
// is the system's, with an ID or without. One the scan met and did not
// read (over its limit, unreadable), one a directory the scan could not
// list may hold, and a link to any other file (which is not kept) leave
// the ID unknown: a verdict is never cleared on a file that stands in for
// one not read. The java4shell_os annotation, which clears nothing, still
// falls back.
func (s *scan) osID(exists func(string) bool, res resolver, hardlinks map[string]string) string {
	const etc, usr = "/etc/os-release", "/usr/lib/os-release"
	if s.osUnread || s.unreadAll {
		return ""
	}
	file := usr
	switch to, hard := hardlinks[etc]; {
	case exists(etc):
		file = etc
	case hard:
		if to != usr {
			return ""
		}
	default:
		for _, d := range s.unreadDirs {
			if d = strings.TrimSuffix(d, "/"); d == "" || d == "/etc" {
				return ""
			}
		}
		if at := res.resolve(etc); at != etc && at != usr {
			return ""
		}
	}
	id, _, _ := strings.Cut(osRelease(s.kept[file]), " ")
	return id
}

var verdicts = map[assess.Status]engine.Verdict{
	assess.Vulnerable:  engine.Vulnerable,
	assess.Fixed:       engine.Fixed,
	assess.NotAffected: engine.Fixed,
	// Mitigated is not cleared: the options can be overridden where the
	// runtime is deployed, and the runtime still needs the update.
	assess.Mitigated: engine.Vulnerable,
	assess.Unknown:   engine.Unknown,
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
	if x.GraalVM {
		// GraalVM's fixed builds are numbered its own way: none was known.
		facts["graalvm"] = "yes"
	} else if fx := fixedFor(x.Version); fx != "" {
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

// osRelease is "ID VERSION_ID" from os-release, for comparing the base OS
// of two images.
func osRelease(files ...[]byte) string {
	for _, b := range files {
		if len(b) == 0 || len(b) > maxOSRelease {
			continue
		}
		var id, ver string
		for _, l := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
			if !ok {
				continue
			}
			v = osToken(strings.Trim(v, "\"'"))
			switch k {
			case "ID":
				id = v
			case "VERSION_ID":
				ver = v
			}
		}
		if id != "" {
			return strings.TrimSpace(id + " " + ver)
		}
	}
	return ""
}

// osToken keeps an os-release value short and plain: an image's files
// are not trusted.
func osToken(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		if b.Len() >= 32 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// osProbe reads only an image's os-release: a light second read of the
// image a move starts from.
type osProbe struct{}

func (osProbe) Manifest() engine.Manifest {
	return engine.Manifest{ID: "java4shell-osprobe", Targets: []engine.TargetKind{engine.Image}}
}
func (osProbe) Load() error { return nil }
func (osProbe) Wants(p string, _ []byte, _ bool) bool {
	return p == "/etc/os-release" || p == "/usr/lib/os-release"
}
func (osProbe) Limit(string, []byte, bool) int64      { return maxOSRelease }
func (osProbe) NewScan(engine.TargetKind) engine.Scan { return &osScan{files: map[string][]byte{}} }

type osScan struct{ files map[string][]byte }

func (s *osScan) Visit(f engine.File) []engine.Skip {
	if len(f.Data) <= maxOSRelease {
		s.files[f.Path] = f.Data
	}
	return nil
}
func (s *osScan) Finish(ctx engine.TargetContext) []engine.Finding {
	if v := osRelease(s.files["/etc/os-release"], s.files["/usr/lib/os-release"]); v != "" {
		ctx.Annotate("java4shell_os", v)
	}
	return nil
}

// pathList keeps items in order, and drops those a path added in constant
// time (Forget can run once per file of an image).
type pathList[T any] struct {
	items []T
	gone  []bool
	at    map[string][]int
	live  int
}

func (l *pathList[T]) add(p string, v T) {
	if l.at == nil {
		l.at = map[string][]int{}
	}
	l.at[p] = append(l.at[p], len(l.items))
	l.items = append(l.items, v)
	l.gone = append(l.gone, false)
	l.live++
}

// drop removes what p added, and returns it.
func (l *pathList[T]) drop(p string) []T {
	var out []T
	for _, i := range l.at[p] {
		if !l.gone[i] {
			l.gone[i] = true
			l.live--
			out = append(out, l.items[i])
		}
	}
	delete(l.at, p)
	return out
}

func (l *pathList[T]) len() int { return l.live }

// list returns the items not dropped, in the order added.
func (l *pathList[T]) list() []T {
	out := make([]T, 0, l.live)
	for i, v := range l.items {
		if !l.gone[i] {
			out = append(out, v)
		}
	}
	return out
}
