// Package assess decides what each Java runtime in a filesystem or image is
// with respect to Java4Shell (CVE-2026-114938): vulnerable, fixed, not
// affected, mitigated or unknown, with the reason. It knows nothing about
// the engine.
package assess

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
)

// Status is a verdict.
type Status string

const (
	Vulnerable  Status = "vulnerable"
	Fixed       Status = "fixed"
	NotAffected Status = "not-affected"
	// Mitigated: vulnerable code, kept from running by JVM options the
	// target sets. It still needs the update.
	Mitigated Status = "mitigated"
	Unknown   Status = "unknown"
)

// Finding kinds.
const (
	KindRuntime = "runtime"
	KindBundled = "bundled-runtime"
)

// Finding is the verdict on one Java runtime.
type Finding struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"` // the runtime directory
	Status  Status `json:"status"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Fix     string `json:"fix"`
	// Version is the version that decided, and where it was read.
	Version     string `json:"version,omitempty"`
	VersionFrom string `json:"version_from,omitempty"` // vm-library, release-file
	// ReleaseVersion is the release file's version when it differs from
	// the VM library's.
	ReleaseVersion string           `json:"release_version,omitempty"`
	Arch           jvm.Arch         `json:"arch,omitempty"`
	VM             string           `json:"vm,omitempty"`
	Vendor         string           `json:"vendor,omitempty"`
	Library        *jvm.Library     `json:"library,omitempty"`
	JLinked        bool             `json:"jlinked,omitempty"`
	Product        string           `json:"product,omitempty"`
	ProductDir     string           `json:"product_dir,omitempty"`
	Package        *Package         `json:"package,omitempty"`
	Mitigation     string           `json:"mitigation,omitempty"`
	MitigatedFor   []string         `json:"mitigated_for,omitempty"` // partial mitigations (one service)
	Release        knowledge.Status `json:"release_status,omitempty"`
	// GraalVM is a GraalVM JDK (HotSpot with JVMCI): fixed only at a
	// published fixed GraalVM build.
	GraalVM bool `json:"graalvm,omitempty"`
}

// Input is everything one target gives.
type Input struct {
	Libraries []*jvm.Library
	// Releases maps a runtime directory to its parsed release file;
	// BadReleases to why one was not used.
	Releases    map[string]jvm.Release
	BadReleases map[string]string
	Settings    []jvm.Setting
	// Env and Command are the image's configuration (nil for a
	// filesystem). Scripts lists, for each startup script kept, the script
	// variables it passes on to java.
	Env     []string
	Command []string
	Scripts map[string]map[string]bool
	// UnreadScripts are files that may be start scripts and were not read
	// (larger than the scan reads): what they pass to java is unknown.
	UnreadScripts map[string]bool
	// UnreadDirs could not be listed; UnreadAll stands for more unread
	// files than were recorded.
	UnreadDirs []string
	UnreadAll  bool
	// Owners maps installed files to the OS package that installed them.
	Owners map[string]Package
	// OSID is the target's os-release ID (rhel, rocky, debian), "" when
	// it has none.
	OSID string
	// Resolve follows symbolic links within the target.
	Resolve func(string) string
}

// Run judges every runtime in the target.
func Run(in Input) []Finding {
	byRoot := map[string][]*jvm.Library{}
	var loose []*jvm.Library
	for _, l := range in.Libraries {
		root, ok := jvm.Root(l.Path)
		if !ok {
			loose = append(loose, l)
			continue
		}
		byRoot[root] = append(byRoot[root], l)
	}
	roots := make([]string, 0, len(byRoot))
	for r := range byRoot {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	env := jvm.EnvMap(in.Env)
	var out []Finding
	for _, r := range roots {
		out = append(out, withFix(redHat(in, judge(in, env, r, byRoot[r]))))
	}
	for _, l := range loose {
		out = append(out, withFix(redHat(in, judge(in, env, path.Dir(l.Path), []*jvm.Library{l}))))
	}
	return out
}

func withFix(f Finding) Finding {
	v, ok := knowledge.Parse(f.Version)
	f.Fix = fixText(f, v, ok)
	return f
}

// primary picks the library that decides: a HotSpot server VM first.
func primary(libs []*jvm.Library) *jvm.Library {
	best := libs[0]
	score := func(l *jvm.Library) int {
		s := 0
		if l.HotSpot() {
			s += 4
		}
		if l.Variant == "server" {
			s += 2
		}
		if l.VMVersion != "" {
			s++
		}
		return s
	}
	for _, l := range libs[1:] {
		if score(l) > score(best) {
			best = l
		}
	}
	return best
}

func judge(in Input, env map[string]string, root string, libs []*jvm.Library) Finding {
	lib := primary(libs)
	rel, hasRel := in.Releases[root]
	if !hasRel && path.Base(root) == "jre" {
		// Java 8 JDKs keep the release file one level up.
		rel, hasRel = in.Releases[path.Dir(root)]
	}
	f := Finding{Kind: KindRuntime, Path: root, Library: lib, Arch: firstArch(lib)}
	if hasRel {
		f.Vendor = rel["IMPLEMENTOR"]
		f.JLinked = rel.JLinked()
	}
	if name, dir, ok := Product(root); ok {
		f.Kind, f.Product, f.ProductDir = KindBundled, name, dir
	}
	if p, ok := owner(in, root, lib); ok {
		f.Package = &p
	}
	// OpenJ9 only from an OpenJ9 library (by name, or the redirector with
	// no HotSpot version line and no decoder stubs): the release file's
	// JVM_VARIANT alone does not decide it.
	relJ9 := hasRel && rel.OpenJ9()
	openj9, stubs := false, false
	for _, l := range libs {
		if l.OpenJ9 {
			openj9 = true
		}
		if l.VBMIStubs {
			stubs = true
		}
	}

	// The version: the VM library's own, the release file's otherwise.
	verText, from := "", ""
	if lib.HotSpot() {
		verText, from = lib.JREVersion, "vm-library"
	}
	if verText == "" && hasRel {
		verText, from = rel.Version(), "release-file"
	}
	v, vok := knowledge.Parse(verText)
	if vok {
		f.Version, f.VersionFrom = verText, from
	}
	if hasRel && from == "vm-library" {
		if rv, ok := knowledge.Parse(rel.Version()); ok && knowledge.Compare(rv.Nums, v.Nums) != 0 {
			f.ReleaseVersion = rel.Version()
		}
	}
	f.VM = lib.VMName
	f.GraalVM = knowledge.IsGraalVM(lib.JREVersion) || knowledge.IsGraalVM(lib.VMVersion) ||
		hasRel && (rel["GRAALVM_VERSION"] != "" || knowledge.IsGraalVM(rel.Version()))
	if openj9 {
		f.VM = "OpenJ9"
	}
	what := describe(f, v, vok)

	hotspot := false
	for _, l := range libs {
		if l.HotSpot() {
			hotspot = true
		}
	}
	switch {
	case (openj9 || relJ9) && (hotspot || stubs):
		return f.set(Unknown, "the runtime's files contradict each other: a VM library carries HotSpot's version line or decoder stubs, but the release file or another VM library names OpenJ9",
			what+": HotSpot and OpenJ9 evidence disagree")
	case openj9:
		return f.set(NotAffected, "an OpenJ9 VM: the vulnerable decoder is HotSpot code that OpenJ9 does not contain",
			what+" runs the OpenJ9 VM, not HotSpot")
	case len(lib.Archs) == 0 || len(lib.Archs) == 1 && lib.Archs[0] == jvm.Other:
		return f.set(Unknown, "the VM library's CPU architecture could not be read", what+": CPU architecture unknown")
	case !lib.Has(jvm.X8664):
		return f.set(NotAffected, fmt.Sprintf("an %s runtime: only x86-64 HotSpot has the AVX-512 VBMI decoder", lib.Archs[0]),
			fmt.Sprintf("%s is built for %s, which Java4Shell does not affect", what, lib.Archs[0]))
	case !vok:
		why := "neither the VM library nor a release file states the Java version"
		if b, ok := in.BadReleases[root]; ok {
			why += " (" + b + ")"
		}
		return f.set(Unknown, why, what+": Java version unknown")
	}
	judgeVersion, judgeBackport := knowledge.Judge, knowledge.JudgeBackport
	if f.GraalVM {
		dist := knowledge.GraalVMDist(f.Vendor)
		judgeVersion = func(v knowledge.Version) (knowledge.Status, string) { return knowledge.JudgeGraalVM(v, dist) }
		judgeBackport = knowledge.JudgeBackportGraalVM
	}
	ks, kwhy := judgeVersion(v)
	f.Release = ks
	read := lib.HotSpot() // the stub names are only meaningful in a HotSpot library that was read
	if !read && ks != knowledge.Vulnerable {
		// Only the release file states the version, and a release file is
		// text anyone can write: it never clears a runtime alone.
		why := fmt.Sprintf("the VM library's version line could not be read, and the release file alone (Java %s) does not prove the runtime is safe", v)
		if lib.VBMIStubs {
			why = fmt.Sprintf("the VM library carries the AVX-512 VBMI Base64 decoder, but its version line could not be read; the release file alone (Java %s) does not prove the fix", v)
		}
		return f.set(Unknown, why, what+": version not readable from the VM library")
	}
	switch ks {
	case knowledge.NotAffected:
		if read && lib.VBMIStubs {
			bs, bwhy := judgeBackport(v)
			f.Release = bs
			if bs == knowledge.Vulnerable {
				if ok, how := mitigation(in, env, root, v.Feature(), &f); ok && unreadCommandScript(in) == "" {
					f.Mitigation = how
					return f.set(Mitigated, bwhy+"; "+how, what+" carries a backported AVX-512 VBMI Base64 decoder without the fix, mitigated by its JVM options until it is updated")
				}
				return f.set(Vulnerable, bwhy, what+" carries a backported AVX-512 VBMI Base64 decoder and is vulnerable to Java4Shell")
			}
			return f.set(Unknown, bwhy, what+" carries the AVX-512 VBMI Base64 decoder of later releases")
		}
		if !read {
			return f.set(NotAffected, kwhy+" (judged by the release file: no HotSpot version line was found in the VM library)", what+" is not affected by Java4Shell")
		}
		return f.set(NotAffected, kwhy+"; its VM library has no AVX-512 VBMI decode stubs", what+" is not affected by Java4Shell")
	case knowledge.Fixed:
		return f.set(Fixed, kwhy, what+" is at or past the first release with the Java4Shell fix (judged by its version)")
	case knowledge.Unknown:
		return f.set(Unknown, kwhy, what+": not known whether it has the Java4Shell fix")
	}
	// The release data says vulnerable.
	if read && !lib.VBMIStubs {
		return f.set(Unknown, fmt.Sprintf("%s, but this VM library does not carry the AVX-512 VBMI Base64 decode stubs, which the affected builds checked so far all carry: it may be built without them; check it", kwhy),
			what+": release says vulnerable, VM library lacks the vulnerable decoder")
	}
	if !read {
		kwhy += " (judged by the release file: no HotSpot version line was found in the VM library)"
	}
	if ok, how := mitigation(in, env, root, v.Feature(), &f); ok {
		if u := unreadCommandScript(in); u != "" {
			return f.set(Vulnerable, kwhy+"; "+how+", but the container's start script "+u+" was not read (larger than the scan reads) and can pass an option that undoes it",
				what+" is vulnerable to Java4Shell")
		}
		f.Mitigation = how
		return f.set(Mitigated, kwhy+"; "+how, what+" is vulnerable to Java4Shell, mitigated by its JVM options until it is updated")
	}
	return f.set(Vulnerable, kwhy, what+" is vulnerable to Java4Shell")
}

// redHatVendor is what Red Hat's release files name as IMPLEMENTOR.
const redHatVendor = "Red Hat, Inc."

// redHat applies Red Hat's backport table to a runtime its rpm installed:
// a fixed Red Hat build keeps the upstream version in its VM library, so
// only the rpm release shows the fix. The rpm is named by the install path
// alone (the rpm database is not read), so the table clears a runtime only
// when the runtime confirms it:
//   - its VM library is a released, non-GraalVM HotSpot of exactly the
//     update and build the rpm packages; a library that is not keeps its own
//     verdict (it proves it is not that build);
//   - its release file names Red Hat as the implementor, and the target's
//     os-release says RHEL (Rocky, AlmaLinux and CentOS Stream reuse Red
//     Hat's releases and implementor); without these, or without a readable
//     version line, the verdict is unknown: the path says fixed, the
//     runtime does not show it.
func redHat(in Input, f Finding) Finding {
	if f.Package == nil || f.Package.Manager != "rpm" || f.Status != Vulnerable && f.Status != Mitigated {
		return f
	}
	st, why, known := knowledge.JudgeRedHat(f.Package.Name, f.Package.Version)
	if !known || st != knowledge.Fixed {
		return f
	}
	why += ", by its install path"
	v, vok := knowledge.Parse(f.Version)
	if f.VersionFrom == "vm-library" && vok {
		up, build, uok := knowledge.RedHatUpstream(f.Package.Version)
		var not string
		switch {
		case f.GraalVM:
			not = "a GraalVM build"
		case v.EA || v.SelfBuilt:
			not = "a pre-release or self-built JDK"
		case !uok || v.Build != build || knowledge.Compare(v.Nums, up) != 0:
			not = "another update or build"
		}
		if not != "" {
			f.Reason += "; " + why + ", but its VM library (Java " + f.Version + ") is " + not + ", not that build"
			return f
		}
	}
	var doubt string
	switch {
	case f.VersionFrom != "vm-library" || !vok:
		doubt = "its VM library's version line could not be read"
	case f.Vendor != redHatVendor:
		doubt = "its release file does not name Red Hat, Inc. as the implementor"
	case in.OSID != "rhel":
		doubt = "the target's os-release does not say RHEL (ID=rhel); Rocky, AlmaLinux and CentOS Stream reuse Red Hat's releases"
	}
	if doubt != "" {
		f.Release = knowledge.Unknown
		return f.set(Unknown, why+"; but "+doubt+", so the runtime does not show that it is that build",
			describe(f, v, vok)+": the install path names Red Hat's fixed build, the runtime does not confirm it")
	}
	f.Release, f.Mitigation, f.MitigatedFor = knowledge.Fixed, "", nil
	return f.set(Fixed, why+"; its VM library reads Java "+f.Version+", the update and build Red Hat backported the fix into, its release file names Red Hat and the target is RHEL",
		describe(f, v, true)+" has Red Hat's backported Java4Shell fix (judged by its rpm release)")
}

func (f Finding) set(s Status, reason, msg string) Finding {
	f.Status, f.Reason, f.Message = s, reason, msg
	return f
}

func firstArch(l *jvm.Library) jvm.Arch {
	if l.Has(jvm.X8664) {
		return jvm.X8664
	}
	if len(l.Archs) > 0 {
		return l.Archs[0]
	}
	return ""
}

// describe names a runtime in a message: "Java 21.0.13+9 (Eclipse
// Adoptium) bundled in Atlassian Jira".
func describe(f Finding, v knowledge.Version, ok bool) string {
	s := "Java runtime"
	if ok {
		s = "Java " + v.Raw
	}
	if f.Vendor != "" {
		s += " (" + f.Vendor + ")"
	}
	if f.JLinked {
		s += ", a jlink image,"
	}
	if f.Product != "" {
		s += " bundled in " + f.Product
	}
	return s
}

// owner finds the package that installed the runtime.
func owner(in Input, root string, lib *jvm.Library) (Package, bool) {
	for _, p := range []string{lib.Path, root + "/release"} {
		cands := []string{p}
		if in.Resolve != nil {
			if r := in.Resolve(p); r != "" && r != p {
				cands = append(cands, r)
			}
		}
		for _, c := range cands {
			if o, ok := in.Owners[c]; ok {
				return o, true
			}
		}
	}
	// Debian's runtime directory is reached through symlinks into
	// /usr/lib/jvm/java-17-openjdk-amd64; the list names the real path.
	for k, o := range in.Owners {
		if strings.HasPrefix(k, root+"/") {
			return o, true
		}
	}
	return rpmFromPath(root)
}

// mitigation decides whether JVM options the target sets keep the
// vulnerable decoder from being generated for this runtime. Mitigations
// that cover only some launches are recorded on f, not counted.
func mitigation(in Input, env map[string]string, root string, feature int, f *Finding) (bool, string) {
	// Settings files of the product the runtime is bundled in.
	var o jvm.Options
	var b64, avx, argfile bool
	if in.Env != nil {
		if v, ok := env["JAVA_TOOL_OPTIONS"]; ok {
			o.Apply(v, "the image's JAVA_TOOL_OPTIONS")
		}
		if v, ok := env["JDK_JAVA_OPTIONS"]; ok && feature >= 9 {
			o.Apply(v, "the image's JDK_JAVA_OPTIONS")
		}
		// Script variables count when the container's command passes them on.
		// They reach only the JVM the script starts: the one JAVA_HOME or
		// JRE_HOME names, or the java on PATH.
		vars := scriptVarsOf(in)
		for _, n := range jvm.ScriptVars {
			if v, ok := env[n]; ok && vars[n] && javaHomeIs(in, env, root) {
				o.Apply(v, "the image's "+n+" (passed on by the container's start script)")
			}
		}
		if opts, ok := jvm.JavaOptions(in.Command); ok && commandRuns(in, env, root) {
			for _, w := range opts {
				o.ApplyWord(w, "the container's command")
			}
		}
		// Words that turn the decoder back on count wherever the command
		// starts java (a "sh -c" script, a java this scan cannot place):
		// a mitigation has to hold for every launch.
		b64, avx, argfile = jvm.Undoes(jvm.CommandWords(in.Command))
		if argfile {
			return false, ""
		}
	}
	for _, s := range in.Settings {
		if s.Kind == "systemd" || s.Scope == "" || s.WindowsOnly && (f.Library == nil || f.Library.Format != "pe") {
			continue
		}
		if within(root, s.Scope) || in.Env != nil && launches(in, env, s) && javaHomeIs(in, env, root) {
			s.ApplyTo(&o, feature)
		}
	}
	if b64 {
		o.ApplyWord("-XX:+UseBASE64Intrinsics", "the container's command")
	}
	if avx {
		o.ApplyWord("-XX:UseAVX=3", "the container's command")
	}
	if in.Env != nil {
		if v, ok := env["_JAVA_OPTIONS"]; ok {
			o.Apply(v, "the image's _JAVA_OPTIONS")
		}
	}
	if ok, how := o.Mitigates(); ok {
		return true, how
	}
	// systemd units: they cover the service, and the runtime only when it
	// is bundled in the product the service starts.
	for _, s := range jvm.MergeUnits(in.Settings) {
		so := s.Options(feature)
		ok, how := so.Mitigates()
		if !ok || s.Exec == "" {
			continue
		}
		exec := s.Exec
		if in.Resolve != nil {
			if r := in.Resolve(exec); r != "" {
				exec = r
			}
		}
		if f.ProductDir != "" && within(exec, f.ProductDir) {
			return true, how + " for the " + s.Unit + " service, which starts " + f.Product
		}
		if within(exec, root) {
			f.MitigatedFor = append(f.MitigatedFor, s.Unit)
		}
	}
	return false, ""
}

// commandRuns reports whether the container's command starts this
// runtime's java: by path, or by name through PATH.
func commandRuns(in Input, env map[string]string, root string) bool {
	for _, w := range in.Command {
		if path.Base(w) != "java" {
			continue
		}
		p := w
		if !strings.Contains(w, "/") {
			for _, d := range strings.Split(env["PATH"], ":") {
				if d != "" && (d == root+"/bin" || in.Resolve != nil && in.Resolve(d+"/java") == in.Resolve(root+"/bin/java")) {
					return true
				}
			}
			return false
		}
		if in.Resolve != nil {
			p = in.Resolve(p)
		}
		return within(p, root)
	}
	return false
}

// launches reports whether the container's command starts the product a
// settings file configures: its own start script, or catalina.sh of the
// CATALINA_HOME or CATALINA_BASE it sits in.
func launches(in Input, env map[string]string, s jvm.Setting) bool {
	for _, w := range in.Command {
		if !strings.Contains(w, "/") {
			if path.Base(w) == "catalina.sh" && (env["CATALINA_HOME"] == s.Scope || env["CATALINA_BASE"] == s.Scope) {
				return true
			}
			continue
		}
		p := w
		if in.Resolve != nil {
			p = in.Resolve(w)
		}
		if within(p, s.Scope) {
			return true
		}
	}
	return false
}

// javaHomeIs reports whether a start script would run this runtime: the
// one JAVA_HOME or JRE_HOME names, or without them the java on PATH.
func javaHomeIs(in Input, env map[string]string, root string) bool {
	res := func(p string) string {
		if in.Resolve != nil {
			return in.Resolve(p)
		}
		return p
	}
	for _, k := range []string{"JRE_HOME", "JAVA_HOME"} {
		if h := strings.TrimSuffix(env[k], "/"); h != "" {
			return h == root || res(h) == res(root)
		}
	}
	for _, d := range strings.Split(env["PATH"], ":") {
		if d != "" && res(d+"/java") == res(root+"/bin/java") {
			return true
		}
	}
	return false
}

// unreadCommandScript is a script the container's command runs that was
// not read, or "".
func unreadCommandScript(in Input) string {
	if len(in.Command) > 0 && in.UnreadAll {
		return "(one of more files than the scan records)"
	}
	for _, w := range in.Command {
		p := w
		if in.Resolve != nil {
			p = in.Resolve(w)
		}
		for _, c := range []string{p, w} {
			if in.UnreadScripts[c] {
				return c
			}
			for _, d := range in.UnreadDirs {
				if strings.HasPrefix(c, strings.TrimSuffix(d, "/")+"/") {
					return c
				}
			}
		}
	}
	return ""
}

// scriptVarsOf lists the script variables the container's command passes
// on: catalina.sh passes CATALINA_OPTS and JAVA_OPTS, and a startup script
// passes the ones it names.
func scriptVarsOf(in Input) map[string]bool {
	out := map[string]bool{}
	for _, w := range in.Command {
		if path.Base(w) == "catalina.sh" {
			out["CATALINA_OPTS"], out["JAVA_OPTS"] = true, true
		}
		p := w
		if in.Resolve != nil {
			p = in.Resolve(w)
		}
		for k := range in.Scripts[p] {
			out[k] = true
		}
		for k := range in.Scripts[w] {
			out[k] = true
		}
	}
	return out
}

func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// fixText is what to do.
func fixText(f Finding, v knowledge.Version, ok bool) string {
	switch f.Status {
	case Fixed, NotAffected:
		return ""
	}
	interim := " Until then, start it with -XX:-UseBASE64Intrinsics (for example JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics); that keeps the vulnerable decoder from being generated, at some cost to Base64 decoding speed."
	if f.Status == Mitigated {
		interim = " The JVM options keep the vulnerable decoder from running until then; keep them until it is updated."
	}
	target := "a Java release with the fix (17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 and later on the same update)"
	if f.GraalVM {
		target = fmt.Sprintf("a GraalVM build with the fix once Oracle or the GraalVM project publishes one (none had been as of %s), or a JDK release with the fix (17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1)", knowledge.Checked)
	} else if ok && v.Feature() < 17 {
		// A backported decoder (Oracle's Java 8 Performance Pack).
		target = fmt.Sprintf("a build of Java %d from the same vendor with the fix (none was known on %s), or one without the backported AVX-512 decoder", v.Feature(), knowledge.Checked)
	} else if ok {
		if fx := knowledge.FixedVersion(v.Feature()); fx != "" {
			target = "Java " + fx + " or later of the same update"
		} else if v.Feature() >= 17 {
			target = "a supported Java release with the fix, such as " + knowledge.Upgrade(v.Feature()) + " (Java " + fmt.Sprint(v.Feature()) + " received none)"
		}
	}
	switch {
	case f.Product != "":
		return fmt.Sprintf("Upgrade %s to a release that bundles %s; its own runtime is not updated by the operating system's Java packages.%s", f.Product, target, interim)
	case f.Package != nil:
		if pkg, el, ok := knowledge.RedHatPackage(f.Package.Name, f.Package.Version); ok {
			if fx, ok := knowledge.RedHatFixFor(pkg, el); ok {
				evr := fx.EVR
				if i := strings.IndexByte(evr, ':'); i >= 0 {
					evr = evr[i+1:]
				}
				target = fmt.Sprintf("Red Hat's build %s or later (%s)", evr, fx.Advisory)
			}
		}
		return fmt.Sprintf("Update the %s package to %s: %s (%s).%s", f.Package.Name, target, upgradeLine(*f.Package), distroStatus(*f.Package), interim)
	case f.JLinked:
		return fmt.Sprintf("Rebuild this jlink image from a JDK at %s.%s", target, interim)
	}
	return fmt.Sprintf("Update this runtime to %s (%s: check your vendor).%s", target, knowledge.VendorStatus(), interim)
}
