package assess

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

// Final review B1: a runtime directory can hold several VM libraries
// (server, client, minimal, a Java 8 lib/amd64/server left behind by an
// upgrade in place, a file dropped into bin/server). Every library that
// states a version or carries the decoder is judged, and the worst verdict
// is the runtime's: one library that clears never hides another.
func TestEveryLibraryIsJudged(t *testing.T) {
	const root = "/opt/java"
	vuln21 := testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}
	for _, c := range []struct {
		name    string
		libs    map[string]testlib.Lib
		release []string
		want    Status
		decides string // the library the finding names
	}{
		{"Java 8 left under lib/amd64, 21 in lib/server", map[string]testlib.Lib{"lib/amd64/server/libjvm.so": {Version: "1.8.0_452-b09"}, "lib/server/libjvm.so": vuln21},
			[]string{"JAVA_VERSION", "21.0.13"}, Vulnerable, "lib/server/libjvm.so"},
		{"a fixed library in bin/server", map[string]testlib.Lib{"bin/server/libjvm.so": {Version: "17.0.21.1+2", VBMI: true}, "lib/server/libjvm.so": {Version: "17.0.21+9", VBMI: true}},
			nil, Vulnerable, "lib/server/libjvm.so"},
		{"fixed server, vulnerable minimal", map[string]testlib.Lib{"lib/server/libjvm.so": {Version: "21.0.13.1+2-LTS", VBMI: true}, "lib/minimal/libjvm.so": vuln21},
			nil, Vulnerable, "lib/minimal/libjvm.so"},
		{"aarch64 server, x86-64 client", map[string]testlib.Lib{"lib/server/libjvm.so": {Machine: "aarch64", Version: "21.0.13+9-LTS"}, "lib/client/libjvm.so": vuln21},
			nil, Vulnerable, "lib/client/libjvm.so"},
		{"fixed server, vulnerable lib/libjvm.so", map[string]testlib.Lib{"lib/server/libjvm.so": {Version: "21.0.13.1+2-LTS", VBMI: true}, "lib/libjvm.so": vuln21},
			nil, Vulnerable, "lib/libjvm.so"},
		{"17.0.5 server, 17.0.21 client", map[string]testlib.Lib{"lib/server/libjvm.so": {Version: "17.0.5+8"}, "lib/client/libjvm.so": {Version: "17.0.21+9", VBMI: true}},
			nil, Vulnerable, "lib/client/libjvm.so"},
		{"fixed server, a later update in client", map[string]testlib.Lib{"lib/server/libjvm.so": {Version: "21.0.13.1+2-LTS", VBMI: true}, "lib/client/libjvm.so": {Version: "21.0.14+1", VBMI: true}},
			nil, Unknown, "lib/client/libjvm.so"},
		// Nothing worse: the server library decides, as before.
		{"two fixed libraries", map[string]testlib.Lib{"lib/server/libjvm.so": {Version: "21.0.13.1+2-LTS", VBMI: true}, "lib/client/libjvm.so": {Version: "21.0.13.1+2-LTS", VBMI: true}},
			nil, Fixed, "lib/server/libjvm.so"},
		{"two vulnerable libraries", map[string]testlib.Lib{"lib/server/libjvm.so": vuln21, "lib/client/libjvm.so": vuln21},
			nil, Vulnerable, "lib/server/libjvm.so"},
	} {
		in := Input{Releases: map[string]jvm.Release{}}
		for p, l := range c.libs {
			in.Libraries = append(in.Libraries, lib(t, root+"/"+p, l))
		}
		if c.release != nil {
			in.Releases[root] = rel(t, c.release...)
		}
		f := one(t, in)
		if f.Status != c.want || f.Library == nil || f.Library.Path != root+"/"+c.decides {
			t.Errorf("%s: %s by %v, want %s by %s (%s)", c.name, f.Status, f.Library, c.want, c.decides, f.Reason)
		}
		if len(c.libs) > 1 && f.Library.Path != root+"/lib/server/libjvm.so" && !strings.Contains(f.Reason, "VM libraries") {
			t.Errorf("%s: the reason does not say another library decided: %s", c.name, f.Reason)
		}
	}
}

// An OpenJ9 runtime's libraries are one VM: its redirector and libj9vm
// are not judged apart.
func TestOpenJ9LibrariesAreOneVM(t *testing.T) {
	const root = "/opt/java/openjdk"
	in := Input{Releases: map[string]jvm.Release{root: rel(t, "JAVA_VERSION", "21.0.13", "JVM_VARIANT", "Openj9")}}
	for _, p := range []string{"/lib/server/libjvm.so", "/lib/default/libjvm.so", "/lib/default/libj9vm29.so"} {
		in.Libraries = append(in.Libraries, lib(t, root+p, testlib.Lib{Extra: "OPENJ9_JAVA_OPTIONS"}))
	}
	if f := one(t, in); f.Status != NotAffected {
		t.Errorf("OpenJ9 runtime: %s (%s)", f.Status, f.Reason)
	}
}

// Final review B3: the string OPENJ9_JAVA_OPTIONS in a library without a
// version line does not make a runtime OpenJ9 on its own. It needs a second
// witness: an OpenJ9 VM library (libj9vm) in the runtime, or a release file
// that names OpenJ9.
func TestOpenJ9NeedsTwoWitnesses(t *testing.T) {
	const root = "/opt/jdk"
	redirector := func() *jvm.Library {
		return lib(t, root+"/lib/server/libjvm.so", testlib.Lib{Extra: "OPENJ9_JAVA_OPTIONS"})
	}
	for _, c := range []struct {
		name    string
		libs    []*jvm.Library
		release []string
		want    Status
	}{
		{"the string alone", []*jvm.Library{redirector()}, nil, Unknown},
		{"the string under a HotSpot release file", []*jvm.Library{redirector()}, []string{"JAVA_VERSION", "21.0.13", "IMPLEMENTOR", "Eclipse Adoptium"}, Unknown},
		{"the string under a fixed release file", []*jvm.Library{redirector()}, []string{"JAVA_VERSION", "21.0.13.1"}, Unknown},
		{"with a release file that names OpenJ9", []*jvm.Library{redirector()}, []string{"JAVA_VERSION", "21.0.13", "JVM_VARIANT", "Openj9"}, NotAffected},
		{"with an OpenJ9 VM library", []*jvm.Library{redirector(), lib(t, root+"/lib/default/libj9vm29.so", testlib.Lib{})}, nil, NotAffected},
	} {
		in := Input{Libraries: c.libs, Releases: map[string]jvm.Release{}}
		if c.release != nil {
			in.Releases[root] = rel(t, c.release...)
		}
		if f := one(t, in); f.Status != c.want {
			t.Errorf("%s: %s, want %s (%s)", c.name, f.Status, c.want, f.Reason)
		}
	}
}

// Second final review: a VM library the scan cannot judge on its own (no
// HotSpot version line and no decoder stubs, with or without OpenJ9's
// string, in a runtime that is not OpenJ9) never lets the libraries beside
// it clear the runtime. Before, a fixed lib/server cleared a runtime whose
// lib/client carried only OPENJ9_JAVA_OPTIONS (unknown before the
// two-witness rule), or no version at all.
func TestUnjudgedLibraryNeverCleared(t *testing.T) {
	const root = "/opt/jdk"
	fixed := testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true}
	vuln := testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}
	for _, c := range []struct {
		name    string
		libs    map[string]testlib.Lib
		release []string
		want    Status
	}{
		{"fixed server, client with only OpenJ9's string", map[string]testlib.Lib{"lib/server/libjvm.so": fixed, "lib/client/libjvm.so": {Extra: "OPENJ9_JAVA_OPTIONS"}}, nil, Unknown},
		{"fixed server, client with no version line", map[string]testlib.Lib{"lib/server/libjvm.so": fixed, "lib/client/libjvm.so": {}}, []string{"JAVA_VERSION", "21.0.13"}, Unknown},
		{"fixed server, client with no version line, fixed release file", map[string]testlib.Lib{"lib/server/libjvm.so": fixed, "lib/client/libjvm.so": {}}, []string{"JAVA_VERSION", "21.0.13.1"}, Unknown},
		{"Java 8 server, minimal with no version line", map[string]testlib.Lib{"lib/amd64/server/libjvm.so": {Version: "1.8.0_452-b09"}, "lib/amd64/minimal/libjvm.so": {}}, nil, Unknown},
		{"aarch64 server, x86-64 client with no version line", map[string]testlib.Lib{"lib/server/libjvm.so": {Machine: "aarch64", Version: "21.0.13+9-LTS"}, "lib/client/libjvm.so": {}}, nil, Unknown},
		// A verdict that is not a clear stands.
		{"vulnerable server, client with only OpenJ9's string", map[string]testlib.Lib{"lib/server/libjvm.so": vuln, "lib/client/libjvm.so": {Extra: "OPENJ9_JAVA_OPTIONS"}}, nil, Vulnerable},
		{"vulnerable server, client with no version line", map[string]testlib.Lib{"lib/server/libjvm.so": vuln, "lib/client/libjvm.so": {}}, nil, Vulnerable},
	} {
		in := Input{Releases: map[string]jvm.Release{}}
		for p, l := range c.libs {
			in.Libraries = append(in.Libraries, lib(t, root+"/"+p, l))
		}
		if c.release != nil {
			in.Releases[root] = rel(t, c.release...)
		}
		if f := one(t, in); f.Status != c.want {
			t.Errorf("%s: %s, want %s (%s)", c.name, f.Status, c.want, f.Reason)
		}
	}
}

// A VM library the scan met and did not read (over a size limit,
// unreadable, a path an image's layers do not settle) is a library that was
// not judged: its runtime is unknown when nothing else was read there, and
// when what was read would clear it.
func TestUnreadLibraryNeverCleared(t *testing.T) {
	const root = "/opt/jdk"
	fixed := lib(t, root+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true})
	vuln := lib(t, root+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})
	for _, c := range []struct {
		name   string
		libs   []*jvm.Library
		unread []string
		want   Status
	}{
		{"the only library", nil, []string{root + "/lib/server/libjvm.so"}, Unknown},
		{"beside a fixed library", []*jvm.Library{fixed}, []string{root + "/lib/client/libjvm.so"}, Unknown},
		{"beside a vulnerable library", []*jvm.Library{vuln}, []string{root + "/lib/client/libjvm.so"}, Vulnerable},
		{"in another runtime", []*jvm.Library{fixed}, []string{"/opt/other/lib/server/libjvm.so"}, Fixed},
	} {
		fs := Run(Input{Libraries: c.libs, UnreadLibraries: c.unread, Releases: map[string]jvm.Release{}})
		var got *Finding
		for i := range fs {
			if fs[i].Path == root {
				got = &fs[i]
			}
		}
		if got == nil || got.Status != c.want {
			t.Errorf("%s: %+v, want %s", c.name, fs, c.want)
			continue
		}
		if len(c.unread) > 0 && strings.HasPrefix(c.unread[0], root) && !strings.Contains(got.Reason, "not read") {
			t.Errorf("%s: the reason does not name the unread library: %s", c.name, got.Reason)
		}
	}
	// The other runtime's unread library is its own unknown finding.
	fs := Run(Input{Libraries: []*jvm.Library{fixed}, UnreadLibraries: []string{"/opt/other/lib/server/libjvm.so"}, Releases: map[string]jvm.Release{}})
	if len(fs) != 2 || fs[0].Path != root || fs[1].Path != "/opt/other" || fs[1].Status != Unknown {
		t.Errorf("an unread library in a second runtime: %+v", fs)
	}
}

// A Red Hat row speaks for one build. With several VM libraries in the
// runtime it is applied to each, not to the one the worst verdict names: a
// library that is another update, or a GraalVM build, keeps its verdict.
func TestRedHatRowEveryLibrary(t *testing.T) {
	saved := knowledge.RedHatFixed
	t.Cleanup(func() { knowledge.RedHatFixed = saved })
	knowledge.RedHatFixed = []knowledge.RedHatFix{{Package: "java-17-openjdk", Dist: "el9_6", EVR: "1:17.0.21.0.9-2.el9_6", Advisory: "RHSA-2026:0000"}}
	const root = "/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.el9_6.x86_64"
	row := testlib.Lib{Version: "17.0.21+9-LTS", VBMI: true}
	for _, c := range []struct {
		name string
		libs map[string]testlib.Lib
		want Status
	}{
		{"the row's build alone", map[string]testlib.Lib{"lib/server/libjvm.so": row}, Fixed},
		{"the row's build twice", map[string]testlib.Lib{"lib/server/libjvm.so": row, "lib/client/libjvm.so": row}, Fixed},
		{"a client library of an older update", map[string]testlib.Lib{"lib/server/libjvm.so": row, "lib/client/libjvm.so": {Version: "17.0.20+8", VBMI: true}}, Vulnerable},
		{"a minimal library that is a GraalVM build", map[string]testlib.Lib{"lib/server/libjvm.so": row, "lib/minimal/libjvm.so": {Version: "17.0.21+9-jvmci-23.0-b12", VBMI: true}}, Vulnerable},
		{"a client library with no version line", map[string]testlib.Lib{"lib/server/libjvm.so": row, "lib/client/libjvm.so": {}}, Unknown},
	} {
		in := Input{OSID: "rhel", Releases: map[string]jvm.Release{root: rel(t, "IMPLEMENTOR", "Red Hat, Inc.", "JAVA_VERSION", "17.0.21")}}
		for p, l := range c.libs {
			in.Libraries = append(in.Libraries, lib(t, root+"/"+p, l))
		}
		if f := one(t, in); f.Status != c.want {
			t.Errorf("%s: %s, want %s (%s)", c.name, f.Status, c.want, f.Reason)
		}
	}
}
