package assess

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
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
