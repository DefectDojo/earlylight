package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

// Review finding 1: the release file alone never clears a runtime whose VM
// library carries the decoder.
func TestReleaseAloneDoesNotClear(t *testing.T) {
	musl := Input{
		Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true, Musl: true})},
		Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13.1", "JAVA_RUNTIME_VERSION", "21.0.13.1+2-LTS")},
	}
	if f := one(t, musl); f.Status != Vulnerable || f.VersionFrom != "vm-library" {
		t.Errorf("musl library with a forged release: %s from %s", f.Status, f.VersionFrom)
	}
	for _, v := range []string{"21.0.13.1", "11.0.20"} {
		in := Input{
			Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{VBMI: true})},
			Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", v)},
		}
		if f := one(t, in); f.Status != Unknown {
			t.Errorf("unreadable library with the decoder, release %s: %s (%s)", v, f.Status, f.Reason)
		}
	}
}

// Review finding 6: a release file that contradicts a HotSpot library that
// was read makes the verdict unknown.
func TestReleaseContradiction(t *testing.T) {
	in := Input{
		Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})},
		Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13", "JVM_VARIANT", "Openj9")},
	}
	if f := one(t, in); f.Status != Unknown {
		t.Errorf("HotSpot library, OpenJ9 release: %s (%s)", f.Status, f.Reason)
	}
}

// Review finding 4: a command that turns the intrinsic back on voids the
// image's mitigation, even when it cannot be tied to one runtime.
func TestCommandReenables(t *testing.T) {
	for _, c := range []struct {
		env string
		cmd []string
	}{
		{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", []string{"/bin/sh", "-c", "exec java -XX:+UseBASE64Intrinsics -jar /app.jar"}},
		{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", []string{"java", "-XX:+UseBASE64Intrinsics", "-jar", "/app.jar"}}, // no PATH in the image config
		{"JAVA_TOOL_OPTIONS=-XX:UseAVX=2", []string{"java", "-XX:UseAVX=3", "-jar", "/app.jar"}},
		{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", []string{"java", "@/app/jvm.args", "-jar", "/app.jar"}}, // options from a file this scan cannot see
	} {
		in := Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Env: []string{c.env}, Command: c.cmd}
		if f := one(t, in); f.Status != Vulnerable || f.Mitigation != "" {
			t.Errorf("%q: %s (%s)", c.cmd, f.Status, f.Mitigation)
		}
	}
	// Turning AVX-512 back on leaves -XX:-UseBASE64Intrinsics in force.
	in := Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Env: []string{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"}, Command: []string{"java", "-XX:UseAVX=3", "-jar", "/a.jar"}}
	if f := one(t, in); f.Status != Mitigated {
		t.Errorf("UseAVX=3 with -UseBASE64Intrinsics: %s", f.Status)
	}
	// _JAVA_OPTIONS is applied after the command line, so it still holds.
	in = Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Env: []string{"_JAVA_OPTIONS=-XX:-UseBASE64Intrinsics"},
		Command: []string{"/bin/sh", "-c", "exec java -XX:+UseBASE64Intrinsics -jar /app.jar"}}
	if f := one(t, in); f.Status != Mitigated {
		t.Errorf("_JAVA_OPTIONS after the command: %s", f.Status)
	}
}

// Review finding 5: a Windows batch file does not cover a Linux runtime.
func TestBatchFileWindowsOnly(t *testing.T) {
	bat, _ := jvm.ReadSetting("/opt/tomcat/bin/setenv.bat", []byte("set \"CATALINA_OPTS=-XX:-UseBASE64Intrinsics\"\n"))
	in := Input{Libraries: []*jvm.Library{vulnLib(t, "/opt/tomcat/jre")}, Settings: []jvm.Setting{bat}}
	if f := one(t, in); f.Status != Vulnerable {
		t.Errorf("setenv.bat on Linux: %s", f.Status)
	}
	win := lib(t, "/opt/tomcat/jre/bin/server/jvm.dll", testlib.Lib{Format: "pe", OS: "windows", Version: "21.0.13+9-LTS", VBMI: true})
	in = Input{Libraries: []*jvm.Library{win}, Settings: []jvm.Setting{bat}}
	if f := one(t, in); f.Status != Mitigated {
		t.Errorf("setenv.bat on Windows: %s", f.Status)
	}
}

// Round-2 finding 1: OpenJ9 only from an OpenJ9 library, never from the
// release file alone, and never when the HotSpot decoder stubs are there.
func TestOpenJ9NeedsLibrary(t *testing.T) {
	fastdebug := lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{VBMI: true, Extra: "\x00OpenJDK 64-Bit Server VM (fastdebug 21.0.13+9) for linux-amd64 JRE (21.0.13+9)\x00"})
	in := Input{Libraries: []*jvm.Library{fastdebug}, Releases: map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13", "JVM_VARIANT", "Openj9")}}
	if f := one(t, in); f.Status != Unknown {
		t.Errorf("release-only OpenJ9 over a library with the decoder: %s (%s)", f.Status, f.Reason)
	}
	// A library without stubs and without a version line, release says
	// OpenJ9, no OpenJ9 library: not cleared either.
	plain := lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{})
	in = Input{Libraries: []*jvm.Library{plain}, Releases: map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13", "JVM_VARIANT", "Openj9")}}
	if f := one(t, in); f.Status == NotAffected {
		t.Errorf("release-only OpenJ9: %s (%s)", f.Status, f.Reason)
	}
	// An OpenJ9 VM library next to a redirector carrying HotSpot stubs: unknown.
	j9 := lib(t, temurin+"/lib/default/libj9vm29.so", testlib.Lib{})
	in = Input{Libraries: []*jvm.Library{fastdebug, j9}}
	if f := one(t, in); f.Status != Unknown {
		t.Errorf("OpenJ9 library next to HotSpot stubs: %s", f.Status)
	}
	// Real Semeru layout: redirector + libj9vm29, release says OpenJ9.
	redir := lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Extra: "OPENJ9_JAVA_OPTIONS"})
	in = Input{Libraries: []*jvm.Library{redir, j9}, Releases: map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13.0.3", "JVM_VARIANT", "Openj9")}}
	if f := one(t, in); f.Status != NotAffected {
		t.Errorf("Semeru: %s (%s)", f.Status, f.Reason)
	}
}
