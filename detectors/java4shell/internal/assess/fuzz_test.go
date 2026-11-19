package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

func FuzzAPKOwners(f *testing.F) {
	f.Add([]byte("P:openjdk17-jre-headless\nV:17.0.21.0.3_p1-r0\nF:usr/lib/jvm/java-17-openjdk/lib/server\nR:libjvm.so\n\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for p, o := range APKOwners(b) {
			if p == "" || o.Name == "" || o.Manager != "apk" {
				t.Fatalf("bad owner %q %+v", p, o)
			}
		}
	})
}

func FuzzDpkgOwners(f *testing.F) {
	f.Add([]byte("Package: openjdk-17-jre-headless\nVersion: 17.0.21+9-1~deb12u1\n\n"), []byte("/usr/lib/jvm/java-17-openjdk-amd64/lib/server/libjvm.so\n"))
	f.Fuzz(func(t *testing.T, status, list []byte) {
		for p, o := range DpkgOwners(status, map[string][]byte{"openjdk-17-jre-headless:amd64": list}) {
			if p == "" || o.Manager != "dpkg" {
				t.Fatalf("bad owner %q %+v", p, o)
			}
		}
	})
}

// FuzzRun judges a runtime made of fuzzed release text, environment,
// command and settings file: every verdict has a reason, and none is
// fixed or not affected when the VM library carries the decoder and
// states an unfixed version.
func FuzzRun(f *testing.F) {
	f.Add("JAVA_VERSION=\"21.0.13.1\"\nJVM_VARIANT=\"Openj9\"\n", "JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", "sh -c java -XX:+UseBASE64Intrinsics", "JAVA_OPTS=\"-XX:-UseBASE64Intrinsics\"\n")
	f.Add("JAVA_VERSION=\"11.0.20\"\n", "_JAVA_OPTIONS=-XX:UseAVX=2", "catalina.sh run", "if true; then CATALINA_OPTS=-XX:UseAVX=1; fi\n")
	f.Fuzz(func(t *testing.T, release, env, cmd, setenv string) {
		lj, _ := jvm.Inspect("/opt/acme/jre/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}))
		in := Input{Libraries: []*jvm.Library{lj}, Env: []string{env, "JAVA_HOME=/opt/acme/jre"}, Command: jvm.Words(cmd), Releases: map[string]jvm.Release{}}
		if r, ok := jvm.ParseRelease([]byte(release)); ok {
			in.Releases["/opt/acme/jre"] = r
		}
		if s, ok := jvm.ReadSetting("/opt/acme/bin/setenv.sh", []byte(setenv)); ok {
			in.Settings = []jvm.Setting{s}
		}
		for _, x := range Run(in) {
			if x.Reason == "" || x.Message == "" {
				t.Fatalf("no reason: %+v", x)
			}
			if x.Status == Fixed || x.Status == NotAffected {
				t.Fatalf("an unfixed library with the decoder cleared: %s (%s)", x.Status, x.Reason)
			}
		}
	})
}
