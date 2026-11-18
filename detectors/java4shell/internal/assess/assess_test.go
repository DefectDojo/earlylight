package assess

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

func lib(t *testing.T, p string, l testlib.Lib) *jvm.Library {
	t.Helper()
	x, ok := jvm.Inspect(p, testlib.Build(l))
	if !ok {
		t.Fatalf("%s not inspected", p)
	}
	return x
}

func rel(t *testing.T, kv ...string) jvm.Release {
	t.Helper()
	r, ok := jvm.ParseRelease(testlib.Release(kv...))
	if !ok {
		t.Fatal("release not parsed")
	}
	return r
}

const temurin = "/opt/java/openjdk"

func one(t *testing.T, in Input) Finding {
	t.Helper()
	fs := Run(in)
	if len(fs) != 1 {
		t.Fatalf("%d findings: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestVerdicts(t *testing.T) {
	for _, c := range []struct {
		name string
		lib  testlib.Lib
		want Status
	}{
		{"21 unfixed", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}, Vulnerable},
		{"21 fixed", testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true}, Fixed},
		{"17.0.5", testlib.Lib{Version: "17.0.5+8"}, NotAffected},
		{"17.0.5 with a vendor backport of the decoder", testlib.Lib{Version: "17.0.5+8", VBMI: true}, Unknown},
		{"11", testlib.Lib{Version: "11.0.33+10"}, NotAffected},
		{"11 with a vendor backport of the decoder", testlib.Lib{Version: "11.0.33+10", VBMI: true}, Unknown},
		{"Oracle 8u511 Performance Pack", testlib.Lib{Version: "1.8.0_511-perf-b33", VBMI: true}, Vulnerable},
		{"Java 8 backport newer than any known affected build", testlib.Lib{Version: "1.8.0_521-perf-b05", VBMI: true}, Unknown},
		{"8", testlib.Lib{Version: "1.8.0_512-b09"}, NotAffected},
		{"aarch64", testlib.Lib{Machine: "aarch64", Version: "21.0.13+9-LTS"}, NotAffected},
		{"x86 32-bit", testlib.Lib{Machine: "x86", Version: "21.0.13+9-LTS"}, NotAffected},
		{"universal macOS", testlib.Lib{Format: "fat", Version: "21.0.13+9-LTS", VBMI: true}, Vulnerable},
		{"unfixed but no decoder stubs", testlib.Lib{Version: "21.0.13+9-LTS"}, Unknown},
		{"24 end of life", testlib.Lib{Version: "24.0.2+12", VBMI: true}, Vulnerable},
		{"later update", testlib.Lib{Version: "21.0.14+1", VBMI: true}, Unknown},
	} {
		f := one(t, Input{Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", c.lib)}})
		if f.Status != c.want || f.Reason == "" || f.Message == "" {
			t.Errorf("%s: %s (%s)", c.name, f.Status, f.Reason)
		}
		if (f.Status == Vulnerable || f.Status == Unknown) && f.Fix == "" {
			t.Errorf("%s: no fix text", c.name)
		}
		if f.Status == Fixed || f.Status == NotAffected {
			if f.Fix != "" {
				t.Errorf("%s: fix text on a cleared finding", c.name)
			}
		}
	}
}

func TestReleaseFile(t *testing.T) {
	// The VM library decides; a release file that says otherwise is noted.
	in := Input{
		Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})},
		Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13.1", "JAVA_RUNTIME_VERSION", "21.0.13.1+2", "IMPLEMENTOR", "Eclipse Adoptium")},
	}
	f := one(t, in)
	if f.Status != Vulnerable || f.ReleaseVersion != "21.0.13.1+2" || f.VersionFrom != "vm-library" || f.Vendor != "Eclipse Adoptium" {
		t.Errorf("forged release file: %+v", f)
	}
	// No version line: the release file is used, and says so.
	in = Input{
		Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{})},
		Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "25.0.5")},
	}
	if f := one(t, in); f.Status != Vulnerable || f.VersionFrom != "release-file" || !strings.Contains(f.Reason, "release file") {
		t.Errorf("release-file version: %+v", f)
	}
	// Neither: unknown, with the release file's problem.
	in = Input{Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{})}, BadReleases: map[string]string{temurin: "too large"}}
	if f := one(t, in); f.Status != Unknown || !strings.Contains(f.Reason, "too large") {
		t.Errorf("no version: %+v", f)
	}
	// Java 8 JDK: the release file one level above jre/.
	in = Input{
		Libraries: []*jvm.Library{lib(t, "/usr/lib/jvm/j8/jre/lib/amd64/server/libjvm.so", testlib.Lib{Version: "1.8.0_452-b09"})},
		Releases:  map[string]jvm.Release{"/usr/lib/jvm/j8": rel(t, "JAVA_VERSION", "1.8.0_452")},
	}
	if f := one(t, in); f.Status != NotAffected {
		t.Errorf("java 8 jdk: %+v", f)
	}
	// jlink image.
	in = Input{
		Libraries: []*jvm.Library{lib(t, "/app/rt/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})},
		Releases:  map[string]jvm.Release{"/app/rt": rel(t, "JAVA_VERSION", "21.0.13", "MODULES", "java.base java.logging")},
	}
	if f := one(t, in); f.Status != Vulnerable || !f.JLinked || !strings.Contains(f.Fix, "jlink") {
		t.Errorf("jlink: %+v", f)
	}
}

func TestOpenJ9(t *testing.T) {
	in := Input{
		Libraries: []*jvm.Library{
			lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Extra: "OPENJ9_JAVA_OPTIONS"}),
			lib(t, temurin+"/lib/default/libj9vm29.so", testlib.Lib{}),
		},
		Releases: map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", "21.0.13.0.3", "JVM_VARIANT", "Openj9")},
	}
	if f := one(t, in); f.Status != NotAffected || f.VM != "OpenJ9" {
		t.Errorf("openj9: %+v", f)
	}
}

func TestProducts(t *testing.T) {
	for root, want := range map[string]string{
		"/opt/atlassian/jira/jre":                                    "Atlassian Jira",
		"/usr/share/elasticsearch/jdk":                               "Elasticsearch",
		"/opt/jfrog/artifactory/app/third-party/java":                "JFrog Artifactory",
		"/opt/idea-IU-243/jbr":                                       "IntelliJ IDEA",
		"/Applications/IntelliJ IDEA.app/Contents/jbr/Contents/Home": "IntelliJ IDEA",
		"/opt/acme/jre":                                              "acme",
	} {
		if name, _, ok := Product(root); !ok || name != want {
			t.Errorf("Product(%s) = %q %v, want %q", root, name, ok, want)
		}
	}
	for _, root := range []string{"/opt/java/openjdk", "/usr/lib/jvm/java-17-openjdk-amd64", "/opt/jdk-21.0.5+11", "/home/u/.sdkman/candidates/java/21.0.5-tem", "/app/jre"} {
		if name, _, ok := Product(root); ok {
			t.Errorf("Product(%s) = %q, want none", root, name)
		}
	}
	f := one(t, Input{Libraries: []*jvm.Library{lib(t, "/opt/atlassian/jira/jre/lib/server/libjvm.so", testlib.Lib{Version: "17.0.12+7", VBMI: true})}})
	if f.Kind != KindBundled || !strings.Contains(f.Fix, "Upgrade Atlassian Jira") {
		t.Errorf("bundled: %+v", f)
	}
}

func TestPackages(t *testing.T) {
	apk := []byte("P:openjdk17-jre-headless\nV:17.0.21.0.3_p1-r0\nF:usr/lib/jvm/java-17-openjdk/lib/server\nR:libjvm.so\n\nP:busybox\nV:1\nF:bin\nR:busybox\n")
	in := Input{
		Libraries: []*jvm.Library{lib(t, "/usr/lib/jvm/java-17-openjdk/lib/server/libjvm.so", testlib.Lib{Version: "17.0.21.0.3+1-alpine-r0", VBMI: true})},
		Owners:    APKOwners(apk),
	}
	f := one(t, in)
	if f.Package == nil || f.Package.Name != "openjdk17-jre-headless" || !strings.Contains(f.Fix, "apk upgrade openjdk17-jre-headless") {
		t.Errorf("apk: %+v", f)
	}
	status := []byte("Package: openjdk-17-jre-headless\nStatus: install ok installed\nVersion: 17.0.21+9-1~deb12u1\n\n")
	lists := map[string][]byte{"openjdk-17-jre-headless:amd64": []byte("/usr/lib/jvm/java-17-openjdk-amd64/lib/server/libjvm.so\n")}
	in = Input{
		Libraries: []*jvm.Library{lib(t, "/usr/lib/jvm/java-17-openjdk-amd64/lib/server/libjvm.so", testlib.Lib{Version: "17.0.21+9-Debian-1deb12u1", VBMI: true})},
		Owners:    DpkgOwners(status, lists),
	}
	if f := one(t, in); f.Package == nil || f.Package.Version != "17.0.21+9-1~deb12u1" || !strings.Contains(f.Fix, "apt-get install --only-upgrade") {
		t.Errorf("dpkg: %+v", f)
	}
	in = Input{Libraries: []*jvm.Library{lib(t, "/usr/lib/jvm/java-21-openjdk-21.0.13.0.11-1.el9.x86_64/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+11-LTS", VBMI: true})}}
	if f := one(t, in); f.Package == nil || f.Package.Name != "java-21-openjdk-headless" || f.Package.From != "install path" {
		t.Errorf("rpm path: %+v", f)
	}
}

func vulnLib(t *testing.T, root string) *jvm.Library {
	return lib(t, root+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})
}

func TestMitigations(t *testing.T) {
	base := func() Input { return Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Env: []string{}} }

	in := base()
	in.Env = []string{"JAVA_TOOL_OPTIONS=-Xmx1g -XX:-UseBASE64Intrinsics"}
	if f := one(t, in); f.Status != Mitigated || !strings.Contains(f.Reason, "JAVA_TOOL_OPTIONS") || f.Fix == "" {
		t.Errorf("image env: %+v", f)
	}
	in.Env = append(in.Env, "_JAVA_OPTIONS=-XX:+UseBASE64Intrinsics")
	if f := one(t, in); f.Status != Vulnerable {
		t.Errorf("_JAVA_OPTIONS re-enables: %+v", f)
	}

	in = base()
	in.Command = []string{"java", "-XX:UseAVX=2", "-jar", "/app.jar"}
	in.Env = []string{"PATH=/opt/java/openjdk/bin:/usr/bin"}
	if f := one(t, in); f.Status != Mitigated {
		t.Errorf("command line: %+v", f)
	}
	in.Command = []string{"java", "-jar", "/app.jar", "-XX:UseAVX=2"}
	if f := one(t, in); f.Status != Vulnerable {
		t.Errorf("an application argument counted: %+v", f)
	}

	// CATALINA_OPTS counts when the container runs catalina.sh.
	in = base()
	in.Env = []string{"CATALINA_OPTS=-XX:-UseBASE64Intrinsics", "JAVA_HOME=/opt/java/openjdk"}
	if f := one(t, in); f.Status != Vulnerable {
		t.Errorf("CATALINA_OPTS without catalina.sh: %+v", f)
	}
	in.Command = []string{"catalina.sh", "run"}
	if f := one(t, in); f.Status != Mitigated {
		t.Errorf("CATALINA_OPTS with catalina.sh: %+v", f)
	}

	// A product's setenv.sh covers the runtime it bundles, not others.
	jira := "/opt/atlassian/jira/jre"
	set, _ := jvm.ReadSetting("/opt/atlassian/jira/bin/setenv.sh", []byte(`JVM_SUPPORT_RECOMMENDED_ARGS="-XX:-UseBASE64Intrinsics"`))
	in = Input{Libraries: []*jvm.Library{vulnLib(t, jira), vulnLib(t, temurin)}, Settings: []jvm.Setting{set}}
	fs := Run(in)
	for _, f := range fs {
		want := Vulnerable
		if f.Path == jira {
			want = Mitigated
		}
		if f.Status != want {
			t.Errorf("setenv.sh scope: %s %s", f.Path, f.Status)
		}
	}

	// Tomcat's setenv.sh covers the JVM catalina.sh starts (JAVA_HOME), when
	// the container runs it.
	tset, _ := jvm.ReadSetting("/usr/local/tomcat/bin/setenv.sh", []byte(`CATALINA_OPTS="$CATALINA_OPTS -XX:-UseBASE64Intrinsics"`))
	in = Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Settings: []jvm.Setting{tset},
		Env: []string{"CATALINA_HOME=/usr/local/tomcat", "JAVA_HOME=/opt/java/openjdk"}, Command: []string{"catalina.sh", "run"}}
	if f := one(t, in); f.Status != Mitigated || !strings.Contains(f.Reason, "setenv.sh") {
		t.Errorf("tomcat setenv.sh: %+v", f)
	}
	in.Command = []string{"java", "-jar", "/app.jar"}
	if f := one(t, in); f.Status != Vulnerable {
		t.Errorf("tomcat setenv.sh without catalina.sh: %+v", f)
	}
	in.Command, in.Env = []string{"catalina.sh", "run"}, []string{"CATALINA_HOME=/usr/local/tomcat", "JAVA_HOME=/usr/lib/jvm/other"}
	if f := one(t, in); f.Status != Vulnerable {
		t.Errorf("tomcat setenv.sh for another JAVA_HOME: %+v", f)
	}

	// A systemd unit covers a bundled runtime of the product it starts;
	// for a shared runtime it is recorded, not counted.
	unit, _ := jvm.ReadSetting("/etc/systemd/system/jira.service", []byte("Environment=JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nExecStart=/opt/atlassian/jira/bin/start-jira.sh -fg\n"))
	in = Input{Libraries: []*jvm.Library{vulnLib(t, jira)}, Settings: []jvm.Setting{unit}}
	if f := one(t, in); f.Status != Mitigated || !strings.Contains(f.Reason, "jira.service") {
		t.Errorf("systemd bundled: %+v", f)
	}
	shared := "/usr/lib/jvm/java-21-openjdk-amd64"
	unit, _ = jvm.ReadSetting("/etc/systemd/system/app.service", []byte("ExecStart="+shared+"/bin/java -XX:-UseBASE64Intrinsics -jar /srv/app.jar\n"))
	in = Input{Libraries: []*jvm.Library{vulnLib(t, shared)}, Settings: []jvm.Setting{unit}}
	if f := one(t, in); f.Status != Vulnerable || len(f.MitigatedFor) != 1 {
		t.Errorf("systemd shared: %+v", f)
	}

	// A mitigation never makes a fixed or unaffected runtime anything else.
	in = Input{Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13.1+2", VBMI: true})}, Env: []string{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"}}
	if f := one(t, in); f.Status != Fixed {
		t.Errorf("fixed + mitigation: %+v", f)
	}
}

func TestSymlinkLoopResolve(t *testing.T) {
	// A resolver that never settles must not hang owner lookup.
	loop := func(p string) string { return p + "/x" }
	in := Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Resolve: loop, Env: []string{}, Command: []string{"java", "-XX:UseAVX=2"}}
	_ = one(t, in)
}

// Round-2 review finding 6: a start script the command runs that was not
// read can pass an option that undoes a mitigation: not mitigated.
func TestMitigationWithUnreadStartScript(t *testing.T) {
	in := Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Env: []string{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", "JAVA_OPTS=-XX:+UseBASE64Intrinsics"},
		Command: []string{"/entrypoint.sh"}}
	if f := one(t, in); f.Status != Mitigated {
		t.Fatalf("read nothing that passes JAVA_OPTS: %+v", f)
	}
	in.UnreadScripts = map[string]bool{"/entrypoint.sh": true}
	if f := one(t, in); f.Status != Vulnerable || !strings.Contains(f.Reason, "/entrypoint.sh was not read") {
		t.Errorf("an unread entrypoint: %+v", f)
	}
	in.Command = []string{"/usr/bin/other"}
	if f := one(t, in); f.Status != Mitigated {
		t.Errorf("an unread script the command does not run: %+v", f)
	}
}
