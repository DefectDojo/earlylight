package assess

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

// fivePart are the last affected releases the OpenJDK advisory names and
// the vendor builds of them (Oracle, Debian sid, Microsoft, Temurin).
var fivePart = []string{
	"17.0.21.0.3+1-LTS", "21.0.13.0.3+1-LTS", "25.0.5.0.3+1-LTS", "27.0.1.0.3+1",
	"17.0.21.0.2+1-LTS", "21.0.13.0.2+1-LTS", "25.0.5.0.2+1-LTS", "27.0.1.0.2+1",
	"17.0.21.0.3+1-Debian-1", "27.0.1.0.3+1-Debian-1",
}

func TestFivePartVMLibrary(t *testing.T) {
	for _, v := range fivePart {
		f := one(t, Input{Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: v, VBMI: true})}})
		if f.Status != Vulnerable || f.VersionFrom != "vm-library" {
			t.Errorf("%s: %s from %s (%s)", v, f.Status, f.VersionFrom, f.Reason)
		}
	}
}

func TestFivePartReleaseFile(t *testing.T) {
	for _, v := range fivePart {
		// A VM library without a readable version line: the release file
		// states the version, and a vulnerable one is reported.
		f := one(t, Input{
			Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{VBMI: true})},
			Releases:  map[string]jvm.Release{temurin: rel(t, "JAVA_VERSION", v[:len(v)-len(v[indexPlus(v):])], "JAVA_RUNTIME_VERSION", v)},
		})
		if f.Status != Vulnerable || f.VersionFrom != "release-file" {
			t.Errorf("%s: %s from %s (%s)", v, f.Status, f.VersionFrom, f.Reason)
		}
	}
}

func indexPlus(s string) int {
	for i := range s {
		if s[i] == '+' {
			return i
		}
	}
	return len(s)
}

func TestFivePartPackages(t *testing.T) {
	// The package that owns the runtime is named in the fix text; the
	// verdict comes from the VM library whatever the package version says.
	for _, c := range []struct {
		root, lib string
		owners    map[string]Package
	}{
		{"/usr/lib/jvm/java-17-openjdk-amd64", "17.0.21.0.3+1-Debian-1", map[string]Package{
			"/usr/lib/jvm/java-17-openjdk-amd64/lib/server/libjvm.so": {Manager: "dpkg", Name: "openjdk-17-jre-headless", Version: "17.0.21.0.3+1-1"}}},
		{"/usr/lib/jvm/java-21-openjdk", "21.0.13.0.3+1-alpine-r0", map[string]Package{
			"/usr/lib/jvm/java-21-openjdk/lib/server/libjvm.so": {Manager: "apk", Name: "openjdk21-jre-headless", Version: "21.0.13.0.3_p1-r0"}}},
		{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-1.el9.x86_64", "17.0.21+9-LTS", nil},
	} {
		f := one(t, Input{Libraries: []*jvm.Library{lib(t, c.root+"/lib/server/libjvm.so", testlib.Lib{Version: c.lib, VBMI: true})}, Owners: c.owners})
		if f.Status != Vulnerable || f.Package == nil {
			t.Errorf("%s: %s package %v (%s)", c.root, f.Status, f.Package, f.Reason)
		}
	}
}

func TestGraalVMRuntime(t *testing.T) {
	const home = "/opt/graalvm"
	for _, c := range []struct {
		name    string
		lib     testlib.Lib
		release []string
		want    Status
	}{
		// Version lines read from GraalVM CE images (findepi/graalvm).
		{"CE 22.3.0 for Java 17", testlib.Lib{Version: "17.0.5+8-jvmci-22.3-b08"}, nil, NotAffected},
		{"CE 22.3.1 for Java 17", testlib.Lib{Version: "17.0.6+10-jvmci-22.3-b13", VBMI: true}, nil, Vulnerable},
		{"CE 22.3.1 for Java 11", testlib.Lib{Version: "11.0.18+10-jvmci-22.3-b13"}, nil, NotAffected},
		{"CE for JDK 21 (23.1.2)", testlib.Lib{Version: "21.0.2+13-jvmci-23.1-b30", VBMI: true}, nil, Vulnerable},
		{"Oracle GraalVM for JDK 17.0.21.0.3", testlib.Lib{VMName: "Java HotSpot(TM) 64-Bit Server VM", Version: "17.0.21.0.3+1-LTS-jvmci-23.0-b99", VBMI: true}, nil, Vulnerable},
		{"Oracle GraalVM for JDK 21.0.13.0.3", testlib.Lib{VMName: "Java HotSpot(TM) 64-Bit Server VM", Version: "21.0.13.0.3+1-LTS-jvmci-23.1-b99", VBMI: true}, nil, Vulnerable},
		{"GraalVM EE 21.3 for Java 11 carrying the decoder", testlib.Lib{VMName: "Java HotSpot(TM) 64-Bit Server VM", Version: "11.0.33+8-LTS-jvmci-21.3-b99", VBMI: true}, nil, Vulnerable},
		{"GraalVM EE 21.3 for Java 17", testlib.Lib{VMName: "Java HotSpot(TM) 64-Bit Server VM", Version: "17.0.21+8-LTS-jvmci-21.3-b99", VBMI: true}, nil, Vulnerable},
		// Past the OpenJDK fix, but no fixed GraalVM build is known.
		{"GraalVM at the OpenJDK fixed release", testlib.Lib{Version: "21.0.13.1+2-jvmci-23.1-b99", VBMI: true}, nil, Unknown},
		{"GraalVM named by its release file only", testlib.Lib{Version: "25.0.5.1+2-LTS", VBMI: true}, []string{"JAVA_VERSION", "25.0.5.1", "GRAALVM_VERSION", "25.0.5.1", "IMPLEMENTOR", "GraalVM Community"}, Unknown},
	} {
		in := Input{Libraries: []*jvm.Library{lib(t, home+"/lib/server/libjvm.so", c.lib)}}
		if c.release != nil {
			in.Releases = map[string]jvm.Release{home: rel(t, c.release...)}
		}
		f := one(t, in)
		if f.Status != c.want || !f.GraalVM {
			t.Errorf("%s: %s graalvm %v (%s)", c.name, f.Status, f.GraalVM, f.Reason)
			continue
		}
		if c.want != NotAffected && (!strings.Contains(f.Reason, "GraalVM") || !strings.Contains(f.Fix, "GraalVM")) {
			t.Errorf("%s: reason or fix does not name GraalVM:\n%s\n%s", c.name, f.Reason, f.Fix)
		}
	}
}

// Red Hat's layout: /usr/lib/jvm/java-17-openjdk-<version>-<release>.<arch>,
// the rpm named by its install path; the VM library reads the upstream
// version (17.0.21+9-LTS) whatever Red Hat backports.
func TestRedHatRuntime(t *testing.T) {
	const el9 = "/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-1.el9.x86_64"
	run := func(root, ver string) Finding {
		return one(t, Input{
			Libraries: []*jvm.Library{lib(t, root+"/lib/server/libjvm.so", testlib.Lib{Version: ver, VBMI: true})},
			Releases:  map[string]jvm.Release{root: rel(t, "JAVA_VERSION", "17.0.21", "JAVA_RUNTIME_VERSION", ver, "IMPLEMENTOR", "Red Hat, Inc.")},
		})
	}
	f := run(el9, "17.0.21+9-LTS")
	if f.Status != Vulnerable || f.Package == nil || f.Package.Name != "java-17-openjdk-headless" || f.Package.Version != "17.0.21.0.9-1.el9" {
		t.Fatalf("RHEL 9 rpm: %s %+v (%s)", f.Status, f.Package, f.Reason)
	}
	if !strings.Contains(f.Fix, "Red Hat had published no fixed") || !strings.Contains(f.Fix, "dnf upgrade java-17-openjdk-headless") {
		t.Errorf("fix text: %s", f.Fix)
	}

	saved := knowledge.RedHatFixed
	t.Cleanup(func() { knowledge.RedHatFixed = saved })
	knowledge.RedHatFixed = []knowledge.RedHatFix{{Package: "java-17-openjdk", EL: 9, EVR: "1:17.0.21.0.9-2.el9", Advisory: "RHSA-2026:0000"}}
	if f := run(el9, "17.0.21+9-LTS"); f.Status != Vulnerable || !strings.Contains(f.Fix, "17.0.21.0.9-2.el9") {
		t.Errorf("older than the listed build: %s (%s) fix %s", f.Status, f.Reason, f.Fix)
	}
	fixed := "/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.el9.x86_64"
	if f := run(fixed, "17.0.21+9-LTS"); f.Status != Fixed || !strings.Contains(f.Reason, "Red Hat") || f.Fix != "" {
		t.Errorf("listed build: %s (%s) fix %q", f.Status, f.Reason, f.Fix)
	}
	if f := run("/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-3.el9_7.x86_64", "17.0.21+9-LTS"); f.Status != Fixed {
		t.Errorf("later build: %s (%s)", f.Status, f.Reason)
	}
	// The VM library must be the update the rpm names: a path that says
	// 17.0.21 over a 17.0.13 VM library proves nothing.
	if f := run("/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.el9.x86_64", "17.0.13+11-LTS"); f.Status != Vulnerable {
		t.Errorf("mismatched VM library: %s (%s)", f.Status, f.Reason)
	}
	// No RHEL 8 entry: judged by the VM library.
	if f := run("/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-9.el8.x86_64", "17.0.21+9-LTS"); f.Status != Vulnerable {
		t.Errorf("RHEL 8: %s (%s)", f.Status, f.Reason)
	}
	// Not Red Hat: Fedora is not in the table.
	if f := run("/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-9.fc41.x86_64", "17.0.21+9"); f.Status != Vulnerable {
		t.Errorf("Fedora: %s (%s)", f.Status, f.Reason)
	}
}

func TestVendorStatusFix(t *testing.T) {
	f := one(t, Input{Libraries: []*jvm.Library{lib(t, temurin+"/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})}})
	for _, s := range []string{"Amazon Corretto and SapMachine", "Temurin, Microsoft, Debian, Ubuntu, Alpine and Red Hat had not", "Azul and BellSoft Liberica were not checked"} {
		if !strings.Contains(f.Fix, s) {
			t.Errorf("fix text does not say %q: %s", s, f.Fix)
		}
	}
}
