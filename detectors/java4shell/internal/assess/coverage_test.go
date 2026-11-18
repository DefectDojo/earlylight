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
	const el96 = "/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-1.el9_6.x86_64"
	type rt struct {
		root, lib, vendor string
		noVersionLine     bool
		env               []string
	}
	run := func(c rt) Finding {
		l := testlib.Lib{Version: c.lib, VBMI: true}
		if c.noVersionLine {
			l.Version = ""
		}
		kv := []string{"JAVA_VERSION", "17.0.21", "JAVA_RUNTIME_VERSION", c.lib}
		if c.vendor != "" {
			kv = append(kv, "IMPLEMENTOR", c.vendor)
		}
		in := Input{
			Libraries: []*jvm.Library{lib(t, c.root+"/lib/server/libjvm.so", l)},
			Releases:  map[string]jvm.Release{c.root: rel(t, kv...)},
			Env:       c.env,
		}
		return one(t, in)
	}
	const rh = "Red Hat, Inc."
	f := run(rt{el96, "17.0.21+9-LTS", rh, false, nil})
	if f.Status != Vulnerable || f.Package == nil || f.Package.Name != "java-17-openjdk-headless" || f.Package.Version != "17.0.21.0.9-1.el9_6" {
		t.Fatalf("RHEL 9 rpm: %s %+v (%s)", f.Status, f.Package, f.Reason)
	}
	if !strings.Contains(f.Fix, "Red Hat had published no fixed") || !strings.Contains(f.Fix, "dnf upgrade java-17-openjdk-headless") {
		t.Errorf("fix text: %s", f.Fix)
	}

	saved := knowledge.RedHatFixed
	t.Cleanup(func() { knowledge.RedHatFixed = saved })
	knowledge.RedHatFixed = []knowledge.RedHatFix{{Package: "java-17-openjdk", Dist: "el9_6", EVR: "1:17.0.21.0.9-2.el9_6", Advisory: "RHSA-2026:0000"}}
	if f := run(rt{el96, "17.0.21+9-LTS", rh, false, nil}); f.Status != Vulnerable || !strings.Contains(f.Fix, "17.0.21.0.9-2.el9_6") {
		t.Errorf("older than the listed build: %s (%s) fix %s", f.Status, f.Reason, f.Fix)
	}
	fixed := "/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.el9_6.x86_64"
	if f := run(rt{fixed, "17.0.21+9-LTS", rh, false, nil}); f.Status != Fixed || !strings.Contains(f.Reason, "Red Hat") || f.Fix != "" {
		t.Errorf("listed build: %s (%s) fix %q", f.Status, f.Reason, f.Fix)
	}
	if f := run(rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-3.el9_6.x86_64", "17.0.21+9-LTS", rh, false, nil}); f.Status != Fixed {
		t.Errorf("later build: %s (%s)", f.Status, f.Reason)
	}
	// A mitigated runtime of the fixed build is fixed too.
	if f := run(rt{fixed, "17.0.21+9-LTS", rh, false, []string{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"}}); f.Status != Fixed || f.Mitigation != "" {
		t.Errorf("mitigated fixed build: %s (%s)", f.Status, f.Reason)
	}
	// What the install path alone must not clear: the path names the fixed
	// build, but the VM library or the release file does not confirm it.
	for _, c := range []struct {
		name string
		rt   rt
	}{
		{"another vendor's library under a later release", rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-99.el9_6.x86_64", "17.0.21+9", "Eclipse Adoptium", false, nil}},
		{"no release-file vendor", rt{fixed, "17.0.21+9-LTS", "", false, nil}},
		{"another build", rt{fixed, "17.0.21+5-LTS", rh, false, nil}},
		{"another update", rt{fixed, "17.0.21.0.3+1-LTS", rh, false, nil}},
		{"pre-release", rt{fixed, "17.0.21-ea+9", rh, false, nil}},
		{"self-built", rt{fixed, "17.0.21-internal+0-adhoc.root.src", rh, false, nil}},
		{"GraalVM", rt{fixed, "17.0.21+9-jvmci-23.0-b12", rh, false, nil}},
		{"version from the release file only", rt{fixed, "17.0.21+9-LTS", rh, true, nil}},
		{"a later update the row does not cover", rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.1.1-1.el9_6.x86_64", "17.0.21.1+1-LTS", rh, false, nil}},
		{"another stream", rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-9.el9_7.x86_64", "17.0.21+9-LTS", rh, false, nil}},
		{"RHEL 8", rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-9.el8.x86_64", "17.0.21+9-LTS", rh, false, nil}},
		{"Oracle Linux", rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.0.1.el9_6.x86_64", "17.0.21+9-LTS", "Oracle Corporation", false, nil}},
		{"Fedora", rt{"/usr/lib/jvm/java-17-openjdk-17.0.21.0.9-9.fc41.x86_64", "17.0.21+9", rh, false, nil}},
	} {
		if f := run(c.rt); f.Status == Fixed || f.Status == NotAffected {
			t.Errorf("%s: cleared: %s (%s)", c.name, f.Status, f.Reason)
		}
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
