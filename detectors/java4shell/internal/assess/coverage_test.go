package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
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
