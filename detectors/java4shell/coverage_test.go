package java4shell_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// A RHEL 9 / UBI 9 layout: the rpm's versioned directory, the jre-17 and
// alternatives symlinks that point into it, and /usr/bin/java through
// /etc/alternatives. One runtime, owned by the rpm its path names.
func TestRedHatLayout(t *testing.T) {
	root := t.TempDir()
	const dir = "usr/lib/jvm/java-17-openjdk-17.0.21.0.9-1.el9.x86_64"
	write(t, root, dir+"/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "17.0.21+9-LTS", VBMI: true}))
	write(t, root, dir+"/release", testlib.Release("IMPLEMENTOR", "Red Hat, Inc.", "JAVA_RUNTIME_VERSION", "17.0.21+9-LTS", "JAVA_VERSION", "17.0.21", "JAVA_VERSION_DATE", "2026-10-21"))
	write(t, root, dir+"/bin/java", []byte("#!fake\n"))
	for link, target := range map[string]string{
		"usr/lib/jvm/jre-17-openjdk": "java-17-openjdk-17.0.21.0.9-1.el9.x86_64",
		"usr/lib/jvm/jre-17":         "/etc/alternatives/jre_17",
		"usr/lib/jvm/jre":            "/etc/alternatives/jre",
		"etc/alternatives/jre_17":    "/" + dir,
		"etc/alternatives/jre":       "/" + dir,
		"etc/alternatives/java":      "/" + dir + "/bin/java",
		"usr/bin/java":               "/etc/alternatives/java",
		"usr/lib/jvm/java-17-openjdk-17.0.21.0.9-1.el9.x86_64/lib/server/libjvm-self": "libjvm.so",
	} {
		p := filepath.Join(root, link)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	r, _ := run(t, "scan", "fs", "--as-root", root)
	if r.Targets[0].Error != "" {
		t.Fatal(r.Targets[0].Error)
	}
	fs := byPath(r)
	if len(fs) != 1 {
		t.Fatalf("want one runtime, got %d: %+v", len(fs), fs)
	}
	f := fs["/"+dir]
	if f.Verdict != engine.Vulnerable || f.Facts["package"] != "java-17-openjdk-headless 17.0.21.0.9-1.el9" || f.Facts["vendor"] != "Red Hat, Inc." || f.Facts["version_from"] != "vm-library" {
		t.Errorf("RHEL runtime: %+v", f)
	}
	if !strings.Contains(f.Fix, "Red Hat had published no fixed") {
		t.Errorf("fix text: %s", f.Fix)
	}
}

// GraalVM CE 22.3.1 for Java 17, as its image lays it out (/graalvm with
// GRAALVM_VERSION in the release file).
func TestGraalVMLayout(t *testing.T) {
	root := t.TempDir()
	write(t, root, "graalvm/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "17.0.6+10-jvmci-22.3-b13", VBMI: true}))
	write(t, root, "graalvm/release", testlib.Release("IMPLEMENTOR", "GraalVM Community", "JAVA_VERSION", "17.0.6", "GRAALVM_VERSION", "22.3.1"))
	write(t, root, "opt/graalvm-25/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "25.0.5.1+2-LTS-jvmci-b01", VBMI: true}))
	r, _ := run(t, "scan", "fs", "--as-root", root)
	fs := byPath(r)
	if f := fs["/graalvm"]; f.Verdict != engine.Vulnerable || f.Facts["graalvm"] != "yes" || f.Facts["fixed_in"] != "" {
		t.Errorf("GraalVM 22.3.1: %+v", f)
	}
	if f := fs["/opt/graalvm-25"]; f.Verdict != engine.Unknown || !strings.Contains(f.Reason, "no fixed GraalVM build") {
		t.Errorf("GraalVM at the OpenJDK fix: %+v", f)
	}
}
