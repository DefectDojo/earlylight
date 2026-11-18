package java4shell_test

import (
	"bytes"
	"github.com/DefectDojo/earlylight/detectors/java4shell"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/cli"
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

// CVSS: the OpenJDK advisory and Oracle score CVE-2026-114938 8.1; that is
// the primary score (Calif's 9.2 and Red Hat's 9.8 are in FACTS.md). The
// two advisories are linked now that they have been read.
func TestManifestScoreAndLinks(t *testing.T) {
	m := (&java4shell.Detector{}).Manifest()
	for _, k := range m.Kinds {
		if k.SecuritySeverity == "9.2" || k.SecuritySeverity == "9.8" {
			t.Errorf("kind %s scores %s, want the OpenJDK/Oracle 8.1", k.ID, k.SecuritySeverity)
		}
		if k.Level == "error" && k.SecuritySeverity != "8.1" {
			t.Errorf("kind %s scores %q", k.ID, k.SecuritySeverity)
		}
	}
	links := strings.Join(m.Advisories, " ")
	for _, u := range []string{"https://openjdk.org/groups/vulnerability/advisories/2026-11-17", "https://www.oracle.com/security-alerts/cspunov2026.html"} {
		if !strings.Contains(links, u) {
			t.Errorf("advisory %s not linked", u)
		}
	}
	if !strings.Contains(m.Kinds[0].Description, "GraalVM") {
		t.Error("the runtime kind does not say GraalVM is affected")
	}
}

// A Red Hat row clears an installed runtime only on RHEL: the os-release
// is read from the target.
func TestRedHatRowNeedsRHEL(t *testing.T) {
	saved := knowledge.RedHatFixed
	t.Cleanup(func() { knowledge.RedHatFixed = saved })
	knowledge.RedHatFixed = []knowledge.RedHatFix{{Package: "java-17-openjdk", Dist: "el9_6", EVR: "1:17.0.21.0.9-2.el9_6", Advisory: "RHSA-2026:0000"}}
	for id, want := range map[string]engine.Verdict{"rhel": engine.Fixed, "rocky": engine.Unknown} {
		root := t.TempDir()
		const dir = "usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.el9_6.x86_64"
		write(t, root, dir+"/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "17.0.21+9-LTS", VBMI: true}))
		write(t, root, dir+"/release", testlib.Release("IMPLEMENTOR", "Red Hat, Inc.", "JAVA_RUNTIME_VERSION", "17.0.21+9-LTS", "JAVA_VERSION", "17.0.21"))
		write(t, root, "etc/os-release", []byte("NAME=x\nID=\""+id+"\"\nVERSION_ID=\"9.6\"\n"))
		r, _ := run(t, "scan", "fs", "--as-root", root)
		if f := byPath(r)["/"+dir]; f.Verdict != want {
			t.Errorf("ID=%s: %s, want %s (%s)", id, f.Verdict, want, f.Reason)
		}
	}
}

// Final review B7: fix says what it could not check and does not exit 0
// over it: findings the scan reports as unknown are printed as not checked.
func TestFixPrintsUnknowns(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"packages it cannot read": {"Dockerfile": "FROM debian\nRUN apt-get install -y zulu21-jdk\nRUN rpm -i https://example.com/dl/jdk.rpm\n"},
		"an Enforcer floor":       {"pom.xml": "<project><build><plugins><plugin><configuration><rules>\n<requireJavaVersion><version>[17.0.6,)</version></requireJavaVersion>\n</rules></configuration></plugin></plugins></build></project>\n"},
	} {
		root := t.TempDir()
		for rel, body := range files {
			write(t, root, rel, []byte(body))
		}
		var out, errb bytes.Buffer
		code := cli.Run(cfg, []string{"fix", "--detector", "java4shell", "--dry-run", "--offline", root}, &out, &errb)
		if code != 1 || !strings.Contains(out.String(), "not checked") {
			t.Errorf("%s: exit %d, output %q %q", name, code, out.String(), errb.String())
		}
	}
}
