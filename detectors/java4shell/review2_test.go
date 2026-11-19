package java4shell_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Review finding 3: a mitigated runtime stays on the list (vulnerable, with
// the mitigation as a fact) and the scan exits 1.
func TestMitigatedIsNotCleared(t *testing.T) {
	root := t.TempDir()
	write(t, root, "opt/atlassian/jira/jre/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}))
	write(t, root, "opt/atlassian/jira/bin/setenv.sh", []byte("JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\n"))
	r, code := run(t, "scan", "fs", "--as-root", root)
	f := byPath(r)["/opt/atlassian/jira/jre"]
	if f.Verdict != engine.Vulnerable || f.Facts["status"] != "mitigated" || f.Facts["mitigation"] == "" || code != 1 {
		t.Errorf("mitigated: %s %q exit %d", f.Verdict, f.Facts["status"], code)
	}
}

// Review finding 7: what a target makes the detector keep is capped, and
// a capped scan clears nothing.
func TestKeptCaps(t *testing.T) {
	root := t.TempDir()
	write(t, root, "opt/fixed/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true}))
	for i := 0; i < 600; i++ {
		write(t, root, fmt.Sprintf("var/lib/dpkg/info/openjdk-%d.list", i), []byte("/usr/lib/jvm/x/lib/server/libjvm.so\n"))
	}
	r, _ := run(t, "scan", "fs", "--as-root", root)
	f := byPath(r)["/opt/fixed"]
	if f.Verdict != engine.Unknown || !strings.Contains(f.Reason, "limit") {
		t.Errorf("capped scan: %s (%s)", f.Verdict, f.Reason)
	}
}

// Review findings 14 and round-2 5: a JDK download in the target is
// recorded by name as context, without reading it and without counting it
// as a file not scanned; other archives are not.
func TestJDKArchiveRecorded(t *testing.T) {
	root := t.TempDir()
	zipHead := []byte("PK\x03\x04")
	write(t, root, "opt/OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz", []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"))
	write(t, root, "opt/amazon-corretto-21-x64-linux-jdk.tar.gz", []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"))
	write(t, root, "docs/openjdk-migration-notes.zip", zipHead)
	write(t, root, "docs/majreport-2026.zip", zipHead)
	r, code := run(t, "scan", "fs", "--fail-on-skip", "--as-root", root)
	got, _ := json.Marshal(r.Targets[0].Annotations["java4shell_runtime_archives"])
	if !strings.Contains(string(got), "OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz") || !strings.Contains(string(got), "amazon-corretto-21-x64-linux-jdk.tar.gz") {
		t.Errorf("runtime downloads not recorded: %s", got)
	}
	if strings.Contains(string(got), "migration") || strings.Contains(string(got), "majreport") {
		t.Errorf("other archives recorded: %s", got)
	}
	if code != 0 {
		t.Errorf("exit %d: a recorded download counted as a file not scanned", code)
	}
	if (&java4shell.Detector{}).Wants("/opt/OpenJDK21U-jre_x64_linux_hotspot_21.0.13_9.tar.gz", []byte("\x1f\x8b\x08"), false) {
		t.Error("a runtime download is read in full")
	}
}

// Round-2 finding 4: units that set no JVM option do not count toward the
// cap.
func TestPlainUnitsUncapped(t *testing.T) {
	root := t.TempDir()
	write(t, root, "opt/fixed/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true}))
	for i := 0; i < 4100; i++ {
		write(t, root, fmt.Sprintf("etc/systemd/system/s%d.service", i), []byte("[Service]\nExecStart=/usr/bin/true\n"))
	}
	r, code := run(t, "scan", "fs", "--as-root", root)
	if f := byPath(r)["/opt/fixed"]; f.Verdict != engine.Fixed || code != 0 {
		t.Errorf("plain units capped the scan: %s (%s) exit %d", f.Verdict, f.Reason, code)
	}
}

// A full /etc override without JVM options still replaces the /usr/lib
// unit that set them.
func TestEtcOverrideKept(t *testing.T) {
	root := t.TempDir()
	write(t, root, "opt/acme/jre/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}))
	write(t, root, "usr/lib/systemd/system/acme.service", []byte("[Service]\nEnvironment=JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nExecStart=/opt/acme/bin/run.sh\n"))
	write(t, root, "etc/systemd/system/acme.service", []byte("[Service]\nExecStart=/opt/acme/bin/run.sh\n"))
	r, _ := run(t, "scan", "fs", "--as-root", root)
	if f := byPath(r)["/opt/acme/jre"]; f.Facts["status"] == "mitigated" {
		t.Errorf("the /usr/lib unit's mitigation counted over the /etc override: %+v", f.Facts)
	}
}

// Round-2 nits: dates live in the knowledge package (the data date is
// knowledge.Checked), and reasons read cleanly.
func TestDatesInOnePlace(t *testing.T) {
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, "knowledge.go") || strings.Contains(p, "testlib") {
			return err
		}
		b, _ := os.ReadFile(p)
		if regexp.MustCompile(`"[^"\n]*2026-\d\d-\d\d`).Match(b) {
			t.Errorf("%s writes a date in a string; take it from the knowledge package", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
