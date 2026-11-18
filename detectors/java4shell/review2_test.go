package java4shell_test

import (
	"fmt"
	"strings"
	"testing"

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
