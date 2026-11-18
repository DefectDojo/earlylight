package java4shell_test

import (
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
