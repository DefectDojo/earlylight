package java4shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Second final review: the VM library is the file a runtime's verdict is
// made of. One the scan met and did not read (over --max-file-size,
// unreadable, named twice in one image layer) makes its runtime unknown:
// never nothing, and never fixed on the word of a library beside it.
func TestUnreadLibraryMakesTheRuntimeUnknown(t *testing.T) {
	fixed := testlib.Build(testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true})
	vuln := testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})
	big := testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true, Extra: strings.Repeat("x", 8192)})
	tree := func(files map[string][]byte) string {
		root := t.TempDir()
		for rel, data := range files {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	scan := func(root string, max int64) engine.Target {
		return *engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true, MaxFileSize: max})
	}
	verdicts := func(tg engine.Target) string {
		var out []string
		for _, f := range tg.Findings {
			out = append(out, f.Path+" "+string(f.Verdict))
		}
		return strings.Join(out, ", ")
	}

	// Over --max-file-size beside a fixed library.
	root := tree(map[string][]byte{"opt/jdk/lib/server/libjvm.so": fixed, "opt/jdk/lib/client/libjvm.so": big})
	if got := verdicts(scan(root, 4096)); got != "/opt/jdk unknown" {
		t.Errorf("an over-limit client library beside a fixed server library: %q, want /opt/jdk unknown", got)
	}
	if got := verdicts(scan(root, 0)); got != "/opt/jdk vulnerable" {
		t.Errorf("the same read in full: %q, want /opt/jdk vulnerable", got)
	}
	// Beside a vulnerable library the verdict stands.
	root = tree(map[string][]byte{"opt/jdk/lib/server/libjvm.so": vuln, "opt/jdk/lib/client/libjvm.so": big})
	if got := verdicts(scan(root, 4096)); got != "/opt/jdk vulnerable" {
		t.Errorf("an over-limit client library beside a vulnerable server library: %q", got)
	}
	// The only library of the runtime, and another runtime read in full.
	root = tree(map[string][]byte{"opt/jdk/lib/server/libjvm.so": big, "opt/jdk/release": testlib.Release("JAVA_VERSION", "21.0.13.1"), "opt/other/lib/server/libjvm.so": fixed})
	if got := verdicts(scan(root, 4096)); got != "/opt/jdk unknown, /opt/other fixed" {
		t.Errorf("the only library over the limit: %q, want /opt/jdk unknown, /opt/other fixed", got)
	}
	// Unreadable (not as root, which can read it).
	if os.Geteuid() != 0 {
		root = tree(map[string][]byte{"opt/jdk/lib/server/libjvm.so": fixed, "opt/jdk/lib/client/libjvm.so": vuln})
		if err := os.Chmod(filepath.Join(root, "opt/jdk/lib/client/libjvm.so"), 0); err != nil {
			t.Fatal(err)
		}
		if got := verdicts(scan(root, 0)); got != "/opt/jdk unknown" {
			t.Errorf("an unreadable client library beside a fixed server library: %q, want /opt/jdk unknown", got)
		}
	}
	// A docker export that names the library again, read: the last entry
	// is the file and nothing is left unread.
	exp := exportOf(t, tarEntry{name: "opt/jdk/lib/server/libjvm.so", data: fixed}, tarEntry{name: "opt/jdk/lib/client/libjvm.so", data: big}, tarEntry{name: "opt/jdk/lib/client/libjvm.so", data: fixed})
	tg := engine.ScanImage([]engine.Detector{&Detector{}}, exp, engine.Options{MaxFileSize: 4096})
	if got := verdicts(*tg); got != "/opt/jdk fixed" {
		t.Errorf("an over-limit library named again and read: %q, want /opt/jdk fixed", got)
	}
}
