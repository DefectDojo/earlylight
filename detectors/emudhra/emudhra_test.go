package emudhra_test

// These are emudhra-scan's command-line tests, run through the engine's shared
// command line twice: as the thin emudhra-scan binary and as the engine with
// --detector emudhra. Both must behave exactly as emudhra-scan did.

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/emudhra"
	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/knowledge"
	"github.com/DefectDojo/earlylight/internal/cli"
)

var (
	thin   = cli.Config{Tool: "emudhra-scan", Version: "test", Detector: emudhra.ID, Summary: "test"}
	engine = cli.Config{Tool: "earlylight", Version: "test", Summary: "test"}
)

// run runs args through both binaries and fails the test if they disagree.
func run(t *testing.T, args []string, out *bytes.Buffer) int {
	t.Helper()
	var o1, e1, o2, e2 bytes.Buffer
	a := cli.Run(thin, args, &o1, &e1)
	eargs := args
	if len(args) > 0 {
		eargs = append([]string{"scan", args[0], "--detector", emudhra.ID}, args[1:]...)
	}
	b := cli.Run(engine, eargs, &o2, &e2)
	if len(args) > 0 && a != b {
		t.Errorf("%v: emudhra-scan exit %d, engine exit %d (%s | %s)", args, a, b, e1.String(), e2.String())
	}
	if out != nil {
		out.Write(o1.Bytes())
	}
	return a
}

func g3Bundle(t *testing.T) string {
	t.Helper()
	kb, err := knowledge.Load()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, k := range kb.Keys {
		if k.Name == "emSign ECC Root CA - G3" {
			p := filepath.Join(dir, "cacert.pem")
			if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.Certs[0].Raw}), 0o600); err != nil {
				t.Fatal(err)
			}
			return dir
		}
	}
	t.Fatal("no G3")
	return ""
}

func TestExitCodes(t *testing.T) {
	bad := g3Bundle(t)
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "readme.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"fs", bad}, 1},
		{[]string{"fs", "--exit-zero", bad}, 0},
		{[]string{"fs", clean}, 0},
		{[]string{"fs", "/definitely/not/here"}, 2},
		{[]string{"fs", "--exit-zero", "/definitely/not/here"}, 2},
		{[]string{"fs", bad, "/definitely/not/here"}, 1},
		{[]string{"nope", clean}, 2},
		{[]string{"fs", empty}, 2}, // nothing scanned is an error, never OK
		{nil, 2},
	}
	for _, c := range cases {
		if got := run(t, c.args, nil); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.args, got, c.want)
		}
	}
}

func TestSARIFIsRepoRelative(t *testing.T) {
	bad := g3Bundle(t)
	var out bytes.Buffer
	run(t, []string{"fs", "--format", "sarif", "--exit-zero", bad}, &out)
	if !bytes.Contains(out.Bytes(), []byte(`"uri": "cacert.pem"`)) {
		t.Fatalf("SARIF URI not relative to the scanned root:\n%s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(`"ruleId": "emudhra/path-root"`)) {
		t.Fatalf("SARIF rule ID is not <detector>/<kind>:\n%s", out.String())
	}
}

// A symlinked root (macOS /etc -> /private/etc, merged-usr /lib) must be followed.
func TestSymlinkedRoot(t *testing.T) {
	bad := g3Bundle(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(bad, link); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if got := run(t, []string{"fs", link}, &out); got != 1 {
		t.Fatalf("exit %d: %s", got, out.String())
	}
}

// Paths are real absolute paths unless --as-root, so location rules still apply
// when scanning a subdirectory.
func TestAbsolutePathsAndAsRoot(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "usr/share/ca-certificates/mozilla")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := g3Bundle(t)
	b, _ := os.ReadFile(filepath.Join(bad, "cacert.pem"))
	os.WriteFile(filepath.Join(src, "emSign_ECC_Root_CA_-_G3.crt"), b, 0o600)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/ca-certificates.conf"), []byte("!mozilla/emSign_ECC_Root_CA_-_G3.crt\n"), 0o600)
	var out bytes.Buffer
	// As a system root: the source cert is disabled by the conf, so nothing active.
	if got := run(t, []string{"fs", "--as-root", root}, &out); got != 0 {
		t.Fatalf("--as-root: exit %d\n%s", got, out.String())
	}
	// As a plain directory the conf is not this system's, so the file stays active.
	out.Reset()
	if got := run(t, []string{"fs", root}, &out); got != 1 {
		t.Fatalf("plain: exit %d\n%s", got, out.String())
	}
}

func TestSARIFAlwaysValidShape(t *testing.T) {
	clean := t.TempDir()
	os.WriteFile(filepath.Join(clean, "x"), []byte("x"), 0o600)
	var out bytes.Buffer
	run(t, []string{"fs", "--format", "sarif", clean, "/definitely/not/here"}, &out)
	for _, want := range []string{`"results": []`, `"executionSuccessful": false`, `"toolExecutionNotifications"`} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Errorf("missing %s in\n%s", want, out.String())
		}
	}
}

// Cleared findings are hidden by default and shown with either flag name.
func TestShowInactiveAlias(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/pki/ca-trust/source/blocklist")
	os.MkdirAll(dir, 0o755)
	b, _ := os.ReadFile(filepath.Join(g3Bundle(t), "cacert.pem"))
	os.WriteFile(filepath.Join(dir, "g3.pem"), b, 0o600)
	for _, flag := range []string{"--show-inactive", "--show-cleared"} {
		var out bytes.Buffer
		if got := run(t, []string{"fs", "--as-root", flag, root}, &out); got != 0 {
			t.Fatalf("%s: exit %d\n%s", flag, got, out.String())
		}
		if !bytes.Contains(out.Bytes(), []byte("[inactive  ]")) {
			t.Errorf("%s did not list the inactive finding:\n%s", flag, out.String())
		}
	}
}
