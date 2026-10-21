package php2shell_test

// php2shell-scan's command-line contract, run through the engine's shared
// command line as the thin php2shell-scan binary.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell"
	"github.com/DefectDojo/earlylight/internal/cli"
)

var thin = cli.Config{Tool: "php2shell-scan", Version: "test", Detector: php2shell.ID, Summary: "test", AsRootDir: true, ErrorsFirst: true}

// fakePHP is an ELF file carrying the two strings every PHP build compiles in.
func fakePHP(version, zend string) []byte {
	var b bytes.Buffer
	b.WriteString("\x7fELF\x02\x01\x01\x00")
	b.Write(make([]byte, 64))
	b.WriteString("X-Powered-By: PHP/" + version + "\x00")
	b.WriteString("Zend Engine v" + zend + ", Copyright (c) Zend Technologies\x00")
	return b.Bytes()
}

func write(t *testing.T, root, p string, data []byte) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func scan(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(thin, append(args[:1:1], append([]string{"--format", "json"}, args[1:]...)...), &out, &errb)
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil && code != 2 {
		t.Fatalf("%v: no JSON (exit %d): %s %s", args, code, out.String(), errb.String())
	}
	return code, doc
}

func TestUnpackagedReleaseVerdicts(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/local/sbin/php-fpm", fakePHP("8.3.35", "4.3.35"))
	write(t, root, "usr/local/bin/php", fakePHP("8.3.36", "4.3.36"))
	code, doc := scan(t, "fs", "--as-root", root, root)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	got := map[string]string{}
	for _, f := range doc["targets"].([]any)[0].(map[string]any)["findings"].([]any) {
		m := f.(map[string]any)
		got[m["path"].(string)] = m["verdict"].(string) + "/" + m["kind"].(string)
	}
	if got["/usr/local/sbin/php-fpm"] != "vulnerable/php-runtime-web" || got["/usr/local/bin/php"] != "fixed/php-runtime-cli" {
		t.Fatalf("verdicts %v", got)
	}
}

// A file whose Zend version disagrees with its PHP version is not trusted.
func TestForgedBannerIsUnknown(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/bin/php", fakePHP("8.3.36", "4.2.0"))
	if code, _ := scan(t, "fs", "--as-root", root, root); code != 3 {
		t.Fatalf("exit %d, want 3 (unknown)", code)
	}
}

// php2shell-scan's exit order: an error wins over a vulnerable finding, and
// --exit-zero wins over findings but not over errors.
func TestExitOrder(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/local/bin/php", fakePHP("8.3.35", "4.3.35"))
	if code, _ := scan(t, "fs", "--as-root", root, root, filepath.Join(root, "missing")); code != 2 {
		t.Errorf("vulnerable + error: exit %d, want 2", code)
	}
	if code, _ := scan(t, "fs", "--exit-zero", "--as-root", root, root); code != 0 {
		t.Errorf("--exit-zero: exit %d, want 0", code)
	}
	clean := t.TempDir()
	write(t, clean, "readme.txt", []byte("hi"))
	if code, _ := scan(t, "fs", "--as-root", clean, clean); code != 0 {
		t.Errorf("no PHP: exit %d, want 0", code)
	}
}

// A scan below the system root reports paths inside the root and reads the
// root's package databases (here, only its os-release).
func TestSubdirectoryBelowRoot(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/local/bin/php", fakePHP("8.2.34", "4.2.34"))
	write(t, root, "etc/os-release", []byte("ID=debian\nVERSION_ID=\"12\"\n"))
	code, doc := scan(t, "fs", "--as-root", root, filepath.Join(root, "usr/local/bin"))
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	tg := doc["targets"].([]any)[0].(map[string]any)
	f := tg["findings"].([]any)[0].(map[string]any)
	if f["path"] != "/usr/local/bin/php" {
		t.Errorf("path %v, want it inside the root", f["path"])
	}
	if os, _ := tg["annotations"].(map[string]any)["os"].(map[string]any); os == nil || os["id"] != "debian" {
		t.Errorf("os-release from the root not read: %v", tg["annotations"])
	}
	if code, _ := scan(t, "fs", "--as-root", filepath.Join(root, "usr"), root); code != 2 {
		t.Errorf("path outside the root: exit %d, want 2", code)
	}
}

func TestUsageNamesPHPModes(t *testing.T) {
	var out, errb bytes.Buffer
	cli.Run(thin, nil, &out, &errb)
	for _, want := range []string{"php2shell-scan repo", "php2shell-scan fix", "--as-root DIR", "--offline"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("usage missing %q", want)
		}
	}
	if strings.Contains(errb.String(), "php2shell-scan host") {
		t.Errorf("php2shell-scan does not scan hosts but its usage says so")
	}
}
