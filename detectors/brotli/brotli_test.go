package brotli_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/testbin"
	"github.com/DefectDojo/earlylight/internal/cli"
)

var cfg = cli.Config{Tool: "earlylight", Version: "test", Summary: "test"}

var decoder = []testbin.Symbol{{Name: "BrotliDecoderDecompressStream", Defined: true}}

func write(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func wheel(t *testing.T, member string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	w, err := z.Create(member)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	z.Close()
	return b.Bytes()
}

type report struct {
	Targets []struct {
		Findings []struct {
			Detector, Kind, Path, Verdict, Reason, Fix string
			Facts                                      map[string]string
		}
	}
}

func scan(t *testing.T, dir string, format string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(cfg, []string{"scan", "fs", "--detector", brotli.ID, "--format", format, dir}, &out, &errb)
	if errb.Len() > 0 && code == 2 {
		t.Fatalf("exit 2: %s", errb.String())
	}
	return code, out.String()
}

func TestScanFilesystem(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "usr/lib/libbrotlidec.so.1.0.9", testbin.ELF(decoder, testbin.Table("1.0.9")))
	write(t, dir, "usr/local/bin/node", testbin.Executable([]byte("nodejs.org/download/release/v24.22.1/node-v24.22.1-headers.tar.gz"), testbin.Table("1.2.1")))
	write(t, dir, "wheels/brotli-1.2.0-cp313-cp313-manylinux2014_x86_64.whl",
		wheel(t, "_brotli.cpython-313-x86_64-linux-gnu.so", testbin.Executable(testbin.Table("1.2.0"))))
	write(t, dir, "usr/bin/curl", testbin.ELF([]testbin.Symbol{{Name: "BrotliDecoderDecompressStream"}}, nil))
	write(t, dir, "notes.txt", []byte("\x00EXUBERANT_META_NIBBLE\x00"+string(testbin.Table("1.2.0"))))

	code, out := scan(t, dir, "json")
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	var r report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	real, err := filepath.EvalSymlinks(dir) // macOS reports /var/folders as /private/var/folders
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tg := range r.Targets {
		for _, f := range tg.Findings {
			rel := strings.TrimPrefix(strings.TrimPrefix(f.Path, filepath.ToSlash(real)), filepath.ToSlash(dir))
			got[rel] = f.Verdict + " " + f.Kind + " " + f.Facts["product"]
			if f.Detector != brotli.ID || f.Reason == "" {
				t.Errorf("%s: detector %q reason %q", rel, f.Detector, f.Reason)
			}
		}
	}
	want := map[string]string{
		"/usr/lib/libbrotlidec.so.1.0.9": "vulnerable decoder-library libbrotlidec",
		"/usr/local/bin/node":            "fixed bundled-decoder node",
		"/wheels/brotli-1.2.0-cp313-cp313-manylinux2014_x86_64.whl!/_brotli.cpython-313-x86_64-linux-gnu.so": "vulnerable bundled-decoder python-brotli",
	}
	if len(got) != len(want) {
		t.Errorf("findings %v, want %v", got, want)
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: got %q, want %q", p, got[p], w)
		}
	}
}

func TestSARIFRules(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "libbrotlidec.so.1", testbin.ELF(decoder, testbin.Table("1.1.0")))
	code, out := scan(t, dir, "sarif")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	for _, s := range []string{`"brotli/decoder-library"`, `"brotli/bundled-decoder"`, `"security-severity": "9.2"`, "CVE-2026-111497", "CWE-787"} {
		if !strings.Contains(out, s) {
			t.Errorf("SARIF has no %s", s)
		}
	}
}

func TestFixedOnlyExitsZero(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "libbrotlidec.so.1", testbin.ELF(decoder, testbin.Table("1.2.1")))
	if code, out := scan(t, dir, "text"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestUnknownExitsThree(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "usr/local/bin/envoy", testbin.Executable(testbin.DecoderTables(16)))
	if code, out := scan(t, dir, "text"); code != 3 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestListed(t *testing.T) {
	var out, errb bytes.Buffer
	if code := cli.Run(cfg, []string{"detectors"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), brotli.ID) || !strings.Contains(out.String(), "CVE-2026-111497") {
		t.Errorf("detectors list:\n%s", out.String())
	}
}
