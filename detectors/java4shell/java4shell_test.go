package java4shell_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/cli"
	"github.com/DefectDojo/earlylight/internal/engine"
)

var cfg = cli.Config{Tool: "earlylight", Version: "test", Summary: "test"}

func write(t *testing.T, root, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

type report struct {
	Targets []struct {
		Error       string           `json:"error"`
		Findings    []engine.Finding `json:"findings"`
		Annotations map[string]any   `json:"annotations"`
	} `json:"targets"`
}

func run(t *testing.T, args ...string) (report, int) {
	t.Helper()
	var out, errb bytes.Buffer
	full := append([]string{args[0], args[1], "--format", "json", "--detector", "java4shell", "--show-cleared"}, args[2:]...)
	code := cli.Run(cfg, full, &out, &errb)
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errb.String())
	}
	return r, code
}

func byPath(r report) map[string]engine.Finding {
	m := map[string]engine.Finding{}
	for _, f := range r.Targets[0].Findings {
		m[f.Path] = f
	}
	return m
}

func TestScanFS(t *testing.T) {
	root := t.TempDir()
	write(t, root, "opt/java/openjdk/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}))
	write(t, root, "opt/java/openjdk/release", testlib.Release("JAVA_VERSION", "21.0.13", "IMPLEMENTOR", "Eclipse Adoptium", "OS_ARCH", "x86_64"))
	write(t, root, "opt/fixed/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "25.0.5.1+2-LTS", VBMI: true}))
	write(t, root, "opt/arm/lib/server/libjvm.so", testlib.Build(testlib.Lib{Machine: "aarch64", Version: "21.0.13+9-LTS"}))
	write(t, root, "opt/atlassian/confluence/jre/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "17.0.12+7", VBMI: true}))
	write(t, root, "opt/atlassian/confluence/bin/setenv.sh", []byte("CATALINA_OPTS=\"-XX:-UseBASE64Intrinsics ${CATALINA_OPTS}\"\n"))
	write(t, root, "var/log/app/hs_err_pid42.log", []byte("# JRE version: OpenJDK Runtime Environment (21.0.13+9) (build 21.0.13+9-LTS)\n# Problematic frame:\n# v  ~StubRoutines::decodeBlock\nCPU: total 8, avx512f, avx512bw, avx512_vbmi, bmi2\n"))
	r, code := run(t, "scan", "fs", "--as-root", root)
	if r.Targets[0].Error != "" {
		t.Fatal(r.Targets[0].Error)
	}
	fs := byPath(r)
	if f := fs["/opt/java/openjdk"]; f.Kind != java4shell.KindRuntime || f.Verdict != engine.Vulnerable || f.Facts["vendor"] != "Eclipse Adoptium" || f.Facts["fixed_in"] != "21.0.13.1" {
		t.Errorf("temurin: %+v", f)
	}
	if f := fs["/opt/fixed"]; f.Verdict != engine.Fixed || f.Facts["status"] != "fixed" {
		t.Errorf("fixed: %+v", f)
	}
	if f := fs["/opt/arm"]; f.Verdict != engine.Fixed || f.Facts["status"] != "not-affected" || !strings.Contains(f.Reason, "aarch64") {
		t.Errorf("arm: %+v", f)
	}
	if f := fs["/opt/atlassian/confluence/jre"]; f.Kind != java4shell.KindBundled || f.Verdict != engine.Vulnerable || f.Facts["status"] != "mitigated" || f.Fix == "" {
		t.Errorf("confluence: %+v", f)
	}
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if _, ok := r.Targets[0].Annotations["java4shell_crash_logs"]; !ok {
		t.Error("crash log not annotated")
	}
	if _, ok := r.Targets[0].Annotations["java4shell_scanner_cpu"]; !ok {
		t.Error("scanner CPU not annotated")
	}
}

func TestHostileFS(t *testing.T) {
	root := t.TempDir()
	// A huge release file claiming a fixed version, next to an unfixed VM.
	write(t, root, "opt/a/lib/server/libjvm.so", testlib.Build(testlib.Lib{}))
	write(t, root, "opt/a/release", append([]byte("JAVA_VERSION=\"21.0.13.1\"\n"), bytes.Repeat([]byte("# padding\n"), 20000)...))
	// A forged small release file: the VM library decides.
	write(t, root, "opt/b/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9", VBMI: true}))
	write(t, root, "opt/b/release", testlib.Release("JAVA_VERSION", "21.0.13.1"))
	// Symlink loops around a runtime.
	if err := os.Symlink("loop2", filepath.Join(root, "opt/loop1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop1", filepath.Join(root, "opt/loop2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".", filepath.Join(root, "opt/b/lib/self")); err != nil {
		t.Fatal(err)
	}
	r, _ := run(t, "scan", "fs", "--as-root", root)
	fs := byPath(r)
	if f := fs["/opt/a"]; f.Verdict != engine.Unknown || !strings.Contains(f.Reason, "64 KiB") {
		t.Errorf("huge release: %+v", f)
	}
	if f := fs["/opt/b"]; f.Verdict != engine.Vulnerable || f.Facts["release_file_version"] != "21.0.13.1" {
		t.Errorf("forged release: %+v", f)
	}
	if len(fs) != 2 {
		t.Errorf("findings: %+v", fs)
	}
}

func TestNoJava(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/hostname", []byte("x\n"))
	r, code := run(t, "scan", "fs", "--as-root", root)
	if len(r.Targets[0].Findings) != 0 || code != 0 {
		t.Errorf("findings without Java: %+v (exit %d)", r.Targets[0].Findings, code)
	}
}

func TestManifest(t *testing.T) {
	d := &java4shell.Detector{}
	if err := d.Load(); err != nil {
		t.Fatal(err)
	}
	m := d.Manifest()
	seen := map[string]bool{}
	for _, k := range m.Kinds {
		if seen[k.ID] {
			t.Errorf("duplicate kind %s", k.ID)
		}
		seen[k.ID] = true
	}
	for _, k := range []string{java4shell.KindRuntime, java4shell.KindBundled, java4shell.KindImage, java4shell.KindImagePin, java4shell.KindJavaPin, java4shell.KindLine, java4shell.KindPackage, java4shell.KindNotChecked} {
		if !seen[k] {
			t.Errorf("kind %s not in the manifest", k)
		}
	}
}
