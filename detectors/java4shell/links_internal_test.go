package java4shell

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// tarEntry is one entry of a docker export: a file, a symbolic link (link)
// or a hard link (hard).
type tarEntry struct {
	name string
	data []byte
	link string
	hard bool
}

func exportOf(t *testing.T, es ...tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
		if e.link != "" {
			h.Typeflag, h.Linkname = tar.TypeSymlink, e.link
			if e.hard {
				h.Typeflag = tar.TypeLink
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write(e.data)
	}
	tw.Close()
	p := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return "rootfs:" + p
}

// Final review B2: a VM library that is a link to a file with another name
// is never read under its own name, so the scan cannot judge the runtime.
// It says so: the runtime is unknown, not absent.
func TestLibraryThatIsALink(t *testing.T) {
	vuln := testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})
	fixed := testlib.Build(testlib.Lib{Version: "21.0.13.1+2-LTS", VBMI: true})
	const lib = "opt/jdk/lib/server/libjvm.so"
	for _, c := range []struct {
		name    string
		entries []tarEntry
		want    string // path verdict, ...
	}{
		{"a hard link to another name", []tarEntry{{name: "opt/jdk/lib/server/hotspot.bin", data: vuln}, {name: lib, link: "opt/jdk/lib/server/hotspot.bin", hard: true}}, "/opt/jdk unknown"},
		{"a symbolic link to another name", []tarEntry{{name: "opt/jdk/lib/server/libjvm.so.21", data: vuln}, {name: lib, link: "libjvm.so.21"}}, "/opt/jdk unknown"},
		{"an object store", []tarEntry{{name: "sysroot/ostree/repo/objects/ab/cdef.file", data: vuln}, {name: "usr/lib/jvm/java-21/lib/server/libjvm.so", link: "sysroot/ostree/repo/objects/ab/cdef.file", hard: true}},
			"/usr/lib/jvm/java-21 unknown"},
		{"beside a fixed library", []tarEntry{{name: lib, data: fixed}, {name: "opt/jdk/lib/minimal/real", data: vuln}, {name: "opt/jdk/lib/minimal/libjvm.so", link: "real"}}, "/opt/jdk unknown"},
		{"beside a vulnerable library", []tarEntry{{name: lib, data: vuln}, {name: "opt/jdk/lib/minimal/real", data: fixed}, {name: "opt/jdk/lib/minimal/libjvm.so", link: "real"}}, "/opt/jdk vulnerable"},
		// A link to a library that is read under its own name is judged there.
		{"a hard link to a library", []tarEntry{{name: lib, data: vuln}, {name: "opt/copy/lib/server/libjvm.so", link: lib, hard: true}}, "/opt/jdk vulnerable"},
		{"a symbolic link to a library", []tarEntry{{name: lib, data: vuln}, {name: "opt/jdk/lib/libjvm.so", link: "server/libjvm.so"}}, "/opt/jdk vulnerable"},
		// A link to nothing is no runtime.
		{"a dangling link", []tarEntry{{name: "etc/hostname", data: []byte("x")}, {name: lib, link: "missing.so"}}, ""},
	} {
		tg := engine.ScanImage([]engine.Detector{&Detector{}}, exportOf(t, c.entries...), engine.Options{})
		var got []string
		for _, f := range tg.Findings {
			got = append(got, f.Path+" "+string(f.Verdict))
		}
		if tg.Error != "" || strings.Join(got, ", ") != c.want {
			t.Errorf("%s: error %q findings [%s], want [%s]", c.name, tg.Error, strings.Join(got, ", "), c.want)
		}
	}

	// On a filesystem, where a hard link is a file read under each name,
	// only the symbolic link is not followed.
	root := t.TempDir()
	dir := filepath.Join(root, "opt/jdk/lib/server")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "libjvm.so.21"), vuln, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libjvm.so.21", filepath.Join(dir, "libjvm.so")); err != nil {
		t.Fatal(err)
	}
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
	if len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Unknown || tg.Findings[0].Path != "/opt/jdk" || !strings.Contains(tg.Findings[0].Reason, "libjvm.so.21") {
		t.Errorf("filesystem: %+v", tg.Findings)
	}
}

// Final review B4: past the cap on VM libraries a runtime is dropped
// unjudged, so the scan is capped like any other: nothing is cleared, and
// the target carries a problem.
func TestLibraryCapClearsNothing(t *testing.T) {
	root := t.TempDir()
	other := testlib.Build(testlib.Lib{Machine: "aarch64", Version: "21.0.13+9-LTS"})
	for i := 0; i < maxLibs; i++ {
		p := filepath.Join(root, "a", fmt.Sprintf("%04d", i), "lib/server/libjvm.so")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, other, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(root, "opt/jdk/lib/server/libjvm.so")
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}), 0o644); err != nil {
		t.Fatal(err)
	}
	tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
	if len(tg.Findings) != maxLibs || tg.Count(engine.Fixed) != 0 || tg.Count(engine.Unknown) != maxLibs {
		t.Errorf("%d findings, %d cleared, %d unknown", len(tg.Findings), tg.Count(engine.Fixed), tg.Count(engine.Unknown))
	}
	if len(tg.Problems) != 1 || !strings.Contains(tg.Problems[0], "Java VM libraries") || tg.Gaps() != 1 {
		t.Errorf("problems %v gaps %d", tg.Problems, tg.Gaps())
	}
}
