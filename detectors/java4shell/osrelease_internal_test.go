package java4shell

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// A Red Hat row clears a runtime on the target's os-release (ID=rhel), so
// the os-release is a file a verdict is cleared on: an /etc/os-release the
// scan met and did not read (over its limit, unreadable) is not stood in
// for by /usr/lib/os-release, which the system reads only when
// /etc/os-release does not exist.
func TestRedHatRowNeedsOSReleaseRead(t *testing.T) {
	saved := knowledge.RedHatFixed
	t.Cleanup(func() { knowledge.RedHatFixed = saved })
	knowledge.RedHatFixed = []knowledge.RedHatFix{{Package: "java-17-openjdk", Dist: "el9_6", EVR: "1:17.0.21.0.9-2.el9_6", Advisory: "RHSA-2026:0000"}}

	const dir = "usr/lib/jvm/java-17-openjdk-17.0.21.0.9-2.el9_6.x86_64"
	lib := testlib.Build(testlib.Lib{Version: "17.0.21+9-LTS", VBMI: true})
	release := testlib.Release("IMPLEMENTOR", "Red Hat, Inc.", "JAVA_RUNTIME_VERSION", "17.0.21+9-LTS", "JAVA_VERSION", "17.0.21")
	rhel := []byte("ID=\"rhel\"\nVERSION_ID=\"9.6\"\n")
	rocky := []byte("ID=\"rocky\"\nVERSION_ID=\"9.6\"\n")
	big := append(append([]byte(nil), rocky...), bytes.Repeat([]byte("# pad\n"), maxOSRelease/6+1)...)

	type entry struct {
		name string
		data []byte
		link string // a symbolic link when set
	}
	for _, c := range []struct {
		name    string
		entries []entry
		want    engine.Verdict
		os      string // the java4shell_os annotation, which may fall back
	}{
		{"usr/lib alone, as RHEL lays it out", []entry{{"etc/os-release", nil, "../usr/lib/os-release"}, {"usr/lib/os-release", rhel, ""}}, engine.Fixed, "rhel 9.6"},
		{"etc read", []entry{{"etc/os-release", rhel, ""}, {"usr/lib/os-release", rocky, ""}}, engine.Fixed, "rhel 9.6"},
		{"etc over the limit", []entry{{"etc/os-release", big, ""}, {"usr/lib/os-release", rhel, ""}}, engine.Unknown, "rhel 9.6"},
		{"etc over the limit, named after usr/lib", []entry{{"usr/lib/os-release", rhel, ""}, {"etc/os-release", big, ""}}, engine.Unknown, "rhel 9.6"},
		{"etc read, then named again over the limit", []entry{{"etc/os-release", rhel, ""}, {"usr/lib/os-release", rhel, ""}, {"etc/os-release", big, ""}}, engine.Unknown, "rhel 9.6"},
		{"etc over the limit, then named again and read", []entry{{"etc/os-release", big, ""}, {"usr/lib/os-release", rocky, ""}, {"etc/os-release", rhel, ""}}, engine.Fixed, "rhel 9.6"},
		{"etc over the limit, then a link to usr/lib", []entry{{"etc/os-release", big, ""}, {"usr/lib/os-release", rhel, ""}, {"etc/os-release", nil, "../usr/lib/os-release"}}, engine.Fixed, "rhel 9.6"},
	} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range append([]entry{{dir + "/lib/server/libjvm.so", lib, ""}, {dir + "/release", release, ""}}, c.entries...) {
			h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
			if e.link != "" {
				h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.link, 0
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
		tg := engine.ScanImage([]engine.Detector{&Detector{}}, "rootfs:"+p, engine.Options{})
		if tg.Error != "" || len(tg.Findings) != 1 {
			t.Fatalf("%s: error %q findings %+v", c.name, tg.Error, tg.Findings)
		}
		if f := tg.Findings[0]; f.Verdict != c.want {
			t.Errorf("%s: %s, want %s (%s)", c.name, f.Verdict, c.want, f.Reason)
		}
		if got := tg.Annotations["java4shell_os"]; got != c.os {
			t.Errorf("%s: java4shell_os %v, want %s", c.name, got, c.os)
		}
	}

	// An /etc/os-release that could not be read (no permission, an I/O
	// error) is the same.
	s := (&Detector{}).NewScan(engine.Filesystem).(*scan)
	s.Visit(engine.File{Path: "/usr/lib/os-release", Data: rhel})
	s.VisitUnread("/etc/os-release", false)
	if id := s.osID(); id != "" {
		t.Errorf("unreadable /etc/os-release: os ID %q, want none", id)
	}
	s.Forget("/etc/os-release")
	if id := s.osID(); id != "rhel" {
		t.Errorf("after the unreadable /etc/os-release is forgotten: os ID %q, want rhel", id)
	}
	// An unread /usr/lib/os-release does not matter when /etc/os-release was read.
	s.Visit(engine.File{Path: "/etc/os-release", Data: rocky})
	s.Forget("/usr/lib/os-release")
	s.VisitOverLimit("/usr/lib/os-release", maxOSRelease+1)
	if id := s.osID(); id != "rocky" {
		t.Errorf("os ID %q, want rocky", id)
	}
}
