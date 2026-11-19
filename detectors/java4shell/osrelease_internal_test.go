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
		hard bool   // link is a hard link
	}
	for _, c := range []struct {
		name    string
		entries []entry
		want    engine.Verdict
		os      string // the java4shell_os annotation, which may fall back
	}{
		{"usr/lib alone, as RHEL lays it out", []entry{{"etc/os-release", nil, "../usr/lib/os-release", false}, {"usr/lib/os-release", rhel, "", false}}, engine.Fixed, "rhel 9.6"},
		{"etc read", []entry{{"etc/os-release", rhel, "", false}, {"usr/lib/os-release", rocky, "", false}}, engine.Fixed, "rhel 9.6"},
		{"etc over the limit", []entry{{"etc/os-release", big, "", false}, {"usr/lib/os-release", rhel, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc over the limit, named after usr/lib", []entry{{"usr/lib/os-release", rhel, "", false}, {"etc/os-release", big, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc read, then named again over the limit", []entry{{"etc/os-release", rhel, "", false}, {"usr/lib/os-release", rhel, "", false}, {"etc/os-release", big, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc over the limit, then named again and read", []entry{{"etc/os-release", big, "", false}, {"usr/lib/os-release", rocky, "", false}, {"etc/os-release", rhel, "", false}}, engine.Fixed, "rhel 9.6"},
		// Review: a file at /etc/os-release is the system's even without an
		// ID, and a link there to any other file is a file not read.
		{"etc empty", []entry{{"etc/os-release", nil, "", false}, {"usr/lib/os-release", rhel, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc without an ID", []entry{{"etc/os-release", []byte("NAME=x\n"), "", false}, {"usr/lib/os-release", rhel, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc a link to another file", []entry{{"etc/rocky-release-os", rocky, "", false}, {"etc/os-release", nil, "rocky-release-os", false}, {"usr/lib/os-release", rhel, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc a hard link to another file", []entry{{"etc/rocky-release-os", rocky, "", false}, {"etc/os-release", nil, "etc/rocky-release-os", true}, {"usr/lib/os-release", rhel, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc a hard link to usr/lib", []entry{{"usr/lib/os-release", rhel, "", false}, {"etc/os-release", nil, "usr/lib/os-release", true}}, engine.Fixed, "rhel 9.6"},
		{"usr/lib a hard link to etc", []entry{{"etc/os-release", rhel, "", false}, {"usr/lib/os-release", nil, "etc/os-release", true}}, engine.Fixed, "rhel 9.6"},
		{"etc a link through a linked directory", []entry{{"usr/etc/os-release", rocky, "", false}, {"etc", nil, "usr/etc", false}, {"usr/lib/os-release", rhel, "", false}}, engine.Unknown, "rhel 9.6"},
		{"etc over the limit, then a link to usr/lib", []entry{{"etc/os-release", big, "", false}, {"usr/lib/os-release", rhel, "", false}, {"etc/os-release", nil, "../usr/lib/os-release", false}}, engine.Fixed, "rhel 9.6"},
	} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range append([]entry{{dir + "/lib/server/libjvm.so", lib, "", false}, {dir + "/release", release, "", false}}, c.entries...) {
			h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}
			if e.link != "" {
				h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.link, 0
			}
			if e.hard {
				h.Typeflag = tar.TypeLink
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
	osID := func(s *scan) string {
		return s.osID(func(p string) bool { _, ok := s.kept[p]; return ok }, resolver{}, nil)
	}
	s := (&Detector{}).NewScan(engine.Filesystem).(*scan)
	s.Visit(engine.File{Path: "/usr/lib/os-release", Data: rhel})
	s.VisitUnread("/etc/os-release", false)
	if id := osID(s); id != "" {
		t.Errorf("unreadable /etc/os-release: os ID %q, want none", id)
	}
	s.Forget("/etc/os-release")
	if id := osID(s); id != "rhel" {
		t.Errorf("after the unreadable /etc/os-release is forgotten: os ID %q, want rhel", id)
	}
	// Nor is /usr/lib/os-release trusted when /etc could not be listed.
	for dir, want := range map[string]string{"/etc": "", "/": "", "/etc/": "", "/etc/ssh": "rhel", "/opt": "rhel"} {
		u := (&Detector{}).NewScan(engine.Filesystem).(*scan)
		u.Visit(engine.File{Path: "/usr/lib/os-release", Data: rhel})
		u.VisitUnread(dir, true)
		if id := osID(u); id != want {
			t.Errorf("unlistable %s: os ID %q, want %q", dir, id, want)
		}
	}
	// The same through a filesystem walk that cannot list /etc (not as
	// root, which can).
	if os.Geteuid() != 0 {
		root := t.TempDir()
		for rel, data := range map[string][]byte{dir + "/lib/server/libjvm.so": lib, dir + "/release": release, "usr/lib/os-release": rhel, "etc/os-release": rocky} {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		etc := filepath.Join(root, "etc")
		for mode, want := range map[os.FileMode]engine.Verdict{0o000: engine.Unknown, 0o755: engine.Unknown} {
			// 0755: /etc/os-release is read and says rocky.
			if err := os.Chmod(etc, mode); err != nil {
				t.Fatal(err)
			}
			tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
			os.Chmod(etc, 0o755)
			if len(tg.Findings) != 1 || tg.Findings[0].Verdict != want {
				t.Errorf("/etc mode %o: findings %+v", mode, tg.Findings)
			}
		}
		// And an /etc/os-release that cannot be opened.
		if err := os.Chmod(filepath.Join(etc, "os-release"), 0o000); err != nil {
			t.Fatal(err)
		}
		tg := engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
		if len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Unknown || tg.Annotations["java4shell_os"] != "rhel 9.6" {
			t.Errorf("unreadable /etc/os-release: findings %+v annotations %v", tg.Findings, tg.Annotations)
		}
		// Without /etc/os-release, /usr/lib/os-release is the system's.
		os.Remove(filepath.Join(etc, "os-release"))
		tg = engine.ScanFS([]engine.Detector{&Detector{}}, root, engine.Options{AsRoot: true})
		if len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Fixed {
			t.Errorf("no /etc/os-release: findings %+v", tg.Findings)
		}
	}
	// An unread /usr/lib/os-release does not matter when /etc/os-release was read.
	s.Visit(engine.File{Path: "/etc/os-release", Data: rocky})
	s.Forget("/usr/lib/os-release")
	s.VisitOverLimit("/usr/lib/os-release", maxOSRelease+1)
	if id := osID(s); id != "rocky" {
		t.Errorf("os ID %q, want rocky", id)
	}
}
