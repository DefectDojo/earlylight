package engine

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/source"
)

func skip(p, reason string, excluded bool) source.Skip {
	return source.Skip{Path: p, Reason: reason, Excluded: excluded}
}

// fake records what it is shown and returns canned findings.
type fake struct {
	id       string
	archives bool
	wants    func(p string) bool // nil: no Reader, wants everything
	finish   func(ctx TargetContext) []Finding
	seen     *[]string
	cleared  bool
}

type fakeReader struct{ *fake }

func (f fakeReader) Wants(p string, _ []byte, _ bool) bool { return f.wants(p) }

func (f *fake) Manifest() Manifest {
	return Manifest{ID: f.id, Targets: []TargetKind{Filesystem, Image}, Archives: f.archives, Kinds: []Kind{{ID: "k", Title: "k", Level: "error"}}}
}
func (f *fake) Load() error             { return nil }
func (f *fake) NewScan(TargetKind) Scan { return f }
func (f *fake) Visit(file File) []Skip {
	*f.seen = append(*f.seen, file.Path)
	return nil
}
func (f *fake) Finish(ctx TargetContext) []Finding {
	if f.finish != nil {
		return f.finish(ctx)
	}
	return nil
}

func detector(f *fake) Detector {
	if f.seen == nil {
		f.seen = &[]string{}
	}
	if f.wants != nil {
		return struct {
			*fake
			fakeReader
		}{f, fakeReader{f}}
	}
	return f
}

func tree(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	for p, b := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func zipOf(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	zw.Close()
	return buf.Bytes()
}

func base(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p[strings.LastIndex(p, "/")+1:])
	}
	sort.Strings(out)
	return out
}

// A finding can only be cleared with a reason attached.
func TestClearedNeedsAReason(t *testing.T) {
	root := tree(t, map[string][]byte{"a": []byte("x")})
	d := detector(&fake{id: "t-clear", finish: func(TargetContext) []Finding {
		return []Finding{
			{Kind: "k", Path: "/a", Verdict: Fixed},
			{Kind: "k", Path: "/b", Verdict: Inactive, Reason: "blocklisted"},
			{Kind: "k", Path: "/c"},
		}
	}})
	tg := ScanFS([]Detector{d}, root, Options{AsRoot: true})
	got := map[string]Verdict{}
	for _, f := range tg.Findings {
		got[f.Path] = f.Verdict
		if f.Detector != "t-clear" {
			t.Errorf("detector ID not stamped: %+v", f)
		}
	}
	if got["/a"] != Unknown || got["/b"] != Inactive || got["/c"] != Unknown {
		t.Fatalf("verdicts %v", got)
	}
}

// Archive members go only to detectors that asked for them; every detector
// sees the file itself exactly once.
func TestArchiveMembersOnlyForDetectorsThatAsk(t *testing.T) {
	root := tree(t, map[string][]byte{"app.jar": zipOf(t, "inner.txt", []byte("hi")), "plain.txt": []byte("x")})
	a := &fake{id: "t-arch", archives: true}
	b := &fake{id: "t-flat"}
	ScanFS([]Detector{detector(a), detector(b)}, root, Options{AsRoot: true})
	sort.Strings(*a.seen)
	if got := strings.Join(*a.seen, ","); got != "/app.jar,/app.jar!/inner.txt,/plain.txt" {
		t.Errorf("archive detector saw %v", *a.seen)
	}
	if got := strings.Join(base(*b.seen), ","); got != "app.jar,plain.txt" {
		t.Errorf("flat detector saw %v", *b.seen)
	}
}

// A file is read when any detector wants it, and every file is read when any
// detector has no filter.
func TestReadFilterIsAUnion(t *testing.T) {
	files := map[string][]byte{"etc/a.conf": []byte("a"), "etc/b.txt": []byte("b"), "bin/c": []byte("c")}
	root := tree(t, files)
	conf := &fake{id: "t-conf", wants: func(p string) bool { return strings.HasSuffix(p, ".conf") }}
	none := &fake{id: "t-none", wants: func(string) bool { return false }}
	ScanFS([]Detector{detector(conf), detector(none)}, root, Options{AsRoot: true})
	if got := strings.Join(*conf.seen, ","); got != "/etc/a.conf" {
		t.Errorf("filtered scan read %q", got)
	}
	all := &fake{id: "t-all"}
	conf2 := &fake{id: "t-conf2", wants: func(p string) bool { return strings.HasSuffix(p, ".conf") }}
	ScanFS([]Detector{detector(conf2), detector(all)}, root, Options{AsRoot: true})
	if len(*all.seen) != 3 || len(*conf2.seen) != 3 {
		t.Errorf("with an unfiltered detector every file is read and shown to all: %v %v", *all.seen, *conf2.seen)
	}
}

func TestAliases(t *testing.T) {
	c := newTargetCtx(Image)
	c.symlinks["/usr/bin/php"] = "php8.3"
	c.symlinks["/lib"] = "usr/lib"
	c.hardlinks["/usr/sbin/php-fpm"] = "/usr/sbin/php-fpm8.3"
	got := func(p string) string { a := c.Aliases(p); sort.Strings(a); return strings.Join(a, ",") }
	if s := got("/usr/bin/php8.3"); s != "/usr/bin/php,/usr/bin/php8.3" {
		t.Errorf("file symlink: %s", s)
	}
	if s := got("/usr/lib/libphp.so"); s != "/lib/libphp.so,/usr/lib/libphp.so" {
		t.Errorf("directory symlink: %s", s)
	}
	if s := got("/usr/sbin/php-fpm8.3"); s != "/usr/sbin/php-fpm,/usr/sbin/php-fpm8.3" {
		t.Errorf("hard link: %s", s)
	}
	if s := got("/etc/passwd"); s != "/etc/passwd" {
		t.Errorf("no alias: %s", s)
	}
}

func TestRegistry(t *testing.T) {
	Register(detector(&fake{id: "t-reg"}))
	defer func() {
		if recover() == nil {
			t.Error("duplicate Register did not panic")
		}
	}()
	if _, err := Select([]string{"t-missing"}); err == nil {
		t.Error("unknown detector accepted")
	}
	Register(detector(&fake{id: "t-reg"}))
}

func TestGaps(t *testing.T) {
	img := &Target{Type: Image, Skipped: []source.Skip{skip("/src/testdata/bad.pem", "unparseable", false)}}
	if g := img.Gaps(); g != 1 {
		t.Errorf("image gaps %d, want 1: image paths never earn the fixture exemption", g)
	}
	tg := &Target{Type: Filesystem}
	tg.Skipped = append(tg.Skipped,
		skip("/proc", "excluded: pseudo-filesystem", true),
		skip("/x/testdata/bad.pem", "unparseable", false),
		skip("/opt/app.jks", "unknown keystore password", false),
		skip("/opt/app.jar!/testdata/cacerts", "unknown keystore password", false))
	if g := tg.Gaps(); g != 2 {
		t.Fatalf("gaps %d, want 2: an archive member named testdata/ is still a gap", g)
	}
}

// A detector that panics on one file loses that file, not the scan.
func TestDetectorPanicIsContained(t *testing.T) {
	root := tree(t, map[string][]byte{"testdata/bad": []byte("x"), "good": []byte("y")})
	seen := &[]string{}
	p := &panicky{fake: fake{id: "t-panic", seen: seen}}
	tg := ScanFS([]Detector{p}, root, Options{AsRoot: true})
	if tg.Error != "" || len(*seen) != 1 || (*seen)[0] != "/good" {
		t.Fatalf("error %q seen %v", tg.Error, *seen)
	}
	if len(tg.Skipped) != 1 || tg.Skipped[0].Path != "/testdata/bad" || tg.Gaps() != 1 {
		t.Fatalf("the panicking file must be a coverage gap: %+v", tg.Skipped)
	}
}

type panicky struct{ fake }

func (p *panicky) NewScan(TargetKind) Scan { return p }
func (p *panicky) Visit(f File) []Skip {
	if f.Path == "/testdata/bad" {
		panic("hostile input")
	}
	return p.fake.Visit(f)
}
