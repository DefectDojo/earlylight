package engine

import (
	"path/filepath"
	"strings"
	"testing"
)

// skipFake records the skips it is given before Finish.
type skipFake struct {
	*fake
	got      []Skip
	finished bool
}

func (s *skipFake) NewScan(TargetKind) Scan { return s }
func (s *skipFake) VisitSkips(sk []Skip) {
	if s.finished {
		panic("VisitSkips after Finish")
	}
	s.got = append(s.got, sk...)
}
func (s *skipFake) Finish(ctx TargetContext) []Finding {
	s.finished = true
	return nil
}

// A SkipVisitor gets the walk's coverage gaps before Finish, with paths
// inside the system root, and not the deliberate exclusions.
func TestSkipVisitor(t *testing.T) {
	root := tree(t, map[string][]byte{"/etc/nginx/big.conf": make([]byte, 2048), "/etc/nginx/small.conf": []byte("x")})
	for _, c := range []struct {
		name string
		scan string
		opts Options
	}{
		{"at the root", root, Options{AsRoot: true, MaxFileSize: 1024}},
		{"below the root", filepath.Join(root, "etc"), Options{SystemRoot: root, MaxFileSize: 1024}},
	} {
		d := &skipFake{fake: &fake{id: "s", seen: &[]string{}}}
		tg := ScanFS([]Detector{d}, c.scan, c.opts)
		if tg.Error != "" {
			t.Fatal(tg.Error)
		}
		if len(d.got) != 1 || d.got[0].Path != "/etc/nginx/big.conf" || !d.finished {
			t.Errorf("%s: %+v", c.name, d.got)
		}
	}
}

// failing panics on every file named bad.conf.
type failing struct{ *fake }

func (f failing) NewScan(TargetKind) Scan { return f }
func (f failing) Visit(file File) []Skip {
	if filepath.Base(file.Path) == "bad.conf" {
		panic("hostile file")
	}
	return nil
}

// A SkipVisitor gets one record per path, as the target reports them, with
// every reason, and with the path inside the system root whether the walk
// or a detector made the record.
func TestSkipVisitorOneRecordPerPath(t *testing.T) {
	root := tree(t, map[string][]byte{"/etc/nginx/big.conf": make([]byte, 2048), "/etc/nginx/bad.conf": []byte("x")})
	for _, c := range []struct {
		name string
		scan string
		opts Options
	}{
		{"at the root", root, Options{AsRoot: true, MaxFileSize: 1024}},
		{"below the root", filepath.Join(root, "etc"), Options{SystemRoot: root, MaxFileSize: 1024}},
	} {
		d := &skipFake{fake: &fake{id: "s", seen: &[]string{}}}
		a := failing{&fake{id: "a", seen: &[]string{}}}
		b := failing{&fake{id: "b", seen: &[]string{}}}
		tg := ScanFS([]Detector{a, b, d}, c.scan, c.opts)
		if tg.Error != "" {
			t.Fatal(tg.Error)
		}
		got := map[string]string{}
		for _, sk := range d.got {
			if _, dup := got[sk.Path]; dup {
				t.Errorf("%s: %s given twice", c.name, sk.Path)
			}
			got[sk.Path] = sk.Reason
		}
		bad := got["/etc/nginx/bad.conf"]
		if len(got) != 2 || got["/etc/nginx/big.conf"] == "" || !strings.Contains(bad, "detector a failed") || !strings.Contains(bad, "detector b failed") {
			t.Errorf("%s: %+v", c.name, d.got)
		}
	}
}

// What another detector reports as a gap at the end (FinishSkipper) is a
// file over its own limit: the SkipVisitor was shown that file, so it is
// not a gap for it, whichever order the detectors run in.
func TestSkipVisitorNotOthersFinishSkips(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10)})
	_, g := gapDetector("t-finskip", false)
	d := &skipFake{fake: &fake{id: "s", seen: &[]string{}}}
	tg := ScanFS([]Detector{finishSkipper{g, true}, d}, root, Options{AsRoot: true})
	if tg.Error != "" || tg.Gaps() != 1 {
		t.Fatalf("error %q skipped %+v", tg.Error, tg.Skipped)
	}
	if len(d.got) != 0 || strings.Join(*d.seen, ",") != "/etc/os-release" {
		t.Errorf("given %+v, seen %v", d.got, *d.seen)
	}
}
