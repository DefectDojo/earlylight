package engine

import (
	"path/filepath"
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
