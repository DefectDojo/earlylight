package brotli

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/DefectDojo/earlylight/internal/engine"
)

// entry is one layer entry: a file with data, a directory (dir) or a
// symbolic link (link).
type entry struct {
	name string
	data []byte
	dir  bool
	link string
}

func archiveOf(t *testing.T, layers ...[]entry) string {
	t.Helper()
	var ls []v1.Layer
	for _, es := range layers {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range es {
			h := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeReg, Size: int64(len(e.data))}
			switch {
			case e.dir:
				h.Typeflag = tar.TypeDir
			case e.link != "":
				h.Typeflag, h.Linkname = tar.TypeSymlink, e.link
			}
			if err := tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			tw.Write(e.data)
		}
		tw.Close()
		b := buf.Bytes()
		l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
		if err != nil {
			t.Fatal(err)
		}
		ls = append(ls, l)
	}
	img, err := mutate.AppendLayers(empty.Image, ls...)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := tarball.WriteToFile(p, name.MustParseReference("test/brotli:1"), img); err != nil {
		t.Fatal(err)
	}
	return p
}

// Final review A4: an image whose upper layer names a library as it is
// written, lib/libbrotlidec.so.1, over a base where lib is a link to
// usr/lib (crane append, Bazel, Jib): the container has the library, and
// the scan reports it. The path it landed on is a coverage gap.
func TestWrittenThroughALink(t *testing.T) {
	p := archiveOf(t,
		[]entry{{name: "usr", dir: true}, {name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}, {name: "usr/lib/other", data: []byte("x")}},
		[]entry{{name: "lib/libbrotlidec.so.1", data: vulnerable}})
	tg := engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+p, engine.Options{})
	if tg.Error != "" || len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Vulnerable || tg.Findings[0].Path != "/lib/libbrotlidec.so.1" {
		t.Errorf("error %q findings %+v", tg.Error, tg.Findings)
	}
	if len(tg.Skipped) != 1 || tg.Skipped[0].Path != "/usr/lib/libbrotlidec.so.1" || tg.Gaps() != 1 {
		t.Errorf("skipped %+v", tg.Skipped)
	}
	// A lower file at the path it landed on was replaced: what it held is
	// forgotten, the file written through the link is kept.
	fixed := testbinFixed()
	p = archiveOf(t,
		[]entry{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}, {name: "usr/lib/libbrotlidec.so.1", data: fixed}},
		[]entry{{name: "lib/libbrotlidec.so.1", data: vulnerable}})
	tg = engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+p, engine.Options{})
	if len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Vulnerable || tg.Findings[0].Path != "/lib/libbrotlidec.so.1" {
		t.Errorf("replaced through the link: findings %+v", tg.Findings)
	}
	// A higher layer then names the real path: that entry is the file, and
	// what was written through the link before it is forgotten.
	p = archiveOf(t,
		[]entry{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}},
		[]entry{{name: "lib/libbrotlidec.so.1", data: fixed}},
		[]entry{{name: "usr/lib/libbrotlidec.so.1", data: vulnerable}})
	tg = engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+p, engine.Options{})
	if len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Vulnerable || tg.Findings[0].Path != "/usr/lib/libbrotlidec.so.1" || tg.Gaps() != 1 {
		t.Errorf("the real path written afterwards: findings %+v skipped %+v", tg.Findings, tg.Skipped)
	}
	// Written both ways in one layer, whose order decides: neither is kept.
	p = archiveOf(t,
		[]entry{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}},
		[]entry{{name: "lib/libbrotlidec.so.1", data: fixed}, {name: "usr/lib/libbrotlidec.so.1", data: vulnerable}})
	tg = engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+p, engine.Options{})
	if len(tg.Findings) != 0 || tg.Gaps() != 2 {
		t.Errorf("written both ways: findings %+v skipped %+v", tg.Findings, tg.Skipped)
	}
}
