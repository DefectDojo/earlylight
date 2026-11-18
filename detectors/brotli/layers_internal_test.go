package brotli

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
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
	// Written both ways in one layer: the layer's order decides, and the
	// later entry is the file.
	p = archiveOf(t,
		[]entry{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}},
		[]entry{{name: "lib/libbrotlidec.so.1", data: fixed}, {name: "usr/lib/libbrotlidec.so.1", data: vulnerable}})
	tg = engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+p, engine.Options{})
	if len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Vulnerable || tg.Findings[0].Path != "/usr/lib/libbrotlidec.so.1" || tg.Gaps() != 1 {
		t.Errorf("written both ways: findings %+v skipped %+v", tg.Findings, tg.Skipped)
	}
}

// Second final review, finding 2: layer layouts where the container has
// the vulnerable library (checked with docker load and docker export) and
// the scan reported only a coverage gap, exit 0, where main reports the
// library. Each is settled now: by following the links as the runtime did,
// by the order of a layer's entries, or by reading both entries a layer
// has for one path.
func TestLayersThatDroppedAFinding(t *testing.T) {
	fixed := testbinFixed()
	const lib = "libbrotlidec.so.1"
	for name, c := range map[string]struct {
		layers [][]entry
		want   string // the path of the one vulnerable finding
	}{
		"a link chain": {[][]entry{
			{{name: "opt/real", dir: true}, {name: "usr", dir: true}, {name: "usr/lib", link: "../opt/real"}, {name: "lib", link: "usr/lib"}},
			{{name: "lib/" + lib, data: vulnerable}}}, "/lib/" + lib},
		"a link to the root, over a clean file": {[][]entry{
			{{name: "r", link: "/"}, {name: "usr/lib", dir: true}, {name: "usr/lib/" + lib, data: fixed}},
			{{name: "r/usr/lib/" + lib, data: vulnerable}}}, "/r/usr/lib/" + lib},
		".. across a link: the clean file lands elsewhere": {[][]entry{
			{{name: "opt/real", dir: true}, {name: "opt/lib64", dir: true}, {name: "usr/lib", link: "/opt/real"}, {name: "lib", link: "usr/lib/../lib64"},
				{name: "usr/lib64", dir: true}, {name: "usr/lib64/" + lib, data: vulnerable}},
			{{name: "lib/" + lib, data: fixed}}}, "/usr/lib64/" + lib},
		"both names in one layer, the real path last": {[][]entry{
			{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}},
			{{name: "lib/" + lib, data: vulnerable}, {name: "usr/lib/" + lib, data: vulnerable}}}, "/usr/lib/" + lib},
		"both names in one layer, the link's last": {[][]entry{
			{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}},
			{{name: "usr/lib/" + lib, data: vulnerable}, {name: "lib/" + lib, data: vulnerable}}}, "/lib/" + lib},
		"two links to one directory": {[][]entry{
			{{name: "usr/lib", dir: true}, {name: "lib", link: "usr/lib"}, {name: "lib64", link: "usr/lib"}},
			{{name: "lib/" + lib, data: vulnerable}},
			{{name: "lib64/" + lib, data: vulnerable}}}, "/lib64/" + lib},
		"one path twice in one layer": {[][]entry{
			{{name: "usr/lib", dir: true}, {name: "usr/lib/" + lib, data: vulnerable}, {name: "usr/lib/" + lib, data: vulnerable}}}, "/usr/lib/" + lib},
		"one path twice in one layer, clean then vulnerable": {[][]entry{
			{{name: "usr/lib", dir: true}, {name: "usr/lib/" + lib, data: fixed}, {name: "usr/lib/" + lib, data: vulnerable}}}, "/usr/lib/" + lib},
	} {
		tg := engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+archiveOf(t, c.layers...), engine.Options{})
		var got []string
		for _, f := range tg.Findings {
			if f.Verdict == engine.Vulnerable {
				got = append(got, f.Path)
			}
		}
		if tg.Error != "" || len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: error %q, vulnerable at %v, want %s (findings %+v, skipped %+v)", name, tg.Error, got, c.want, tg.Findings, tg.Skipped)
		}
	}
	// The last entry is the file the other way round too: vulnerable then
	// clean in one layer is clean.
	tg := engine.ScanImage([]engine.Detector{&Detector{}}, "docker-archive:"+archiveOf(t,
		[]entry{{name: "usr/lib", dir: true}, {name: "usr/lib/" + lib, data: vulnerable}, {name: "usr/lib/" + lib, data: fixed}}), engine.Options{})
	if tg.Error != "" || tg.Count(engine.Vulnerable) != 0 || tg.Gaps() != 0 {
		t.Errorf("vulnerable then clean in one layer: findings %+v skipped %+v", tg.Findings, tg.Skipped)
	}
}

// Final review A5: a docker export names d/lib twice, and d is a link that
// points somewhere else by the second time: the two entries are two files
// (e/lib and o/lib), so the first is not forgotten.
func TestNamedAgainThroughAMovedLink(t *testing.T) {
	export := func(es ...entry) string {
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
		p := filepath.Join(t.TempDir(), "rootfs.tar")
		if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	clean := []byte("clean")
	for name, c := range map[string]struct {
		entries []entry
		want    int
	}{
		"the link moves": {[]entry{{name: "e", dir: true}, {name: "o", dir: true}, {name: "d", link: "e"}, {name: "d/libbrotlidec.so.1", data: vulnerable},
			{name: "d", link: "o"}, {name: "d/libbrotlidec.so.1", data: clean}}, 1},
		"a link above moves": {[]entry{{name: "e/s", dir: true}, {name: "o/s", dir: true}, {name: "d", link: "e"}, {name: "d/s/libbrotlidec.so.1", data: vulnerable},
			{name: "d", link: "o"}, {name: "d/s/libbrotlidec.so.1", data: clean}}, 1},
		"the link becomes a directory": {[]entry{{name: "e", dir: true}, {name: "d", link: "e"}, {name: "d/libbrotlidec.so.1", data: vulnerable},
			{name: "d", dir: true}, {name: "d/libbrotlidec.so.1", data: clean}}, 1},
		// No link: the last entry is the file.
		"a plain directory": {[]entry{{name: "d", dir: true}, {name: "d/libbrotlidec.so.1", data: vulnerable}, {name: "d/libbrotlidec.so.1", data: clean}}, 0},
	} {
		tg := engine.ScanImage([]engine.Detector{&Detector{}}, "rootfs:"+export(c.entries...), engine.Options{})
		if tg.Error != "" || len(tg.Findings) != c.want {
			t.Errorf("%s: error %q, %d findings, want %d: %+v", name, tg.Error, len(tg.Findings), c.want, tg.Findings)
		}
	}
}
