package image

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// layer builds a layer from (name, content) entries; content "\x00dir" is
// a directory.
func layer(t *testing.T, entries ...[2]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e[0], Mode: 0o755, Size: int64(len(e[1])), Typeflag: tar.TypeReg}
		if e[1] == "\x00dir" {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e[1]))
		}
	}
	tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func entries(t *testing.T, img v1.Image) map[string][]string {
	t.Helper()
	rc := flatten(img)
	defer rc.Close()
	out := map[string][]string{}
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = append(out[h.Name], string(b))
	}
}

// Final review finding 1: a path spelled with and without a leading slash
// in two layers is one file, the upper layer's; a whiteout hides it
// whichever way either is spelled.
func TestFlattenOnePathTwoSpellings(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image,
		layer(t, [2]string{"usr/sbin/sshd", "placeholder"}, [2]string{"etc/gone", "x"}, [2]string{"/etc/gone2", "x"}, [2]string{"./opt/a", "lower"}),
		layer(t, [2]string{"/usr/sbin/sshd", "real"}, [2]string{"/etc/.wh.gone", ""}, [2]string{"etc/.wh.gone2", ""}, [2]string{"opt/a", "upper"}))
	if err != nil {
		t.Fatal(err)
	}
	got := entries(t, img)
	if s := got["usr/sbin/sshd"]; len(s) != 1 || s[0] != "real" {
		t.Errorf("sshd: %q", s)
	}
	if s := got["opt/a"]; len(s) != 1 || s[0] != "upper" {
		t.Errorf("opt/a: %q", s)
	}
	if _, ok := got["etc/gone"]; ok {
		t.Error("a whiteout spelled /etc/.wh.gone did not hide etc/gone")
	}
	if _, ok := got["etc/gone2"]; ok {
		t.Error("a whiteout spelled etc/.wh.gone2 did not hide /etc/gone2")
	}
	for name := range got {
		if len(name) > 0 && name[0] == '/' {
			t.Errorf("entry %q is not relative to the root", name)
		}
	}
}

// Unsafe names fail the image, as with mutate.Extract.
func TestFlattenUnsafe(t *testing.T) {
	img, _ := mutate.AppendLayers(empty.Image, layer(t, [2]string{"../escape", "x"}))
	rc := flatten(img)
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil {
		t.Error("an unsafe path was accepted")
	}
}
