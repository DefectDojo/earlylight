package image

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// ent is one layer entry: kind "f" (file), "d", "l" (symlink to body),
// "h" (hard link to body); a name with ".wh." is a whiteout.
type ent struct{ name, kind, body string }

func f(name, body string) ent { return ent{name, "f", body} }
func d(name string) ent       { return ent{name, "d", ""} }
func sl(name, to string) ent  { return ent{name, "l", to} }
func hl(name, to string) ent  { return ent{name, "h", to} }

func layerOf(t testing.TB, es ...ent) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		h := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeReg, Size: int64(len(e.body))}
		switch e.kind {
		case "d":
			h.Typeflag, h.Size = tar.TypeDir, 0
		case "l":
			h.Typeflag, h.Size, h.Linkname = tar.TypeSymlink, 0, e.body
		case "h":
			h.Typeflag, h.Size, h.Linkname = tar.TypeLink, 0, e.body
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
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

func imageOf(t testing.TB, layers ...[]ent) v1.Image {
	t.Helper()
	var ls []v1.Layer
	for _, es := range layers {
		ls = append(ls, layerOf(t, es...))
	}
	img, err := mutate.AppendLayers(empty.Image, ls...)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// read lists a flattened stream: name -> "kind:content" for each entry
// (several when a name repeats).
func read(t testing.TB, rc io.ReadCloser) map[string][]string {
	t.Helper()
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
		v := ""
		switch h.Typeflag {
		case tar.TypeDir:
			v = "d"
		case tar.TypeSymlink:
			v = "l:" + h.Linkname
		case tar.TypeLink:
			v = "h:" + strings.TrimPrefix(h.Linkname, "/")
		default:
			v = "f:" + string(b)
		}
		out[h.Name] = append(out[h.Name], v)
	}
}

func flat(t testing.TB, layers ...[]ent) (map[string][]string, []string) {
	t.Helper()
	rc, unresolved := flatten(imageOf(t, layers...))
	got := read(t, rc)
	return got, unresolved()
}

func one(got map[string][]string, name string) string {
	if len(got[name]) != 1 {
		return fmt.Sprint(got[name])
	}
	return got[name][0]
}

// A path spelled with and without a leading slash in two layers is one
// file, the upper layer's; a whiteout hides it whichever way either is
// spelled.
func TestFlattenOnePathTwoSpellings(t *testing.T) {
	got, _ := flat(t,
		[]ent{f("usr/sbin/sshd", "placeholder"), f("etc/gone", "x"), f("/etc/gone2", "x"), f("./opt/a", "lower")},
		[]ent{f("/usr/sbin/sshd", "real"), f("/etc/.wh.gone", ""), f("etc/.wh.gone2", ""), f("opt/a", "upper")})
	if one(got, "usr/sbin/sshd") != "f:real" || one(got, "opt/a") != "f:upper" {
		t.Errorf("%v", got)
	}
	if _, ok := got["etc/gone"]; ok {
		t.Error("a whiteout spelled /etc/.wh.gone did not hide etc/gone")
	}
	if _, ok := got["etc/gone2"]; ok {
		t.Error("a whiteout spelled etc/.wh.gone2 did not hide /etc/gone2")
	}
	for name := range got {
		if strings.HasPrefix(name, "/") {
			t.Errorf("entry %q is not relative to the root", name)
		}
	}
}

// Unsafe names fail the image, as with mutate.Extract.
func TestFlattenUnsafe(t *testing.T) {
	rc, _ := flatten(imageOf(t, []ent{f("../escape", "x")}))
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil {
		t.Error("an unsafe path was accepted")
	}
}

// Round-5 review finding 1 and 2c: a symbolic link with more "../" than
// its depth is kept (it resolves at the root), so the lower file at its
// path stays hidden; so is a root-level link to a name starting with "..".
func TestFlattenDeepSymlink(t *testing.T) {
	for _, upper := range []string{"/u/x", "u/x"} {
		got, _ := flat(t, []ent{f("u/x", "lower"), f("foo", "foo")}, []ent{sl(upper, "../../../foo"), sl("y", "..data/x")})
		if one(got, "u/x") != "l:../../../foo" || one(got, "y") != "l:..data/x" {
			t.Errorf("%s: %v", upper, got)
		}
	}
}

// Round-5 review finding 2a: a hard link keeps the content of the file it
// named when a later layer removes or replaces that file.
func TestFlattenHardLinkToHiddenFile(t *testing.T) {
	base := []ent{f("a", "orig")}
	linked := []ent{f("a", "orig"), hl("b", "a")} // RUN ln /a /b copies /a up
	got, unresolved := flat(t, base, linked, []ent{f(".wh.a", "")})
	if one(got, "b") != "f:orig" || len(got["a"]) != 0 || len(unresolved) != 0 {
		t.Errorf("rm /a: %v unresolved %v", got, unresolved)
	}
	got, unresolved = flat(t, base, linked, []ent{f("a", "new")})
	if one(got, "b") != "f:orig" || one(got, "a") != "f:new" || len(unresolved) != 0 {
		t.Errorf("echo new > /a: %v unresolved %v", got, unresolved)
	}
	// A hard link to a file outside its layer is not settled.
	_, unresolved = flat(t, base, []ent{hl("b", "a")}, []ent{f("a", "new")})
	if fmt.Sprint(unresolved) != "[/b]" {
		t.Errorf("a link to another layer's file: unresolved %v", unresolved)
	}
}

// Round-5 review finding 2b: a directory, then a file, then a directory
// over three layers: the file removed the first directory's entries.
func TestFlattenDirFileDir(t *testing.T) {
	got, _ := flat(t,
		[]ent{d("d"), f("d/inc", "UsePAM yes")},
		[]ent{f("d", "a file")},
		[]ent{d("d"), f("d/new", "z")})
	if one(got, "d") != "d" || one(got, "d/new") != "f:z" || len(got["d/inc"]) != 0 {
		t.Errorf("%v", got)
	}
}

// Round-5 review finding 4: what one layer says twice about a path, and a
// write or whiteout through a directory that is a symbolic link, is
// unresolved.
func TestFlattenUnresolved(t *testing.T) {
	for _, c := range []struct {
		name   string
		layers [][]ent
		want   string
	}{
		{"two entries in one layer", [][]ent{{f("a", "1"), f("a", "2")}}, "[/a]"},
		{"whiteout then file", [][]ent{{f("a", "lower")}, {f(".wh.a", ""), f("a", "new")}}, "[/a]"},
		{"file then whiteout", [][]ent{{f("a", "lower")}, {f("a", "new"), f(".wh.a", "")}}, "[/a]"},
		{"a directory twice", [][]ent{{d("d"), d("d"), f("d/x", "1")}}, "[]"},
		{"a write through a symlinked directory", [][]ent{{sl("etc/ssh", "../opt/ssh"), f("opt/ssh/sshd_config", "old")}, {f("etc/ssh/sshd_config", "new")}},
			"[/etc/ssh/sshd_config /opt/ssh/sshd_config]"},
		{"a whiteout through a symlinked directory", [][]ent{{sl("etc/ssh", "/opt/ssh"), f("opt/ssh/sshd_config", "old")}, {f("etc/ssh/.wh.sshd_config", "")}},
			"[/etc/ssh/sshd_config /opt/ssh/sshd_config]"},
	} {
		_, unresolved := flat(t, c.layers...)
		if fmt.Sprint(unresolved) != c.want {
			t.Errorf("%s: unresolved %v, want %s", c.name, unresolved, c.want)
		}
	}
}

// fuzzNames are the paths fuzzed images use, each with one kind, so that
// mutate.Extract (which does not handle a path changing kind) is a fair
// reference.
var fuzzNames = []struct{ name, kind string }{
	{"a", "f"}, {"b", "f"}, {"d", "d"}, {"d/x", "f"}, {"d/y", "f"}, {"d/e", "d"}, {"d/e/z", "f"}, {"l", "l"},
}

// FuzzFlatten builds random multi-layer images. On clean names it must
// give what mutate.Extract gives; with names spelled with a leading slash,
// the same; and with any entries (kinds changing, hard links, repeats), it
// must never write a path twice or fail on a well-formed image.
func FuzzFlatten(fz *testing.F) {
	fz.Add([]byte{0, 1, 2, 3, 0x80, 0x41, 5, 0xff, 7})
	fz.Add([]byte{2, 3, 4, 0x82, 0x90, 0x23, 0x25})
	fz.Add([]byte{0x10, 0x11, 0xc0, 0x13, 0x40, 0x2a, 0x8b})
	fz.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64 {
			return
		}
		var clean, slashed, wild [][]ent
		var cur, curS, curW []ent
		used := map[string]bool{}
		for i, b := range data {
			if b == 0xff || len(cur) == 6 {
				clean, slashed, wild = append(clean, cur), append(slashed, curS), append(wild, curW)
				cur, curS, curW, used = nil, nil, nil, map[string]bool{}
				if b == 0xff {
					continue
				}
			}
			n := fuzzNames[int(b)%len(fuzzNames)]
			var e ent
			switch op := (b >> 3) & 3; {
			case op == 3 && n.kind == "d":
				e = f(n.name+"/.wh..wh..opq", "")
			case op == 3 || op == 2 && n.kind != "d":
				dir, base := "", n.name
				if j := strings.LastIndexByte(n.name, '/'); j >= 0 {
					dir, base = n.name[:j+1], n.name[j+1:]
				}
				e = f(dir+".wh."+base, "")
			case n.kind == "d":
				e = d(n.name)
			case n.kind == "l":
				e = sl(n.name, "d/x")
			default:
				e = f(n.name, fmt.Sprintf("%d-%d", i, b))
			}
			key := strings.Replace(e.name, ".wh.", "", 1)
			if !used[key] && !strings.Contains(e.name, ".wh..wh..opq") || strings.Contains(e.name, ".wh..wh..opq") && !used[e.name] {
				used[key], used[e.name] = true, true
				cur = append(cur, e)
				s := e
				if b&0x40 != 0 {
					s.name = "/" + s.name
				}
				curS = append(curS, s)
			}
			// The wild image takes every entry, with kinds changing.
			w := e
			switch b >> 6 {
			case 1:
				w = hl(n.name, fuzzNames[int(b>>2)%len(fuzzNames)].name)
			case 2:
				w = d(n.name)
			case 3:
				w = f(n.name, "w")
			}
			curW = append(curW, w)
		}
		clean, slashed, wild = append(clean, cur), append(slashed, curS), append(wild, curW)

		want := read(t, mutate.Extract(imageOf(t, clean...)))
		for _, layers := range [][][]ent{clean, slashed} {
			got, unresolved := flat(t, layers...)
			if len(unresolved) != 0 {
				t.Fatalf("clean image left %v unresolved: %v", unresolved, layers)
			}
			if a, b := dump(got), dump(want); a != b {
				t.Fatalf("layers %v:\nflatten %s\nExtract %s", layers, a, b)
			}
		}
		got, _ := flat(t, wild...)
		for name, v := range got {
			if len(v) != 1 {
				t.Fatalf("%s written %d times: %v (layers %v)", name, len(v), v, wild)
			}
		}
	})
}

func dump(m map[string][]string) string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+strings.Join(v, "|"))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}
