package pkgdb_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"
	_ "github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb/rpmdb"
)

// Real-image verification. Each case is a tar of an image's package database
// files, release files and symlinks (as the scanner's walk would see them),
// plus ground truth recorded inside the running image with the package
// manager itself:
//
//	pkgs.txt     dpkg-query -W / apk list -I / rpm -qa --qf
//	owners.txt   dpkg -S / apk info --who-owns / rpm -qf for every regular
//	             file in /usr/bin /usr/sbin /bin /sbin
//	digests.txt  md5, sha1, sha256 of those files
//	rpmfiles.txt rpm -q --dump of every package (rpm only)
//
// testdata/images/*.tar.gz are trimmed copies kept in the repository. Set
// PKGDB_REALDB to a directory of untrimmed cases (one subdirectory per image
// with db.tar and the truth files) to verify complete databases.

type imageCase struct {
	name   string
	files  map[string][]byte // wanted files, as the walk collects them
	links  map[string]string
	hard   map[string]string
	truth  map[string][]byte
	family string
}

func readTar(t *testing.T, r io.Reader, c *imageCase) {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		name := "/" + strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		switch h.Typeflag {
		case tar.TypeSymlink:
			c.links[name] = h.Linkname
		case tar.TypeLink:
			c.hard[name] = "/" + strings.TrimPrefix(h.Linkname, "/")
		case tar.TypeReg:
			b, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(name, "/truth/") {
				c.truth[strings.TrimPrefix(name, "/truth/")] = b
			} else if pkgdb.Wanted(name) {
				c.files[name] = b
			}
		}
	}
}

func newCase(name string) *imageCase {
	return &imageCase{name: name, files: map[string][]byte{}, links: map[string]string{}, hard: map[string]string{}, truth: map[string][]byte{}}
}

func loadCases(t *testing.T) []*imageCase {
	var cases []*imageCase
	if dir := os.Getenv("PKGDB_REALDB"); dir != "" {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			db := filepath.Join(dir, e.Name(), "db.tar")
			f, err := os.Open(db)
			if err != nil {
				continue
			}
			c := newCase(e.Name())
			readTar(t, f, c)
			f.Close()
			for _, tf := range []string{"pkgs.txt", "owners.txt", "digests.txt", "rpmfiles.txt"} {
				if b, err := os.ReadFile(filepath.Join(dir, e.Name(), tf)); err == nil {
					c.truth[tf] = b
				}
			}
			cases = append(cases, c)
		}
		return cases
	}
	ms, _ := filepath.Glob(filepath.Join("testdata", "images", "*.tar.gz"))
	for _, m := range ms {
		f, err := os.Open(m)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		c := newCase(strings.TrimSuffix(filepath.Base(m), ".tar.gz"))
		readTar(t, zr, c)
		f.Close()
		cases = append(cases, c)
	}
	if len(cases) == 0 {
		t.Fatal("no image fixtures")
	}
	return cases
}

func lines(b []byte) [][]string {
	var out [][]string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, strings.Split(l, "\t"))
		}
	}
	return out
}

// pkgID is how each family's tools name an installed package.
func pkgID(p pkgdb.Package) string {
	switch p.Format {
	case pkgdb.APK:
		return p.Name + "-" + p.Version
	case pkgdb.RPM:
		v := p.Version
		if !strings.Contains(v, ":") {
			v = "0:" + v
		}
		return p.Name + "-" + v + "." + p.Arch
	}
	return p.Name
}

// modifiedOnDisk are files the image build changed after the package
// installed them, so their content legitimately differs from the database.
var modifiedOnDisk = map[string]bool{
	"distroless:/usr/lib/os-release": true, // distroless writes its own
}

func TestRealImages(t *testing.T) {
	for _, c := range loadCases(t) {
		t.Run(c.name, func(t *testing.T) { checkImage(t, c) })
	}
}

func checkImage(t *testing.T, c *imageCase) {
	ix := pkgdb.Build(c.files)
	r := pkgdb.NewResolver(c.links)
	for p, tgt := range c.hard {
		r.AddHardlink(p, tgt)
	}
	for _, p := range ix.Problems {
		t.Errorf("problem: %s", p)
	}
	if len(ix.DBs) == 0 {
		t.Fatal("no database read")
	}
	if _, ok := c.truth["os-release.txt"]; ok || true {
		if os, ok := pkgdb.OSRelease(c.files); !ok || os.ID == "" {
			t.Errorf("OSRelease: %+v %v", os, ok)
		}
	}
	got := map[string]pkgdb.Package{}
	for _, p := range ix.Packages() {
		k := p.Package.Name + "|" + p.Package.Arch
		if _, dup := got[k]; dup && p.Package.Format != pkgdb.RPM {
			t.Errorf("duplicate package %s", k)
		}
		got[k+"|"+p.Package.Version] = p.Package
	}
	format := ix.Packages()[0].Package.Format

	// 1. Package list.
	want := map[string]pkgdb.Package{}
	for _, f := range lines(c.truth["pkgs.txt"]) {
		var p pkgdb.Package
		switch format {
		case pkgdb.Dpkg:
			if len(f) != 7 {
				t.Fatalf("pkgs.txt line %q", f)
			}
			if st := f[6]; len(st) < 2 || !strings.ContainsRune("iUFWtH", rune(st[1])) {
				continue
			}
			p = pkgdb.Package{Format: pkgdb.Dpkg, Name: f[1], Version: f[2], Source: f[3], Vendor: f[4], Arch: f[5]}
		case pkgdb.APK:
			fs := strings.Fields(strings.Join(f, " "))
			nv := fs[0]
			i := strings.LastIndexByte(nv, '-')
			i = strings.LastIndexByte(nv[:i], '-')
			p = pkgdb.Package{Format: pkgdb.APK, Name: nv[:i], Version: nv[i+1:], Arch: fs[1], Source: strings.Trim(fs[2], "{}")}
		case pkgdb.RPM:
			if len(f) != 5 {
				t.Fatalf("pkgs.txt line %q", f)
			}
			none := func(s string) string {
				if s == "(none)" {
					return ""
				}
				return s
			}
			src := f[0]
			if s := none(f[2]); s != "" {
				src = strings.TrimSuffix(strings.TrimSuffix(s, ".src.rpm"), ".nosrc.rpm")
				for k := 0; k < 2; k++ {
					src = src[:strings.LastIndexByte(src, '-')]
				}
			}
			p = pkgdb.Package{Format: pkgdb.RPM, Name: f[0], Version: strings.TrimPrefix(f[1], "0:"), Source: src, Vendor: none(f[3]), Arch: none(f[4])}
		}
		want[p.Name+"|"+p.Arch+"|"+p.Version] = p
	}
	for k, w := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("package %s missing", k)
			continue
		}
		g.DB = ""
		if g != w {
			t.Errorf("package %s:\n got %+v\nwant %+v", k, g, w)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("package %s not listed by the package manager", k)
		}
	}

	// 2. Ownership and digests of every binary.
	sums := map[string][]string{}
	for _, f := range lines(c.truth["digests.txt"]) {
		sums[f[0]] = f[1:]
	}
	// The tools answer for the literal path (dpkg -S /usr/bin/bash finds
	// nothing when bash lists /bin/bash and /bin -> usr/bin); the truth for a
	// file is the union over the paths in owners.txt that name it.
	byFile := map[string]map[string]bool{}
	for _, f := range lines(c.truth["owners.txt"]) {
		cp, err := r.Canonical(f[0])
		if err != nil {
			t.Fatal(err)
		}
		if byFile[cp] == nil {
			byFile[cp] = map[string]bool{}
		}
		if len(f) > 1 {
			for _, o := range strings.Fields(f[1]) {
				if format == pkgdb.Dpkg {
					o = strings.SplitN(o, ":", 2)[0]
				}
				byFile[cp][o] = true
			}
		}
	}
	owned, verified := 0, 0
	for _, f := range lines(c.truth["owners.txt"]) {
		p := f[0]
		cp, _ := r.Canonical(p)
		var wantOwners []string
		for o := range byFile[cp] {
			wantOwners = append(wantOwners, o)
		}
		var gotOwners []string
		for _, o := range ix.OwnersOf(r, p) {
			gotOwners = append(gotOwners, pkgID(o.Package))
			s, ok := sums[p]
			if !ok || o.File.Digest == nil {
				continue
			}
			var w string
			switch o.File.Algo {
			case "md5":
				w = s[0]
			case "sha1":
				w = s[1]
			case "sha256":
				w = s[2]
			case "sha256-160":
				w = s[2][:40]
			default:
				t.Errorf("%s: digest algorithm %q", p, o.File.Algo)
			}
			if modifiedOnDisk[c.name+":"+p] {
				continue
			}
			if hex.EncodeToString(o.File.Digest) != w {
				t.Errorf("%s: %s digest %x, file has %s", p, o.File.Algo, o.File.Digest, w)
			} else {
				verified++
			}
		}
		sort.Strings(gotOwners)
		sort.Strings(wantOwners)
		if strings.Join(gotOwners, " ") != strings.Join(wantOwners, " ") {
			t.Errorf("owners of %s: got %v, package manager says %v", p, gotOwners, wantOwners)
		}
		if len(wantOwners) > 0 {
			owned++
		}
	}

	// 3. rpm: every file of every package, with its digest.
	files, fileDigests := 0, 0
	if dump, ok := c.truth["rpmfiles.txt"]; ok {
		byID := map[string]map[string]pkgdb.File{}
		for _, p := range ix.Packages() {
			m := map[string]pkgdb.File{}
			for _, f := range p.Files {
				m[f.Path] = f
			}
			id := pkgID(p.Package)
			byID[strings.Replace(id, "-0:", "-", 1)] = m
		}
		wantFiles := map[string]map[string]bool{}
		for _, l := range lines(dump) {
			if len(l) != 2 || !strings.HasPrefix(l[1], "/") {
				continue
			}
			fs := strings.Split(l[1], " ")
			if len(fs) != 11 {
				continue // path with spaces: ambiguous in --dump output
			}
			id, p, digest := l[0], fs[0], fs[3]
			if wantFiles[id] == nil {
				wantFiles[id] = map[string]bool{}
			}
			wantFiles[id][p] = true
			gf, ok := byID[id][p]
			if !ok {
				t.Errorf("%s: file %s missing", id, p)
				continue
			}
			files++
			if gf.Digest != nil {
				if hex.EncodeToString(gf.Digest) != digest {
					t.Errorf("%s: %s digest %x, rpm says %s", id, p, gf.Digest, digest)
				}
				fileDigests++
			}
		}
		for id, m := range wantFiles {
			if len(byID[id]) < len(m) {
				t.Errorf("%s: %d files, rpm lists %d", id, len(byID[id]), len(m))
			}
		}
	}
	t.Logf("%s: %d dbs, %d packages (truth %d), %d owned binaries checked, %d binary digests verified, %d rpm files matched (%d digests)",
		c.name, len(ix.DBs), len(ix.Packages()), len(want), owned, verified, files, fileDigests)
}

var _ = md5.Sum
var _ = bytes.Equal
