package rpmdb

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"
	gorpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

// rpmFixtures returns the rpm database files of ../testdata/images.
func rpmFixtures(t *testing.T) map[string]map[string][]byte {
	out := map[string]map[string][]byte{}
	ms, _ := filepath.Glob("../testdata/images/rpm-*.tar.gz")
	for _, m := range ms {
		f, err := os.Open(m)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		tr := tar.NewReader(zr)
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			if h.Typeflag == tar.TypeReg && pkgdb.Wanted("/"+h.Name) {
				files["/"+h.Name], _ = io.ReadAll(tr)
			}
		}
		f.Close()
		out[filepath.Base(m)] = files
	}
	if len(out) == 0 {
		t.Fatal("no rpm fixtures")
	}
	return out
}

// TestAgainstGoRPMDB compares pkgdb's rpm reading with go-rpmdb on every
// fixture: same packages, same files, same digests.
func TestAgainstGoRPMDB(t *testing.T) {
	for name, files := range rpmFixtures(t) {
		ix := pkgdb.Build(files)
		if len(ix.Problems) != 0 || len(ix.DBs) != 1 {
			t.Fatalf("%s: %v %v", name, ix.DBs, ix.Problems)
		}
		dir := t.TempDir()
		p := filepath.Join(dir, filepath.Base(ix.DBs[0]))
		if err := os.WriteFile(p, files[ix.DBs[0]], 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := gorpmdb.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := db.ListPackages()
		db.Close()
		if err != nil {
			t.Fatal(err)
		}
		var want, got []string
		for _, q := range theirs {
			evr := q.Version + "-" + q.Release
			if q.EpochNum() != 0 {
				evr = fmt.Sprint(q.EpochNum()) + ":" + evr
			}
			fs, err := q.InstalledFiles()
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, fmt.Sprintf("%s %s %s %q %d", q.Name, evr, q.Arch, q.Vendor, len(fs)))
			for _, f := range fs {
				if f.Digest != "" {
					want = append(want, q.Name+" "+f.Path+" "+f.Digest)
				}
			}
		}
		for _, p := range ix.Packages() {
			got = append(got, fmt.Sprintf("%s %s %s %q %d", p.Package.Name, p.Package.Version, p.Package.Arch, p.Package.Vendor, len(p.Files)))
			for _, f := range p.Files {
				if f.Digest != nil {
					got = append(got, fmt.Sprintf("%s %s %x", p.Package.Name, f.Path, f.Digest))
				}
			}
		}
		sort.Strings(want)
		sort.Strings(got)
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s: pkgdb and go-rpmdb differ\npkgdb:\n%s\ngo-rpmdb:\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		t.Logf("%s: %d packages, %d lines agree with go-rpmdb", name, len(theirs), len(got))
	}
}

// TestWAL: rows committed to the write-ahead log but not yet checkpointed
// into the main file are read.
func TestWAL(t *testing.T) {
	var main []byte
	for _, files := range rpmFixtures(t) {
		if b, ok := files["/var/lib/rpm/rpmdb.sqlite"]; ok {
			main = b
			break
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(p, main, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := sql.Open("sqlite", "file:"+p+"?_pragma=journal_mode(WAL)&_pragma=wal_autocheckpoint(0)")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	h.SetMaxOpenConns(1)
	before, err := Read(main, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Exec("INSERT INTO Packages (hnum, blob) SELECT 9999, blob FROM Packages LIMIT 1"); err != nil {
		t.Fatal(err)
	}
	// Copy the files while the connection is open: the new row is only in the WAL.
	m, _ := os.ReadFile(p)
	w, err := os.ReadFile(p + "-wal")
	if err != nil || len(w) == 0 {
		t.Fatalf("no WAL: %v", err)
	}
	withoutWAL, err := Read(m, nil)
	if err != nil {
		t.Fatal(err)
	}
	withWAL, err := Read(m, w)
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutWAL) != len(before) || len(withWAL) != len(before)+1 {
		t.Errorf("rows: before %d, main only %d, main+wal %d", len(before), len(withoutWAL), len(withWAL))
	}
	// And through Build, which picks up rpmdb.sqlite-wal by name.
	ix := pkgdb.Build(map[string][]byte{"/var/lib/rpm/rpmdb.sqlite": m, "/var/lib/rpm/rpmdb.sqlite-wal": w})
	if len(ix.Packages()) != len(before)+1 {
		t.Errorf("Build with WAL: %d packages, problems %v", len(ix.Packages()), ix.Problems)
	}
}

func TestCorruptSQLite(t *testing.T) {
	var main []byte
	for _, files := range rpmFixtures(t) {
		if b, ok := files["/var/lib/rpm/rpmdb.sqlite"]; ok {
			main = b
		}
	}
	for _, n := range []int{0, 15, 100, 4096, len(main) / 2, len(main) - 1} {
		recs, err := Read(main[:n], nil)
		if err == nil {
			t.Errorf("truncated to %d bytes: %d rows, no error", n, len(recs))
		}
	}
	// A page of garbage in the middle of the table.
	bad := append([]byte(nil), main...)
	for i := 8192; i < 12288 && i < len(bad); i++ {
		bad[i] = 0xa5
	}
	if recs, err := Read(bad, nil); err == nil {
		t.Logf("garbage page: %d rows read without error (page not in the Packages table)", len(recs))
	}
	if _, err := Read([]byte("SQLite format 3\x00garbage"), nil); err == nil {
		t.Error("garbage accepted")
	}
}
