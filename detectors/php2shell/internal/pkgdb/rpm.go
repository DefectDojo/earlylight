package pkgdb

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RPMRecord is one row of an rpm sqlite database's Packages table: the
// package's instance number (hnum) and its header blob.
type RPMRecord struct {
	Key  uint32
	Blob []byte
}

// RPMSQLiteReader returns every row of the Packages table of an rpm sqlite
// database (rpmdb.sqlite), applying the write-ahead log wal when non-nil. It
// must fail rather than return a partial table.
type RPMSQLiteReader func(main, wal []byte) ([]RPMRecord, error)

var (
	sqliteMu     sync.RWMutex
	sqliteReader RPMSQLiteReader
)

// RegisterRPMSQLiteReader installs the reader for rpm sqlite databases. The
// package github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb/rpmdb registers one from
// init(); blank-import it to read rpm 4.16+ databases (RHEL 9, Fedora, Amazon
// Linux 2023, SLES 16). Without it, Build records a problem for every sqlite
// database it finds. Berkeley DB and ndb databases need no registration.
func RegisterRPMSQLiteReader(r RPMSQLiteReader) {
	sqliteMu.Lock()
	sqliteReader = r
	sqliteMu.Unlock()
}

func getSQLiteReader() RPMSQLiteReader {
	sqliteMu.RLock()
	defer sqliteMu.RUnlock()
	return sqliteReader
}

type pkgKey struct{ name, version, arch string }

// readRPMFile reads one rpm database file into packages. A database that
// cannot be read at all returns ok=false (with the problem recorded).
func (b *builder) readRPMFile(path, kind string, files map[string][]byte) (pkgs []Installed, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			b.problem("rpm: %s: reader failed on malformed data: %v", path, r)
			pkgs, ok = nil, false
		}
	}()
	var blobs []rpmBlob
	var err error
	switch kind {
	case "sqlite":
		rd := getSQLiteReader()
		if rd == nil {
			b.problem("rpm: %s: rpm sqlite database present but this build has no rpm sqlite reader (import pkgdb/rpmdb): its packages are unknown", path)
			return nil, false
		}
		var wal []byte
		if w, ok := files[path+"-wal"]; ok && len(w) > 0 {
			wal = w
		}
		var recs []RPMRecord
		recs, err = rd(files[path], wal)
		for _, r := range recs {
			blobs = append(blobs, rpmBlob{key: r.Key, data: r.Blob})
		}
	case "ndb":
		blobs, err = readNDB(files[path])
	case "bdb":
		var warn string
		blobs, warn, err = readBDB(files[path])
		if warn != "" {
			b.problem("rpm: %s: %s", path, warn)
		}
	}
	if err != nil {
		b.problem("rpm: %s: unreadable %s database: %v", path, kind, err)
		return nil, false
	}
	b.dbs = append(b.dbs, path)
	for _, bl := range blobs {
		if bl.err != nil {
			b.problem("rpm: %s: %v", path, bl.err)
			continue
		}
		h, err := parseHeaderBlob(bl.data)
		if err != nil {
			b.problem("rpm: %s: package record %d: unreadable header: %v", path, bl.key, err)
			continue
		}
		inst, warns, err := headerPackage(h, path)
		if err != nil {
			b.problem("rpm: %s: package record %d: %v", path, bl.key, err)
			continue
		}
		for _, w := range warns {
			b.problem("rpm: %s: %s", path, w)
		}
		pkgs = append(pkgs, inst)
	}
	return pkgs, true
}

func (b *builder) readRPM(files map[string][]byte) {
	type source struct {
		path string
		pkgs []Installed
	}
	var read []source
	for _, dir := range rpmDirs {
		for _, f := range []struct{ name, kind string }{
			{"rpmdb.sqlite", "sqlite"}, {"Packages.db", "ndb"}, {"Packages", "bdb"},
		} {
			p := dir + "/" + f.name
			if _, ok := files[p]; !ok {
				continue
			}
			if pkgs, ok := b.readRPMFile(p, f.kind, files); ok {
				read = append(read, source{p, pkgs})
			}
		}
		if _, ok := files[dir+"/rpmdb.sqlite-wal"]; ok {
			if _, main := files[dir+"/rpmdb.sqlite"]; !main {
				b.problem("rpm: %s/rpmdb.sqlite-wal present without rpmdb.sqlite", dir)
			}
		}
	}
	if len(read) == 0 {
		return
	}
	// One database is normal. Several (a leftover Packages next to
	// rpmdb.sqlite, or both /var/lib/rpm and /usr/lib/sysimage/rpm as real
	// directories) are all read; packages are taken from the first, and any
	// package only the others list is added too, with a problem, because which
	// one rpm uses depends on its configuration.
	have := map[pkgKey]bool{}
	for _, p := range read[0].pkgs {
		have[pkgKey{p.Package.Name, p.Package.Version, p.Package.Arch}] = true
	}
	b.pkgs = append(b.pkgs, read[0].pkgs...)
	for _, s := range read[1:] {
		var extra []string
		for _, p := range s.pkgs {
			k := pkgKey{p.Package.Name, p.Package.Version, p.Package.Arch}
			if !have[k] {
				have[k] = true
				extra = append(extra, p.Package.Name+"-"+p.Package.Version)
				b.pkgs = append(b.pkgs, p)
			}
		}
		other := map[pkgKey]bool{}
		for _, p := range s.pkgs {
			other[pkgKey{p.Package.Name, p.Package.Version, p.Package.Arch}] = true
		}
		missing := 0
		for _, p := range read[0].pkgs {
			if !other[pkgKey{p.Package.Name, p.Package.Version, p.Package.Arch}] {
				missing++
			}
		}
		if nExtra := len(extra); nExtra > 0 || missing > 0 {
			sort.Strings(extra)
			if len(extra) > 10 {
				extra = append(extra[:10], fmt.Sprintf("and %d more", len(extra)-10))
			}
			b.problem("rpm: %s and %s are both present and disagree (%d packages only in the second%s, %d only in the first); rpm uses one of them depending on its configuration",
				read[0].path, s.path, nExtra, listSuffix(extra), missing)
		}
	}
}

func listSuffix(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return ": " + strings.Join(xs, ", ")
}
