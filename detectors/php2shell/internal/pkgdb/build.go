package pkgdb

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Paths of the databases Build reads. Directories are absolute within the
// scanned root.
const (
	dpkgDir       = "/var/lib/dpkg"
	dpkgStatus    = dpkgDir + "/status"
	dpkgStatusD   = dpkgDir + "/status.d"
	dpkgInfo      = dpkgDir + "/info"
	dpkgUpdates   = dpkgDir + "/updates"
	dpkgDiversion = dpkgDir + "/diversions"
	chiselDir     = "/var/lib/chisel"
)

// apkDBs are the installed-package databases apk-tools reads ("lib/apk/db"
// and the uvol layer "lib/apk/db-uvol", relative to the root), also under
// /usr/lib for roots where /lib is a symlink to usr/lib (the walk then sees the
// real path).
var apkDBs = []string{
	"/lib/apk/db/installed",
	"/lib/apk/db-uvol/installed",
	"/usr/lib/apk/db/installed",
	"/usr/lib/apk/db-uvol/installed",
}

// rpmDirs are the rpm %_dbpath locations in use: /var/lib/rpm (RHEL, CentOS,
// Amazon Linux, older Fedora and SUSE), /usr/lib/sysimage/rpm (Fedora 36+,
// openSUSE, SLES 15 SP3+), /usr/share/rpm (some older SUSE builds).
var rpmDirs = []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm", "/usr/share/rpm"}

// rpmFiles are the database files of the three rpm backends, best first:
// sqlite (rpm 4.16+; its write-ahead log may hold committed transactions not
// yet copied into the main file), ndb (SUSE), Berkeley DB hash (rpm < 4.16).
var rpmFiles = []string{"rpmdb.sqlite", "rpmdb.sqlite-wal", "Packages.db", "Packages"}

// Release files OSRelease reads.
var releaseFiles = []string{"/etc/os-release", "/usr/lib/os-release", "/etc/debian_version", "/etc/alpine-release"}

// Wanted reports whether an absolute path (within the scanned root) is a file
// Build or OSRelease needs: package databases, dpkg file lists and digests,
// and release files. The caller collects the content of every wanted regular
// file (path -> bytes) and passes the map to Build and OSRelease; symlinks
// and hard links go to a Resolver instead.
func Wanted(p string) bool {
	p = clean(p)
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	switch dir {
	case dpkgDir:
		return base == "status" || base == "diversions"
	case dpkgInfo:
		return strings.HasSuffix(base, ".list") || strings.HasSuffix(base, ".md5sums")
	case dpkgStatusD:
		return base != "" && !strings.HasPrefix(base, ".")
	case dpkgUpdates:
		return isDigits(base)
	case chiselDir:
		return base == "manifest.wall"
	}
	for _, d := range rpmDirs {
		if dir == d {
			for _, f := range rpmFiles {
				if base == f {
					return true
				}
			}
			return false
		}
	}
	for _, a := range apkDBs {
		if p == a {
			return true
		}
	}
	for _, r := range releaseFiles {
		if p == r {
			return true
		}
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// builder accumulates the result of reading every database.
type builder struct {
	pkgs     []Installed
	dbs      []string
	problems []string
}

func (b *builder) problem(format string, args ...any) {
	b.problems = append(b.problems, fmt.Sprintf(format, args...))
}

// Build parses the collected files (absolute path -> content) into an Index.
// It never fails: databases that exist but cannot be read completely are
// recorded in Index.Problems with the reason, and every database read is in
// Index.DBs. A package read from a database with a problem is still indexed
// when its own record was readable.
func Build(files map[string][]byte) *Index {
	norm := make(map[string][]byte, len(files))
	for p, c := range files {
		norm[clean(p)] = c
	}
	b := &builder{}
	b.readDpkg(norm)
	b.readAPK(norm)
	b.readRPM(norm)
	if _, ok := norm[chiselDir+"/manifest.wall"]; ok {
		b.problem("%s/manifest.wall: Ubuntu chisel manifest present; this scanner does not read it, so packages installed by chisel are unknown", chiselDir)
	}
	sort.Strings(b.dbs)
	return NewIndex(b.pkgs, b.dbs, b.problems)
}

// Packages returns every installed package read, including packages whose
// database records no file list (distroless status.d entries without
// .md5sums, for example): those have no Files. Callers can thus tell "a PHP
// package is installed but its files are unknown" from "no package owns this
// file". The slice is shared; do not modify it.
func (ix *Index) Packages() []Installed {
	if ix == nil {
		return nil
	}
	return ix.pkgs
}

// OwnersOf returns the owners of p under every alias the resolver knows (see
// Resolver.Aliases), deduplicated. With a nil resolver it equals Owners(p).
func (ix *Index) OwnersOf(r *Resolver, p string) []Owner {
	if ix == nil {
		return nil
	}
	type key struct {
		db, name, version, arch, path string
	}
	seen := map[key]bool{}
	var out []Owner
	for _, a := range r.Aliases(p) {
		for _, o := range ix.Owners(a) {
			k := key{o.Package.DB, o.Package.Name, o.Package.Version, o.Package.Arch, o.File.Path}
			if !seen[k] {
				seen[k] = true
				out = append(out, o)
			}
		}
	}
	return out
}
