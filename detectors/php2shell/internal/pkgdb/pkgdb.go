// Package pkgdb reads the package databases a system or container image carries
// (dpkg, apk, rpm) and answers which installed package owns a file, so a PHP
// binary installed by a distribution is judged by that distribution's fix and
// not by its upstream version string.
package pkgdb

import (
	"path"
	"sort"
)

// Format names a package manager.
type Format string

const (
	Dpkg Format = "dpkg"
	APK  Format = "apk"
	RPM  Format = "rpm"
)

// Package is one installed package.
type Package struct {
	Format Format `json:"format"`
	Name   string `json:"name"`
	// Version is the full version as the package manager writes it, with the
	// epoch if it has one: "1:8.2.35-1~deb12u1", "8.3.29-r0", "8.2.13-1.module+el9.4.0+20xxx".
	// For rpm it is EPOCH:VERSION-RELEASE (epoch omitted when zero).
	Version string `json:"version"`
	// Source is the source package it was built from: dpkg "Source:", apk origin,
	// rpm source rpm name without version. Equals Name when the database has none.
	Source string `json:"source"`
	// Vendor is rpm's Vendor tag, or dpkg's Maintainer. Empty for apk.
	Vendor string `json:"vendor,omitempty"`
	Arch   string `json:"arch,omitempty"`
	// DB is the database file the package was read from.
	DB string `json:"db"`
}

// File is one file a package installed, with the digest the database records
// for it, if any.
type File struct {
	Path string
	// Algo is "md5", "sha1", "sha256" (or another name rpm uses); empty when the
	// database records no digest for the file.
	Algo   string
	Digest []byte
}

// Installed is a package and the files it owns.
type Installed struct {
	Package Package
	Files   []File
}

// Index maps absolute paths to the packages that own them, across every
// database found.
type Index struct {
	owners map[string][]Owner
	pkgs   []Installed
	// DBs lists the databases that were read.
	DBs []string
	// Problems lists databases that exist but could not be read fully. A file
	// under such a database may have an owner this index does not know.
	Problems []string
}

// Owner is a package that lists a file, with the digest it recorded.
type Owner struct {
	Package Package
	File    File
}

// NewIndex builds an index from installed packages.
func NewIndex(pkgs []Installed, dbs, problems []string) *Index {
	ix := &Index{owners: map[string][]Owner{}, pkgs: pkgs, DBs: dbs, Problems: problems}
	for _, p := range pkgs {
		for _, f := range p.Files {
			k := path.Clean("/" + f.Path)
			ix.owners[k] = append(ix.owners[k], Owner{p.Package, f})
		}
	}
	for k := range ix.owners {
		o := ix.owners[k]
		sort.SliceStable(o, func(i, j int) bool { return o[i].Package.Name < o[j].Package.Name })
	}
	return ix
}

// Owners returns every package that lists p. Callers resolve symlinked
// directories first (see Resolver).
func (ix *Index) Owners(p string) []Owner {
	if ix == nil {
		return nil
	}
	return ix.owners[path.Clean("/"+p)]
}

// Empty reports whether no package database was found at all.
func (ix *Index) Empty() bool { return ix == nil || (len(ix.DBs) == 0 && len(ix.Problems) == 0) }
