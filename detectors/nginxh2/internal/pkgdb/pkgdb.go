// Package pkgdb reads which package owns a file from dpkg's and apk's
// databases, and compares their versions. It knows nothing about the
// engine.
package pkgdb

import (
	"bufio"
	"bytes"
	"path"
	"strings"
)

// Package is an installed package.
type Package struct {
	Manager    string `json:"manager"` // dpkg, apk
	Name       string `json:"name"`
	Source     string `json:"source,omitempty"`
	Version    string `json:"version"`
	Maintainer string `json:"maintainer,omitempty"`
}

const maxLine = 1 << 20

func scanner(b []byte) *bufio.Scanner {
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 64<<10), maxLine)
	return s
}

// DpkgStatus reads /var/lib/dpkg/status: the installed packages by name.
func DpkgStatus(b []byte) map[string]Package {
	out := map[string]Package{}
	var cur Package
	installed := false
	flush := func() {
		if cur.Name != "" && installed {
			if cur.Source == "" {
				cur.Source = cur.Name
			}
			out[cur.Name] = cur
		}
		cur, installed = Package{Manager: "dpkg"}, false
	}
	cur.Manager = "dpkg"
	s := scanner(b)
	for s.Scan() {
		l := s.Text()
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.HasPrefix(l, " ") {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.Name = v
		case "Version":
			cur.Version = v
		case "Maintainer":
			cur.Maintainer = v
		case "Source":
			// "nginx (1.22.1-9)" names the source and its version.
			src, _, _ := strings.Cut(v, " ")
			cur.Source = src
		case "Status":
			installed = strings.HasSuffix(v, " installed")
		}
	}
	flush()
	return out
}

// DpkgListName returns the package a /var/lib/dpkg/info/*.list file is
// for ("nginx-core:amd64.list" is nginx-core).
func DpkgListName(p string) string {
	n := strings.TrimSuffix(path.Base(p), ".list")
	n, _, _ = strings.Cut(n, ":")
	return n
}

// ListHas reports whether a dpkg .list file names p.
func ListHas(list []byte, p string) bool {
	s := scanner(list)
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == p {
			return true
		}
	}
	return false
}

// APKOwners reads an apk installed database: the package owning each
// file, by absolute path.
func APKOwners(b []byte) map[string]Package {
	out := map[string]Package{}
	var cur Package
	var files []string
	dir := ""
	flush := func() {
		if cur.Name != "" {
			if cur.Source == "" {
				cur.Source = cur.Name
			}
			for _, f := range files {
				out[f] = cur
			}
		}
		cur, files, dir = Package{Manager: "apk"}, nil, ""
	}
	cur.Manager = "apk"
	s := scanner(b)
	for s.Scan() {
		l := s.Text()
		if l == "" {
			flush()
			continue
		}
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		v := l[2:]
		switch l[0] {
		case 'P':
			cur.Name = v
		case 'V':
			cur.Version = v
		case 'o':
			cur.Source = v
		case 'm':
			cur.Maintainer = v
		case 'F':
			dir = v
		case 'R':
			if len(files) < 1<<16 {
				files = append(files, "/"+path.Join(dir, v))
			}
		}
	}
	flush()
	return out
}
