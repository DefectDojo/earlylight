package pkgdb

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// apkKnownFields are the single-letter fields apk-tools 3 accepts in the
// installed database (apk_pkgtmpl_add_info and apk_db_fdb_read). apk-tools
// refuses a database with any other field ("too old to handle installed
// packages"); so do we, per package, as a problem.
const apkKnownFields = "PVTULADCSIpiomtckFMRZrqasfg"

// parseAPKInstalled reads an apk installed database (lib/apk/db/installed,
// the text format both apk-tools 2 and 3 write): one paragraph per package,
// "X:value" lines, F: a directory (relative to the root), R: a file in it, Z:
// the preceding file's digest. db is the path recorded in Package.DB.
func parseAPKInstalled(data []byte, db string) (pkgs []Installed, errs []string) {
	var cur *Installed
	var dir string
	haveDir := false
	sha256_160 := false // "f:S": Z digests are sha256 truncated to 160 bits
	var lastFile = -1
	lineNo := 0
	flush := func() {
		if cur != nil {
			if cur.Package.Name == "" {
				errs = append(errs, "package ending at line "+strconv.Itoa(lineNo)+" has no P: name")
			} else {
				if cur.Package.Source == "" {
					cur.Package.Source = cur.Package.Name
				}
				if cur.Package.Version == "" {
					errs = append(errs, "package "+cur.Package.Name+" has no V: version")
				}
				pkgs = append(pkgs, *cur)
			}
		}
		cur, dir, haveDir, sha256_160, lastFile = nil, "", false, false, -1
	}
	for len(data) > 0 {
		lineNo++
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if len(line) < 2 { // apk: a line shorter than 2 ends the package
			flush()
			continue
		}
		if line[1] != ':' {
			errs = append(errs, "line "+strconv.Itoa(lineNo)+": not a field")
			continue
		}
		field, val := line[0], string(line[2:])
		if cur == nil {
			cur = &Installed{Package: Package{Format: APK, DB: db}}
		}
		where := func() string {
			n := cur.Package.Name
			if n == "" {
				n = "?"
			}
			return "line " + strconv.Itoa(lineNo) + " (package " + n + ")"
		}
		switch field {
		case 'P':
			cur.Package.Name = val
		case 'V':
			cur.Package.Version = val
		case 'A':
			cur.Package.Arch = val
		case 'o':
			cur.Package.Source = val
		case 'f':
			sha256_160 = strings.IndexByte(val, 'S') >= 0
		case 'F':
			dir, haveDir, lastFile = val, true, -1
		case 'R':
			if !haveDir {
				errs = append(errs, where()+": R: file before any F: directory")
				lastFile = -1
				continue
			}
			p := val
			if dir != "" {
				p = dir + "/" + val
			}
			cur.Files = append(cur.Files, File{Path: clean(p)})
			lastFile = len(cur.Files) - 1
		case 'Z':
			if lastFile < 0 {
				errs = append(errs, where()+": Z: checksum without a preceding R: file")
				continue
			}
			algo, d, ok := parseAPKDigest(val, sha256_160)
			if !ok {
				errs = append(errs, where()+": unreadable Z: checksum "+strconv.Quote(val))
				continue
			}
			cur.Files[lastFile].Algo, cur.Files[lastFile].Digest = algo, d
		case 'a':
			if lastFile < 0 {
				errs = append(errs, where()+": a: without a preceding R: file")
			}
		default:
			if strings.IndexByte(apkKnownFields, field) < 0 {
				errs = append(errs, where()+": unknown field "+strconv.Quote(string(field)))
			}
		}
	}
	flush()
	return pkgs, errs
}

// parseAPKDigest decodes an apk digest as apk_blob_pull_digest does: an
// encoding letter (Q base64, X hex) and an algorithm digit (1 sha1, 2 sha256),
// where a "1" digest that is 32 bytes long is sha256. In a package flagged
// f:S, 20-byte "1" digests are the first 160 bits of sha256 ("sha256-160").
func parseAPKDigest(s string, sha256_160 bool) (algo string, d []byte, ok bool) {
	if len(s) < 3 {
		return "", nil, false
	}
	var err error
	switch s[0] {
	case 'Q':
		d, err = base64.StdEncoding.DecodeString(s[2:])
	case 'X':
		d, err = hex.DecodeString(s[2:])
	default:
		return "", nil, false
	}
	if err != nil {
		return "", nil, false
	}
	switch {
	case s[1] == '1' && len(d) == 20:
		if sha256_160 {
			return "sha256-160", d, true
		}
		return "sha1", d, true
	case (s[1] == '1' || s[1] == '2') && len(d) == 32:
		return "sha256", d, true
	}
	return "", nil, false
}

func (b *builder) readAPK(files map[string][]byte) {
	var read [][]byte
	for _, db := range apkDBs {
		data, ok := files[db]
		if !ok {
			continue
		}
		dup := false
		for _, r := range read {
			if bytes.Equal(r, data) {
				dup = true
			}
		}
		if dup {
			// /lib/apk/db and /usr/lib/apk/db with identical content: the same
			// database seen through two paths.
			continue
		}
		if strings.HasPrefix(db, "/usr/lib/") {
			if _, also := files[strings.TrimPrefix(db, "/usr")]; also {
				b.problem("apk: both %s and %s exist and differ; apk-tools reads %s, so packages from %s may not be installed", strings.TrimPrefix(db, "/usr"), db, strings.TrimPrefix(db, "/usr"), db)
			}
		}
		read = append(read, data)
		b.dbs = append(b.dbs, db)
		pkgs, errs := parseAPKInstalled(data, db)
		for _, e := range errs {
			b.problem("apk: %s: %s", db, e)
		}
		b.pkgs = append(b.pkgs, pkgs...)
	}
}
