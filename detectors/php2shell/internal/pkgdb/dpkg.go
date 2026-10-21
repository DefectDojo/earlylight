package pkgdb

import (
	"bytes"
	"encoding/hex"
	"path"
	"sort"
	"strconv"
	"strings"
)

// deb822 paragraph as dpkg reads it: field names are case-insensitive, a line
// starting with a space or tab continues the previous field, and only an
// empty line separates paragraphs (a whitespace-only line is a continuation).
type para struct {
	line   int               // line of the first field
	fields map[string]string // lower-case name -> value (continuations joined with "\n")
}

func (p para) get(name string) string { return p.fields[name] }

// parseDeb822 splits a dpkg database file into paragraphs. Malformed lines are
// reported in errs (with line numbers) and skipped; the rest is still parsed.
func parseDeb822(data []byte) (paras []para, errs []string) {
	var cur *para
	last := ""
	flush := func() {
		if cur != nil && len(cur.fields) > 0 {
			paras = append(paras, *cur)
		}
		cur, last = nil, ""
	}
	lineNo := 0
	for len(data) > 0 {
		lineNo++
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur == nil || last == "" {
				errs = append(errs, "line "+strconv.Itoa(lineNo)+": continuation line without a field")
				continue
			}
			cur.fields[last] += "\n" + string(bytes.TrimSpace(line))
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			errs = append(errs, "line "+strconv.Itoa(lineNo)+": not a field")
			last = ""
			continue
		}
		name := strings.ToLower(string(bytes.TrimSpace(line[:colon])))
		if cur == nil {
			cur = &para{line: lineNo, fields: map[string]string{}}
		}
		if _, dup := cur.fields[name]; dup {
			errs = append(errs, "line "+strconv.Itoa(lineNo)+": duplicate field "+name)
		}
		cur.fields[name] = string(bytes.TrimSpace(line[colon+1:]))
		last = name
	}
	flush()
	return paras, errs
}

// parseMD5Sums reads a dpkg .md5sums file: "<32 hex> <space|*><path>" per
// line, paths relative to the root. It returns absolute paths -> digest.
func parseMD5Sums(data []byte) (map[string][]byte, []string) {
	out := map[string][]byte{}
	var errs []string
	lineNo := 0
	for len(data) > 0 {
		lineNo++
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			continue
		}
		if len(line) < 34 || line[32] != ' ' {
			errs = append(errs, "line "+strconv.Itoa(lineNo)+": not \"<md5>  <path>\"")
			continue
		}
		sum, err := hex.DecodeString(string(line[:32]))
		if err != nil {
			errs = append(errs, "line "+strconv.Itoa(lineNo)+": bad md5")
			continue
		}
		p := line[33:]
		if p[0] == ' ' || p[0] == '*' {
			p = p[1:]
		}
		if len(p) == 0 {
			errs = append(errs, "line "+strconv.Itoa(lineNo)+": empty path")
			continue
		}
		out[clean(strings.TrimPrefix(string(p), "./"))] = sum
	}
	return out, errs
}

// parseList reads a dpkg .list file: one absolute path per line.
func parseList(data []byte) []string {
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSuffix(l, "\r")
		if l == "" || l == "/." {
			continue
		}
		out = append(out, clean(l))
	}
	return out
}

type diversion struct{ to, by string }

// parseDiversions reads /var/lib/dpkg/diversions: groups of three lines
// (diverted path, path it was moved to, diverting package or ":" for a local
// diversion).
func parseDiversions(data []byte) (map[string]diversion, []string) {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil, nil
	}
	var errs []string
	if len(lines)%3 != 0 {
		errs = append(errs, "line count is not a multiple of 3")
	}
	out := map[string]diversion{}
	for i := 0; i+2 < len(lines); i += 3 {
		from, to, by := lines[i], lines[i+1], lines[i+2]
		if !strings.HasPrefix(from, "/") || !strings.HasPrefix(to, "/") || by == "" {
			errs = append(errs, "line "+strconv.Itoa(i+1)+": malformed diversion")
			continue
		}
		out[clean(from)] = diversion{to: clean(to), by: by}
	}
	return out, errs
}

type dpkgStatusVal struct{ want, eflag, state string }

func parseStatusField(s string) (dpkgStatusVal, bool) {
	f := strings.Fields(s)
	if len(f) != 3 {
		return dpkgStatusVal{}, false
	}
	return dpkgStatusVal{f[0], f[1], f[2]}, true
}

type dpkgRec struct {
	p      para
	from   string // file the record came from
	distro bool   // from status.d (distroless: no Status, no .list)
	base   string // status.d file name
}

func (b *builder) readDpkg(files map[string][]byte) {
	status, haveStatus := files[dpkgStatus]
	var statusD, updates []string
	haveInfo := false
	for p := range files {
		dir, base := path.Split(p)
		switch strings.TrimSuffix(dir, "/") {
		case dpkgStatusD:
			if !strings.HasSuffix(base, ".md5sums") {
				statusD = append(statusD, p)
			}
		case dpkgUpdates:
			if isDigits(base) {
				updates = append(updates, p)
			}
		case dpkgInfo:
			haveInfo = true
		}
	}
	if !haveStatus && len(statusD) == 0 {
		if haveInfo {
			b.problem("dpkg: %s has package file lists but %s is missing: installed dpkg packages are unknown", dpkgInfo, dpkgStatus)
		}
		return
	}
	sort.Strings(statusD)
	sort.Slice(updates, func(i, j int) bool {
		a, _ := strconv.ParseUint(path.Base(updates[i]), 10, 64)
		c, _ := strconv.ParseUint(path.Base(updates[j]), 10, 64)
		return a < c
	})

	recs := map[string]*dpkgRec{} // name:arch -> record
	var order []string
	add := func(p para, from string, distro bool, base string) {
		name := p.get("package")
		if name == "" {
			b.problem("dpkg: %s: line %d: paragraph without Package field", from, p.line)
			return
		}
		key := name + ":" + p.get("architecture")
		if _, ok := recs[key]; !ok {
			order = append(order, key)
		} else if distro {
			b.problem("dpkg: %s: package %s also listed elsewhere", from, key)
		}
		recs[key] = &dpkgRec{p: p, from: from, distro: distro, base: base}
	}
	readParas := func(file string, data []byte, distro bool, base string) {
		ps, errs := parseDeb822(data)
		for _, e := range errs {
			b.problem("dpkg: %s: %s", file, e)
		}
		for _, p := range ps {
			add(p, file, distro, base)
		}
	}
	if haveStatus {
		b.dbs = append(b.dbs, dpkgStatus)
		readParas(dpkgStatus, status, false, "")
	}
	for _, f := range statusD {
		b.dbs = append(b.dbs, f)
		readParas(f, files[f], true, path.Base(f))
	}
	// The journal: dpkg applies these complete records over the status file
	// before anything else reads the database.
	for _, f := range updates {
		if len(files[f]) == 0 {
			continue
		}
		b.dbs = append(b.dbs, f)
		readParas(f, files[f], false, "")
	}

	var div map[string]diversion
	if d, ok := files[dpkgDiversion]; ok {
		var errs []string
		div, errs = parseDiversions(d)
		for _, e := range errs {
			b.problem("dpkg: %s: %s", dpkgDiversion, e)
		}
		b.dbs = append(b.dbs, dpkgDiversion)
	}

	for _, key := range order {
		r := recs[key]
		p := r.p
		name := p.get("package")
		arch := p.get("architecture")
		if !r.distro {
			st, ok := parseStatusField(p.get("status"))
			if !ok {
				b.problem("dpkg: %s: package %s: missing or malformed Status %q; treated as installed", r.from, key, p.get("status"))
			} else {
				switch st.state {
				case "installed", "triggers-pending", "triggers-awaited", "half-configured", "unpacked":
					// Files of this version are on disk.
				case "half-installed":
					b.problem("dpkg: package %s is half-installed: its files on disk may be from version %s or from the version it replaced", key, p.get("version"))
				case "config-files", "not-installed":
					continue
				default:
					b.problem("dpkg: %s: package %s: unknown state %q; treated as installed", r.from, key, st.state)
				}
				if st.eflag != "ok" {
					b.problem("dpkg: package %s has error flag %q (needs reinstallation)", key, st.eflag)
				}
			}
		}
		version := p.get("version")
		if version == "" {
			b.problem("dpkg: %s: package %s has no Version", r.from, key)
		}
		src := p.get("source")
		if i := strings.IndexAny(src, " \t("); i >= 0 {
			src = src[:i]
		}
		if src == "" {
			src = name
		}
		pkg := Package{Format: Dpkg, Name: name, Version: version, Source: src,
			Vendor: p.get("maintainer"), Arch: arch, DB: r.from}

		var listed []string
		var sums map[string][]byte
		var listFile, sumFile string
		if r.distro {
			sumFile = dpkgStatusD + "/" + r.base + ".md5sums"
		} else {
			qual, plain := name+":"+arch, name
			first, second := plain, qual
			if p.get("multi-arch") == "same" {
				first, second = qual, plain
			}
			for _, n := range []string{first, second} {
				if _, ok := files[dpkgInfo+"/"+n+".list"]; ok && listFile == "" {
					listFile = dpkgInfo + "/" + n + ".list"
				}
				if _, ok := files[dpkgInfo+"/"+n+".md5sums"]; ok && sumFile == "" {
					sumFile = dpkgInfo + "/" + n + ".md5sums"
				}
			}
			if listFile == "" {
				b.problem("dpkg: package %s: no file list (%s/%s.list): the files it owns are unknown", key, dpkgInfo, first)
			} else {
				listed = parseList(files[listFile])
			}
		}
		if data, ok := files[sumFile]; ok && sumFile != "" {
			var errs []string
			sums, errs = parseMD5Sums(data)
			for _, e := range errs {
				b.problem("dpkg: %s: %s", sumFile, e)
			}
		}
		// Conffile digests (the shipped content) for files md5sums omits.
		conf := map[string][]byte{}
		for _, l := range strings.Split(p.get("conffiles"), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 && strings.HasPrefix(f[0], "/") {
				if d, err := hex.DecodeString(f[1]); err == nil && len(d) == 16 {
					conf[clean(f[0])] = d
				}
			}
		}

		seen := map[string]bool{}
		var out []File
		addFile := func(fp string) {
			if seen[fp] {
				return
			}
			seen[fp] = true
			f := File{Path: fp}
			if d, ok := sums[fp]; ok {
				f.Algo, f.Digest = "md5", d
			} else if d, ok := conf[fp]; ok {
				f.Algo, f.Digest = "md5", d
			}
			// A file diverted away from this package lives at the diversion
			// target; the diverting package keeps the original name.
			if d, ok := div[fp]; ok && d.by != name {
				f.Path = d.to
			}
			out = append(out, f)
		}
		for _, fp := range listed {
			addFile(fp)
		}
		extra := make([]string, 0)
		for fp := range sums {
			if !seen[fp] {
				extra = append(extra, fp)
			}
		}
		sort.Strings(extra)
		for _, fp := range extra {
			addFile(fp)
		}
		b.pkgs = append(b.pkgs, Installed{Package: pkg, Files: out})
	}
}
