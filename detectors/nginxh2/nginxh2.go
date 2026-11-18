// Package nginxh2 is the detector for the nginx HTTP/2 pair disclosed on
// 2026-11-18: CVE-2026-123007 (memory corruption in HTTP/2 flow control,
// nginx 1.9.5 to 1.31.8) and CVE-2026-123633 (use-after-free in HTTP/2
// connection reuse, 1.19.7 to 1.31.8), both fixed in nginx 1.31.9 and
// 1.30.7.
//
// It finds nginx, OpenResty, Tengine, Angie and NGINX Plus binaries in
// filesystems and container images by what the binary carries (its
// version line, configure arguments and module list), judges each CVE on
// each binary on its own, applies the distribution backport table through
// the package database, and reads the configuration the binary loads
// (includes, globs, templates, the container's -c) to report whether
// HTTP/2 is on over TLS and in front of a proxy. Exposure is a fact on the
// finding; it never clears one. In a source tree it finds the nginx images,
// packages and configurations a project uses, and fix moves image tags to
// the fixed release of their line after reading the new image.
//
// internal/knowledge, internal/ngx, internal/conf, internal/pkgdb,
// internal/assess and internal/repo know nothing about the engine; this
// file adapts them.
package nginxh2

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/pkgdb"
	"github.com/DefectDojo/earlylight/internal/archive"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// ID is the detector's ID.
const ID = "nginxh2"

// Kind IDs.
const (
	KindFlow  = assess.KindFlow
	KindReuse = assess.KindReuse
)

// Detector implements engine.Detector, engine.Reader, engine.RepoScanner
// and engine.Fixer.
type Detector struct{}

func init() { engine.Register(&Detector{}) }

const about = " Fixed in nginx 1.31.9 (mainline) and 1.30.7 (stable) on 2026-11-18; lines 1.29 and older received no fix." +
	" Debian, Ubuntu, Alpine, OpenResty, Tengine and Angie had published no fixed build that day; NGINX Plus is fixed in" +
	" 37.0.7.1 and 37.2.0.1 (CVE-2026-123633) and 37.0.8.1 and 37.3.0.1 (CVE-2026-123007). Turning HTTP/2 off" +
	" (\"http2 off;\" and no \"http2\" on any listen) removes the published path until the update; it is not a fix."

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	return engine.Manifest{
		ID:    ID,
		Title: "nginx HTTP/2 remote code execution pair (" + knowledge.Flow + ", " + knowledge.Reuse + ")",
		CVEs:  []string{knowledge.Flow, knowledge.Reuse},
		Advisories: []string{
			"https://nginx.org/en/security_advisories.html",
			"https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities",
			"https://my.f5.com/manage/s/article/K000163926",
			"https://my.f5.com/manage/s/article/K000163928",
			"https://github.com/nginx/nginx/commit/e27f5fa84fe6e98505e70bc543b748747dad0a3b",
			"https://github.com/nginx/nginx/commit/2df48a501d0fb8212b7d39dffeeff5876332ba59",
		},
		Disclosed: knowledge.Disclosed,
		Targets:   []engine.TargetKind{engine.Filesystem, engine.Image, engine.Repository},
		Kinds: append([]engine.Kind{
			{ID: KindFlow, Title: "nginx vulnerable to " + knowledge.Flow + " (HTTP/2 flow control memory corruption)", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: []string{"CWE-787", "CWE-190"},
				Description: "An nginx binary (or OpenResty, Tengine, Angie, NGINX Plus) from 1.9.5 to 1.31.8 built with HTTP/2. A client's WINDOW_UPDATE frames can push the connection's send window past its limit when a stream ends with queued data, and the next send copies out of bounds: Wiz showed pre-authentication code execution over HTTP/2 with TLS on the official 64-bit images. The finding reports whether the configuration turns HTTP/2 on over TLS." + about},
			{ID: KindReuse, Title: "nginx vulnerable to " + knowledge.Reuse + " (HTTP/2 connection reuse use-after-free)", Level: "error", SecuritySeverity: knowledge.CVSS, CWEs: []string{"CWE-416"},
				Description: "An nginx binary (or OpenResty, Tengine, Angie, NGINX Plus) from 1.19.7 to 1.31.8 built with HTTP/2. A connection marked reusable while a HEADERS frame is incomplete can be closed under connection pressure while one of its streams is being proxied, and the error path frees memory still in use. The finding reports whether the configuration turns HTTP/2 on in front of a proxy, and worker_connections." + about},
		}, repoKinds()...),
		Tags: []string{"security", "nginx", "http2", "openresty", "ingress-nginx"},
		Data: "nginx fixed releases (1.31.9, 1.30.7), the releases that introduced each flaw (1.9.5, 1.19.7), NGINX Plus fixed releases, OpenResty, Tengine and Angie releases, distribution and image status, checked " + knowledge.Checked,
	}
}

// Load checks the release data.
func (d *Detector) Load() error {
	for _, c := range knowledge.CVEs {
		if len(c.Fixed) == 0 || len(c.PlusFixed) == 0 || len(c.Introduced) != 3 {
			return errData(c.ID)
		}
		for _, f := range c.Fixed {
			if knowledge.Cmp(f, c.Introduced) <= 0 || len(f) != 3 {
				return errData(c.ID)
			}
		}
	}
	return nil
}

type errData string

func (e errData) Error() string { return "release data for " + string(e) + " contradicts itself" }

// Wants reads executables (possible nginx binaries), configuration files,
// package databases and os-release.
func (d *Detector) Wants(p string, head []byte, _ bool) bool {
	return archive.IsExecutable(head) || keepDB(p) || keepConf(p)
}

// Limits on what one target keeps.
const (
	maxConf      = 4 << 20
	maxConfTotal = 64 << 20
	maxConfFiles = 8192
	maxDB        = 32 << 20
	maxBinaries  = 512
)

// confDirs are directories whose every file can be a configuration file
// (mime.types, fastcgi_params and sites-enabled/default have no .conf).
var confDirs = []string{"/etc/nginx/", "/usr/local/nginx/conf/", "/usr/local/openresty/nginx/conf/", "/etc/openresty/",
	"/etc/angie/", "/usr/local/angie/conf/", "/etc/tengine/", "/usr/local/tengine/conf/", "/opt/bitnami/nginx/conf/",
	"/etc/nginx-plus/", "/usr/local/etc/nginx/"}

// confSuffixes are names any of whose files the scan keeps, wherever they
// are.
var confSuffixes = []string{".conf", ".conf.template", ".template", ".conf.tmpl", ".tmpl", ".vhost"}

// confNames are file names a configuration commonly includes without a
// .conf suffix.
var confNames = map[string]bool{"mime.types": true, "fastcgi_params": true, "scgi_params": true, "uwsgi_params": true,
	"proxy_params": true, "koi-utf": true, "koi-win": true, "win-utf": true, "default": true, "nginx.conf": true}

// keepConf reports a file that can be part of an nginx configuration:
// every file under a directory nginx builds read their configuration
// from, files with a configuration suffix anywhere, and under a directory
// named for nginx, files without an extension or with a configuration
// one (not the libraries, scripts and pages OpenResty keeps there).
func keepConf(p string) bool {
	for _, d := range confDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	base := path.Base(p)
	if confSuffix(base) {
		return true
	}
	if !nginxDir(path.Dir(p)) {
		return false
	}
	ext := path.Ext(base)
	return confNames[base] || ext == "" || ext == ".types" || ext == ".inc" || ext == ".cfg" || ext == ".site" || strings.HasSuffix(base, "_params")
}

func confSuffix(base string) bool {
	for _, s := range confSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}

func nginxDir(dir string) bool {
	for _, part := range strings.Split(dir, "/") {
		low := strings.ToLower(part)
		if strings.Contains(low, "nginx") || strings.Contains(low, "openresty") || low == "sites-enabled" || low == "sites-available" || low == "conf.d" || low == "http.d" {
			return true
		}
	}
	return false
}

// keptByAll reports whether every file a glob pattern can match is one
// keepConf keeps, so that the matches seen are all there are: the pattern
// is under a directory read whole, or every name it matches ends in a
// configuration suffix.
func keptByAll(pattern string) bool {
	dir := pattern
	if i := strings.IndexAny(dir, "*?["); i >= 0 {
		dir = dir[:i]
	}
	dir = dir[:strings.LastIndexByte(dir, '/')+1]
	for _, d := range confDirs {
		if strings.HasPrefix(dir, d) {
			return true
		}
	}
	return confSuffix(path.Base(pattern))
}

func keepDB(p string) bool {
	switch p {
	case "/var/lib/dpkg/status", "/lib/apk/db/installed", "/usr/lib/apk/db/installed", "/etc/os-release", "/usr/lib/os-release", "/etc/alpine-release":
		return true
	}
	if strings.HasPrefix(p, "/var/lib/dpkg/info/") && strings.HasSuffix(p, ".list") {
		n := pkgdb.DpkgListName(p)
		return strings.Contains(n, "nginx") || strings.Contains(n, "openresty") || strings.Contains(n, "angie") || strings.Contains(n, "tengine")
	}
	return strings.HasPrefix(p, "/docker-entrypoint.d/")
}

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(kind engine.TargetKind) engine.Scan {
	return &scan{kind: kind, conf: map[string][]byte{}, db: map[string][]byte{}, tooLarge: map[string]bool{}}
}

type scan struct {
	kind      engine.TargetKind
	binaries  []*ngx.Binary
	conf      map[string][]byte
	confBytes int
	confFull  bool            // the limit on configuration files was reached
	tooLarge  map[string]bool // configuration files over maxConf, not kept
	db        map[string][]byte
	ingress   bool
	dropped   int
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if f.Member {
		return nil // installed servers only
	}
	if archive.IsExecutable(f.Data) {
		if path.Base(f.Path) == "nginx-ingress-controller" {
			s.ingress = true
		}
		if b, ok := ngx.Inspect(f.Path, f.Data); ok {
			if len(s.binaries) >= maxBinaries {
				s.dropped++
				return []engine.Skip{{Path: f.Path, Reason: "an nginx binary past the detector's limit of 512 per target; not checked"}}
			}
			s.binaries = append(s.binaries, b)
		}
		return nil
	}
	if keepDB(f.Path) {
		if len(f.Data) <= maxDB {
			s.db[f.Path] = f.Data
		}
		return nil
	}
	if keepConf(f.Path) {
		switch {
		case len(f.Data) > maxConf:
			if len(s.tooLarge) < maxConfFiles {
				s.tooLarge[f.Path] = true
			} else {
				s.confFull = true
			}
			return nil
		case s.confBytes+len(f.Data) > maxConfTotal || len(s.conf) >= maxConfFiles:
			s.confFull = true
			return nil
		}
		s.conf[f.Path] = f.Data
		s.confBytes += len(f.Data)
	}
	return nil
}

func (s *scan) Finish(ctx engine.TargetContext) []engine.Finding {
	if len(s.binaries) == 0 {
		return nil
	}
	if s.dropped > 0 {
		ctx.Problem("nginxh2: more nginx binaries than the detector's limit; some were not checked")
	}
	links, _ := ctx.Links()
	src := &source{kept: s.conf, full: s.confFull, tooLarge: s.tooLarge, root: ctx.SystemRoot(), links: links}
	if s.kind == engine.Image && s.db["/docker-entrypoint.d/20-envsubst-on-templates.sh"] != nil {
		src.templates(ctx.Env())
	}
	id, like, ver := osRelease(s.read(src, "/etc/os-release", "/usr/lib/os-release"))
	distro := knowledge.DistroOf(id, like)
	release := ver
	if distro == "alpine" {
		release = alpineBranch(string(s.read(src, "/etc/alpine-release")))
	}
	if distro != "" {
		ctx.Annotate("nginxh2_os", id+" "+ver)
	}
	owners := s.owners(src)
	found := assess.Run(assess.Input{
		Binaries: s.binaries,
		Source:   src,
		Owner: func(p string) *pkgdb.Package {
			for _, a := range ctx.Aliases(p) {
				if pk, ok := owners(a); ok {
					return pk
				}
			}
			return nil
		},
		Distro:  distro,
		Release: release,
		Command: ctx.Command(),
		Ingress: s.ingress,
	})
	out := make([]engine.Finding, 0, len(found))
	for _, x := range found {
		out = append(out, finding(x))
	}
	return out
}

func (s *scan) read(src *source, ps ...string) []byte {
	for _, p := range ps {
		if b, ok := s.db[p]; ok {
			return b
		}
		if src.root != "" {
			if b := src.disk(p, maxDB); b != nil {
				return b
			}
		}
	}
	return nil
}

// owners returns a lookup of the package that owns a file, from dpkg's
// status and .list files and apk's database.
func (s *scan) owners(src *source) func(string) (*pkgdb.Package, bool) {
	var dpkg map[string]pkgdb.Package
	if st := s.read(src, "/var/lib/dpkg/status"); st != nil {
		dpkg = pkgdb.DpkgStatus(st)
	}
	apk := map[string]pkgdb.Package{}
	for _, p := range []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"} {
		if b := s.read(src, p); b != nil {
			for k, v := range pkgdb.APKOwners(b) {
				apk[k] = v
			}
		}
	}
	lists := map[string][]byte{}
	for p, b := range s.db {
		if strings.HasPrefix(p, "/var/lib/dpkg/info/") {
			lists[p] = b
		}
	}
	names := make([]string, 0, len(lists))
	for p := range lists {
		names = append(names, p)
	}
	sort.Strings(names)
	return func(p string) (*pkgdb.Package, bool) {
		if pk, ok := apk[p]; ok {
			return &pk, true
		}
		for _, l := range names {
			if pkgdb.ListHas(lists[l], p) {
				if pk, ok := dpkg[pkgdb.DpkgListName(l)]; ok {
					return &pk, true
				}
			}
		}
		return nil, false
	}
}

var verdicts = map[knowledge.Status]engine.Verdict{
	knowledge.Vulnerable:  engine.Vulnerable,
	knowledge.Fixed:       engine.Fixed,
	knowledge.NotAffected: engine.Inactive,
	knowledge.Unknown:     engine.Unknown,
}

func finding(x assess.Finding) engine.Finding {
	v, ok := verdicts[x.Status]
	if !ok {
		v = engine.Unknown
	}
	facts := map[string]string{"status": string(x.Status)}
	for k, val := range x.Facts {
		facts[k] = val
	}
	return engine.Finding{
		Kind:     x.Kind,
		Path:     x.Path,
		Verdict:  v,
		Reason:   x.Reason,
		Message:  x.Message,
		Method:   "binary",
		Facts:    facts,
		CVEs:     []engine.CVEResult{{ID: x.CVE, Verdict: v, Reason: x.Reason}},
		Fix:      x.Fix,
		Severity: x.Severity,
		Details:  x,
	}
}

// osRelease reads ID, ID_LIKE and VERSION_ID.
func osRelease(b []byte) (id, like, ver string) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			like = v
		case "VERSION_ID":
			ver = v
		}
	}
	return
}

// alpineBranch turns "3.24.4" into "3.24"; edge stays "edge".
func alpineBranch(r string) string {
	r = strings.TrimSpace(r)
	parts := strings.Split(r, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return r
}

// source serves configuration files: what the scan kept, and below a
// system root, the root's files from disk.
type source struct {
	kept     map[string][]byte
	full     bool
	tooLarge map[string]bool
	root     string
	links    map[string]string
	// virtual are files the image's entrypoint writes at start
	// (templates), by the path they get.
	virtual map[string][]byte
}

// templates maps the official image's /etc/nginx/templates/*.template to
// the /etc/nginx/conf.d files its entrypoint writes from them.
func (s *source) templates(env []string) {
	dir, out, suffix := "/etc/nginx/templates", "/etc/nginx/conf.d", ".template"
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "NGINX_ENVSUBST_TEMPLATE_DIR":
			dir = v
		case "NGINX_ENVSUBST_OUTPUT_DIR":
			out = v
		case "NGINX_ENVSUBST_TEMPLATE_SUFFIX":
			suffix = v
		}
	}
	dir, out = path.Clean("/"+dir), path.Clean("/"+out)
	for p, b := range s.kept {
		if strings.HasPrefix(p, dir+"/") && strings.HasSuffix(p, suffix) && suffix != "" {
			rel := strings.TrimSuffix(strings.TrimPrefix(p, dir+"/"), suffix)
			if s.virtual == nil {
				s.virtual = map[string][]byte{}
			}
			s.virtual[path.Join(out, rel)] = b
		}
	}
}

// resolve follows symbolic links within the target, as the kernel would.
func (s *source) resolve(p string) string {
	cur := path.Clean("/" + p)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(cur, "/"), "/")
		changed := false
		prefix := "/"
		for i, part := range parts {
			next := path.Join(prefix, part)
			if to, ok := s.links[next]; ok {
				if !strings.HasPrefix(to, "/") {
					to = path.Join(prefix, to)
				}
				cur = path.Clean(path.Join(append([]string{to}, parts[i+1:]...)...))
				changed = true
				break
			}
			prefix = next
		}
		if !changed {
			return cur
		}
	}
	return ""
}

func (s *source) Read(p string) ([]byte, bool, string) {
	if b, ok := s.virtual[p]; ok {
		return b, true, ""
	}
	r := s.resolve(p)
	if r == "" {
		return nil, false, "a symbolic link loop"
	}
	if b, ok := s.virtual[r]; ok {
		return b, true, ""
	}
	if b, ok := s.kept[r]; ok {
		return b, true, ""
	}
	if s.root != "" {
		if b := s.disk(r, maxConf); b != nil {
			return b, true, ""
		}
	}
	switch {
	case s.tooLarge[r]:
		return nil, false, fmt.Sprintf("larger than the %d bytes the detector reads of a configuration file", maxConf)
	case s.full:
		return nil, false, "not kept: the scan reached its limit on configuration files"
	case !keepConf(r):
		return nil, false, "not a file the scan reads as configuration, or not in the target"
	}
	return nil, false, "not in the target, or not readable"
}

func (s *source) Glob(pattern string) ([]string, bool) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, m := range []map[string][]byte{s.kept, s.virtual} {
		for p := range m {
			if ok, _ := path.Match(pattern, p); ok {
				add(p)
			}
		}
	}
	// A directory reached through a symbolic link: match its target's
	// files under the linked name.
	if dir := path.Dir(pattern); !strings.ContainsAny(dir, "*?[") {
		if r := s.resolve(dir); r != "" && r != dir {
			for p := range s.kept {
				if path.Dir(p) == r {
					if ok, _ := path.Match(path.Base(pattern), path.Base(p)); ok {
						add(path.Join(dir, path.Base(p)))
					}
				}
			}
		}
	}
	complete := !s.full && keptByAll(pattern)
	for p := range s.tooLarge {
		if ok, _ := path.Match(pattern, p); ok {
			complete = false
		}
	}
	if s.root != "" {
		if full, ok := s.diskPath(pattern); ok {
			ms, _ := filepath.Glob(full)
			for _, m := range ms {
				rel, err := filepath.Rel(s.root, m)
				if err != nil {
					continue
				}
				p := "/" + filepath.ToSlash(rel)
				if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() {
					add(p)
				}
			}
			complete = !s.full
		}
	}
	sort.Strings(out)
	return out, complete
}

func (s *source) diskPath(p string) (string, bool) {
	clean := path.Clean("/" + p)
	full := filepath.Join(s.root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(s.root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return full, true
}

// disk reads a regular file below the system root, never through a
// symbolic link in any component of its path.
func (s *source) disk(p string, limit int64) []byte {
	full, ok := s.diskPath(p)
	if !ok {
		return nil
	}
	rel, _ := filepath.Rel(s.root, full)
	cur := s.root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return nil
		}
	}
	fi, err := os.Lstat(full)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil
	}
	b, err := os.ReadFile(full)
	if err != nil || int64(len(b)) > limit {
		return nil
	}
	return b
}
