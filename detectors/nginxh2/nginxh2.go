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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	maxDBTotal   = 128 << 20
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
	return strings.HasPrefix(p, "/docker-entrypoint.d/") || unitPath(p)
}

// unitDirs hold systemd units; a unit's drop-ins are in <dir>/<unit>.d.
var unitDirs = []string{"/etc/systemd/system/", "/run/systemd/system/", "/lib/systemd/system/", "/usr/lib/systemd/system/"}

// unitPath reports a systemd service unit or one of its drop-ins.
func unitPath(p string) bool {
	for _, d := range unitDirs {
		if rest, ok := strings.CutPrefix(p, d); ok {
			return strings.HasSuffix(rest, ".service") && !strings.Contains(rest, "/") ||
				strings.Contains(rest, ".service.d/") && strings.HasSuffix(rest, ".conf")
		}
	}
	return false
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
	unread    map[string]string
	unreadAll bool
	dbBytes   int
	ingress   bool
	f5ingress bool
	dropped   int
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if f.Member {
		return nil // installed servers only
	}
	if archive.IsExecutable(f.Data) {
		switch path.Base(f.Path) {
		case "nginx-ingress-controller":
			s.ingress = true
		case "nginx-ingress":
			s.f5ingress = true
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
		if len(f.Data) <= maxDB && s.dbBytes+len(f.Data) <= maxDBTotal {
			s.db[f.Path] = f.Data
			s.dbBytes += len(f.Data)
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

// maxUnread bounds the not-scanned records kept.
const maxUnread = 1 << 16

// VisitSkips records what the walk could not read: a configuration file
// among them leaves exposure unknown, never off.
func (s *scan) VisitSkips(skips []engine.Skip) {
	if s.unread == nil {
		s.unread = map[string]string{}
	}
	for _, sk := range skips {
		if len(s.unread) >= maxUnread {
			s.unreadAll = true
			return
		}
		s.unread[path.Clean("/"+sk.Path)] = sk.Reason
	}
}

func (s *scan) Finish(ctx engine.TargetContext) []engine.Finding {
	if len(s.binaries) == 0 {
		return nil
	}
	if s.dropped > 0 {
		ctx.Problem("nginxh2: more nginx binaries than the detector's limit; some were not checked")
	}
	links, hardlinks := ctx.Links()
	src := &confSource{kept: s.conf, full: s.confFull, tooLarge: s.tooLarge, root: ctx.SystemRoot(), links: links, hardlinks: hardlinks, unread: s.unread, unreadAll: s.unreadAll}
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
		Distro:            distro,
		Release:           release,
		Command:           ctx.Command(),
		CommandFrom:       "the image's command",
		CommandFor:        s.commandFor(),
		EntrypointScripts: s.entrypointScripts(),
		Ingress:           s.ingress,
		Generated:         s.generated(),
	})
	out := make([]engine.Finding, 0, len(found))
	for _, x := range found {
		out = append(out, finding(x))
	}
	return out
}

// entrypointScripts names the files of /docker-entrypoint.d, read or
// not.
func (s *scan) entrypointScripts() []string {
	var out []string
	for p := range s.db {
		if strings.HasPrefix(p, "/docker-entrypoint.d/") {
			out = append(out, strings.TrimPrefix(p, "/docker-entrypoint.d/"))
		}
	}
	for p := range s.unread {
		if strings.HasPrefix(p, "/docker-entrypoint.d/") || p == "/docker-entrypoint.d" {
			out = append(out, strings.TrimPrefix(p, "/docker-entrypoint.d/")+" (not read)")
		}
	}
	sort.Strings(out)
	return out
}

// commandFor returns, for a filesystem, the start command of each binary
// from the systemd units that run it; an image has its own command.
func (s *scan) commandFor() func(string) ([]string, string, string) {
	if s.kind == engine.Image {
		return nil
	}
	units := systemdStarts(s.db)
	return func(bin string) ([]string, string, string) {
		var found [][]string
		var from []string
		for _, u := range units {
			if u.cmd[0] == bin || !strings.HasPrefix(u.cmd[0], "/") && path.Base(u.cmd[0]) == path.Base(bin) {
				found = append(found, u.cmd)
				from = append(from, u.unit)
			}
		}
		switch len(found) {
		case 0:
			return nil, "", "no service unit that starts " + bin + " was found (systemd), so the configuration it loads is not known"
		case 1:
			return found[0], "the service unit " + from[0], ""
		}
		for _, c := range found[1:] {
			if strings.Join(c, "\x00") != strings.Join(found[0], "\x00") {
				return nil, "", "more than one service unit starts " + bin + " (" + strings.Join(from, ", ") + ")"
			}
		}
		return found[0], "the service units " + strings.Join(from, ", "), ""
	}
}

type unitStart struct {
	unit string
	cmd  []string
}

// systemdStarts reads the ExecStart of every service unit that runs an
// nginx build, its drop-ins applied in order ("ExecStart=" clears).
func systemdStarts(db map[string][]byte) []unitStart {
	byName := map[string]string{} // unit name -> path, the first directory wins
	for _, d := range unitDirs {
		var names []string
		for p := range db {
			if rest, ok := strings.CutPrefix(p, d); ok && strings.HasSuffix(rest, ".service") && !strings.Contains(rest, "/") {
				names = append(names, rest)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if _, ok := byName[n]; !ok {
				byName[n] = d + n
			}
		}
	}
	var out []unitStart
	var names []string
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files := []string{byName[n]}
		var drops []string
		for p := range db {
			for _, d := range unitDirs {
				if strings.HasPrefix(p, d+n+".d/") {
					drops = append(drops, p)
				}
			}
		}
		sort.Slice(drops, func(i, j int) bool { return path.Base(drops[i]) < path.Base(drops[j]) })
		files = append(files, drops...)
		var exec []string
		for _, f := range files {
			for _, l := range strings.Split(string(db[f]), "\n") {
				l = strings.TrimSpace(l)
				v, ok := strings.CutPrefix(l, "ExecStart=")
				if !ok {
					continue
				}
				v = strings.TrimLeft(strings.TrimSpace(v), "-@:+!")
				if v == "" {
					exec = nil
					continue
				}
				exec = unitWords(v)
			}
		}
		if len(exec) > 0 && nginxStart(path.Base(exec[0])) {
			out = append(out, unitStart{unit: byName[n], cmd: exec})
		}
	}
	return out
}

func nginxStart(b string) bool {
	switch b {
	case "nginx", "nginx-debug", "openresty", "angie", "tengine":
		return true
	}
	return false
}

// unitWords splits an ExecStart value on white space, with quotes
// grouping and a backslash escaping.
func unitWords(v string) []string {
	var out []string
	var b strings.Builder
	in, q := false, byte(0)
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			q, in = c, true
		case c == '\\' && i+1 < len(v):
			i++
			b.WriteByte(v[i])
			in = true
		case c == ' ' || c == '\t':
			if in {
				out = append(out, b.String())
				b.Reset()
				in = false
			}
		default:
			b.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, b.String())
	}
	return out
}

// generated says why the configuration on disk is not what runs.
func (s *scan) generated() string {
	if s.f5ingress && !s.ingress {
		return "the F5 NGINX Ingress Controller writes nginx.conf at start; HTTP/2 follows its ConfigMap key http2 (off by default) and the VirtualServer and Ingress resources, which the image does not hold"
	}
	return ""
}

func (s *scan) read(src *confSource, ps ...string) []byte {
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
func (s *scan) owners(src *confSource) func(string) (*pkgdb.Package, bool) {
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

// confSource serves configuration files: what the scan kept, and below a
// system root, the root's files from disk.
type confSource struct {
	kept     map[string][]byte
	full     bool
	tooLarge map[string]bool
	root     string
	links    map[string]string
	// hardlinks are an image's hard links (path -> the path it names),
	// which the walk does not hand out as files of their own.
	hardlinks map[string]string
	// unread are the paths the walk recorded as not scanned, with why.
	unread    map[string]string
	unreadAll bool // more not-scanned records than kept: any path may be one
	// virtual are files the image's entrypoint writes at start
	// (templates), by the path they get.
	virtual map[string][]byte
}

// templates maps the official image's /etc/nginx/templates/*.template to
// the /etc/nginx/conf.d files its entrypoint writes from them.
func (s *confSource) templates(env []string) {
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
			s.virtual[path.Join(out, rel)] = envsubst(b, env)
		}
	}
}

// envsubst puts in the image's environment as the entrypoint's envsubst
// does: only variables that are set, $NAME and ${NAME}. A variable left
// as written makes what it decides unknown (internal/conf).
func envsubst(b []byte, env []string) []byte {
	vals := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vals[k] = v
		}
	}
	return envRef.ReplaceAllFunc(b, func(m []byte) []byte {
		name := strings.Trim(string(m), "${}")
		if v, ok := vals[name]; ok {
			return []byte(v)
		}
		return m
	})
}

var envRef = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

// resolve follows symbolic links within the target, as the kernel would.
func (s *confSource) resolve(p string) string {
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

func (s *confSource) Read(p string) ([]byte, bool, string) {
	if b, ok := s.virtual[p]; ok {
		return b, true, ""
	}
	r := s.resolve(p)
	if r == "" {
		return nil, false, "a symbolic link loop"
	}
	if to, ok := s.hardlinks[r]; ok {
		r = to
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
	if why, ok := s.unreadAt(r); ok {
		return nil, false, "not scanned: " + why
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

// unreadAt reports a path, or a directory above it, the walk could not
// read.
func (s *confSource) unreadAt(p string) (string, bool) {
	for q := p; q != "/" && q != "."; q = path.Dir(q) {
		if why, ok := s.unread[q]; ok {
			return why, true
		}
	}
	if s.unreadAll {
		return "more files were not scanned than the detector keeps a record of", true
	}
	return "", false
}

func (s *confSource) Glob(pattern string) ([]string, bool) {
	complete := !s.full
	match := func(pat, p string) bool {
		ok, err := globMatch(pat, p)
		if err != nil {
			complete = false // a pattern nginx's glob(3) reads and this one does not
		}
		return ok
	}
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
			if match(pattern, p) {
				add(p)
			}
		}
	}
	// Symbolic links match too (sites-enabled/default ->
	// ../sites-available/default); Read follows them, and one that leads
	// nowhere the scan read is reported as not read.
	for p := range s.links {
		if match(pattern, p) {
			add(p)
		}
	}
	for p := range s.hardlinks {
		if match(pattern, p) {
			add(p)
		}
	}
	dir, base := path.Dir(pattern), path.Base(pattern)
	wildDir := strings.ContainsAny(dir, "*?[")
	resolved := pattern
	if !wildDir {
		// A directory reached through a symbolic link: its target's files
		// and links, under the linked name. Whether the list is complete
		// is decided on the directory the files are really in.
		switch r := s.resolve(dir); {
		case r == "":
			complete = false
		case r != dir:
			resolved = path.Join(r, base)
			for _, m := range []map[string][]byte{s.kept, s.virtual} {
				for p := range m {
					if path.Dir(p) == r && match(base, path.Base(p)) {
						add(path.Join(dir, path.Base(p)))
					}
				}
			}
			for p := range s.links {
				if path.Dir(p) == r && match(base, path.Base(p)) {
					add(path.Join(dir, path.Base(p)))
				}
			}
		}
	}
	complete = complete && keptByAll(pattern) && keptByAll(resolved)
	// A file or directory the walk could not read where the pattern looks
	// may hold a match.
	for _, pat := range []string{pattern, resolved} {
		d := path.Dir(pat)
		if s.unreadAll {
			complete = false
		}
		for u := range s.unread {
			if u == d || strings.HasPrefix(d, u+"/") || match(pat, u) || strings.ContainsAny(d, "*?[") && strings.HasPrefix(u, d[:strings.IndexAny(d, "*?[")]) {
				complete = false
			}
		}
	}
	for p := range s.tooLarge {
		if match(pattern, p) || match(resolved, p) {
			complete = false
		}
	}
	if s.root != "" {
		// Below a system root the directory is read from disk: every
		// entry, symbolic links included (Read follows them inside the
		// root). A directory that cannot be listed leaves the list
		// incomplete; one that does not exist matches nothing, as for
		// nginx.
		complete = !s.full && !wildDir
		if full, ok := s.diskPath(dir); ok {
			ents, err := os.ReadDir(full)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				complete = false
			}
			for _, e := range ents {
				if match(base, e.Name()) && (e.Type().IsRegular() || e.Type()&fs.ModeSymlink != 0) {
					add(path.Join(dir, e.Name()))
				}
			}
		} else {
			complete = false
		}
	}
	sort.Strings(out)
	return out, complete
}

// globMatch matches a path as nginx's glob(3) does: "[!...]" negates, a
// wildcard does not match a leading dot, and each "/"-separated part
// matches on its own.
func globMatch(pattern, p string) (bool, error) {
	pp, np := strings.Split(pattern, "/"), strings.Split(p, "/")
	if len(pp) != len(np) {
		return false, nil
	}
	for i := range pp {
		pc, err := posixClasses(strings.ReplaceAll(pp[i], "[!", "[^"))
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(np[i], ".") && !strings.HasPrefix(pc, ".") {
			return false, nil
		}
		ok, err := path.Match(pc, np[i])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// posixClasses turns glob(3)'s character classes ([[:digit:]]) into the
// ranges path.Match reads. An unknown class is an error, so the list it
// would give is not taken as complete.
func posixClasses(p string) (string, error) {
	for {
		i := strings.Index(p, "[:")
		if i < 0 {
			return p, nil
		}
		j := strings.Index(p[i:], ":]")
		if j < 0 {
			return "", path.ErrBadPattern
		}
		r, ok := classRanges[p[i+2:i+j]]
		if !ok {
			return "", path.ErrBadPattern
		}
		p = p[:i] + r + p[i+j+2:]
	}
}

var classRanges = map[string]string{"digit": "0-9", "alpha": "a-zA-Z", "alnum": "a-zA-Z0-9", "upper": "A-Z", "lower": "a-z",
	"xdigit": "0-9a-fA-F", "space": " \t", "blank": " \t", "punct": "!-/:-@\\[-`{-~"}

func (s *confSource) diskPath(p string) (string, bool) {
	clean := path.Clean("/" + p)
	full := filepath.Join(s.root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(s.root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return full, true
}

// disk reads a regular file below the system root, following symbolic
// links only while they stay inside it.
func (s *confSource) disk(p string, limit int64) []byte {
	full, ok := s.diskPath(p)
	if !ok {
		return nil
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil
	}
	root, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return nil
	}
	if rel, err := filepath.Rel(root, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscallNoFollow, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil
	}
	return b
}
