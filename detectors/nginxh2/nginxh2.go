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
	"crypto/sha256"
	"encoding/hex"
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
	return archive.IsExecutable(head) || keepDB(p) || keepConf(p) || isScript(head)
}

// isScript reports a "#!" script: an entrypoint, or a file one runs.
func isScript(head []byte) bool { return len(head) > 2 && head[0] == '#' && head[1] == '!' }

// Limits on the scripts kept.
const (
	maxScript  = 256 << 10
	maxScripts = 32 << 20
)

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
	return strings.HasPrefix(p, "/docker-entrypoint.d/") || unitPath(p) || strings.HasSuffix(p, ".service") || envFileDir(p)
}

// envFileDir reports a file where units keep their EnvironmentFile
// (/etc/sysconfig/nginx, /etc/default/nginx): kept whole, so one that is
// not kept is not there.
func envFileDir(p string) bool {
	return strings.HasPrefix(p, "/etc/sysconfig/") || strings.HasPrefix(p, "/etc/default/")
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
	kind        engine.TargetKind
	binaries    []*ngx.Binary
	conf        map[string][]byte
	confBytes   int
	confFull    bool            // the limit on configuration files was reached
	tooLarge    map[string]bool // configuration files over maxConf, not kept
	db          map[string][]byte
	scripts     map[string][]byte // "#!" scripts, by path
	units       map[string]map[string]bool
	epSeen      map[string]bool // every file seen under /docker-entrypoint.d
	scriptBytes int
	unread      map[string]string
	unreadAll   bool
	dbBytes     int
	ingress     bool
	f5ingress   bool
	dropped     int
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if f.Member {
		return nil // installed servers only
	}
	if strings.HasPrefix(f.Path, "/docker-entrypoint.d/") {
		// Everything there is run or skipped by the official
		// entrypoint: each file is recorded, and kept to be checked.
		if s.epSeen == nil {
			s.epSeen = map[string]bool{}
		}
		if len(s.epSeen) < maxUnread {
			s.epSeen[f.Path] = true
		} else {
			s.unreadAll = true
		}
		if len(f.Data) <= maxDB && s.dbBytes+len(f.Data) <= maxDBTotal {
			s.db[f.Path] = f.Data
			s.dbBytes += len(f.Data)
		}
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
	if isScript(f.Data) && len(f.Data) <= maxScript && s.scriptBytes+len(f.Data) <= maxScripts {
		if s.scripts == nil {
			s.scripts = map[string][]byte{}
		}
		s.scripts[f.Path] = f.Data
		s.scriptBytes += len(f.Data)
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
	cmds := s.commands(links, hardlinks, workdirOf(ctx), ctx.Env(), ctx.Exists)
	if s.kind == engine.Image && assess.OfficialEntrypointRuns(ctx.Command(), cmds.launcher) && s.db["/docker-entrypoint.d/20-envsubst-on-templates.sh"] != nil {
		// Only then does the entrypoint write the templates.
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
		Distro:      distro,
		Release:     release,
		Command:     ctx.Command(),
		CommandFrom: "the image's command",
		CommandFor:  s.commandFor(src),
		Launcher:    cmds.launcher,
		Starts:      cmds.starts,
		Ingress:     s.ingress,
		Generated:   s.generated(),
	})
	out := make([]engine.Finding, 0, len(found))
	for _, x := range found {
		out = append(out, finding(x))
	}
	return out
}

// commands resolves the words of a target's start command and judges
// the official entrypoint, once per scan.
type commands struct {
	s         *scan
	src       *confSource
	links     map[string]string
	hardlinks map[string]string
	workdir   string
	env       []string
	exists    func(string) bool
	epDone    bool
	epOK      bool
	epWhy     string
	words     map[string]wordAnswer
}

type wordAnswer struct {
	ok  bool
	why string
}

func (s *scan) commands(links, hardlinks map[string]string, workdir string, env []string, exists func(string) bool) *commands {
	return &commands{s: s, src: &confSource{links: links, hardlinks: hardlinks}, links: links, hardlinks: hardlinks,
		workdir: workdir, env: env, exists: exists, words: map[string]wordAnswer{}}
}

// real follows a path's links inside the target ("" for a loop).
func (c *commands) real(p string) string {
	r := c.src.resolve(p)
	if to, ok := c.hardlinks[r]; ok && r != "" {
		r = to
	}
	return r
}

// content is a kept file's bytes, through links.
func (c *commands) content(p string) ([]byte, bool) {
	r := c.real(p)
	if r == "" {
		return nil, false
	}
	if b, ok := c.s.scripts[r]; ok {
		return b, true
	}
	b, ok := c.s.db[r]
	return b, ok
}

// present reports a path that is in the target: a file the walk read or
// kept, or a link, read or not (a PATH search stops at the first).
func (c *commands) present(q string) bool {
	if _, ok := c.links[q]; ok {
		return true
	}
	if _, ok := c.hardlinks[q]; ok {
		return true
	}
	if c.exists != nil && c.exists(q) {
		return true
	}
	if _, ok := c.s.unread[q]; ok {
		return true
	}
	_, ok := c.content(q)
	return ok
}

// resolve resolves a command word as the runtime does.
func (c *commands) resolve(word string) (string, string) {
	return resolveCommand(word, c.workdir, c.env, c.present)
}

// launcher reports whether a word that starts the command is the official
// nginx image's entrypoint (by content), with everything it runs from
// /docker-entrypoint.d read and official.
func (c *commands) launcher(word string) (bool, string) {
	if a, ok := c.words[word]; ok {
		return a.ok, a.why
	}
	ok, why := c.launcherOnce(word)
	c.words[word] = wordAnswer{ok, why}
	return ok, why
}

func (c *commands) launcherOnce(word string) (bool, string) {
	p, why := c.resolve(word)
	if p == "" {
		return false, why
	}
	b, ok := c.content(p)
	if !ok {
		return false, fmt.Sprintf("nginx is started through %s, which was not read", word)
	}
	if !officialScripts["docker-entrypoint.sh"][sha(b)] {
		return false, fmt.Sprintf("nginx is started through %s, which is not the official nginx image's entrypoint and can change the configuration", word)
	}
	if !c.epDone {
		c.epOK, c.epWhy = c.entrypointDir()
		c.epDone = true
	}
	return c.epOK, c.epWhy
}

// starts reports whether a word that starts nginx resolves to the binary
// judged, through the working directory, PATH and links.
func (c *commands) starts(word, binary string) (bool, string) {
	p, why := c.resolve(word)
	if p == "" {
		return false, why
	}
	if r := c.real(p); r == "" || r != c.real(binary) {
		return false, fmt.Sprintf("%s resolves to %s, not to the nginx binary judged (%s), so what it starts is not known", word, p, binary)
	}
	return true, ""
}

// entrypointDir checks /docker-entrypoint.d as the official entrypoint
// runs it (find -follow): every file reachable there, whatever its name,
// size or first line, must have been read and be one of the official
// scripts; a directory link that leads out of it, or anything not read,
// leaves exposure unknown.
func (c *commands) entrypointDir() (bool, string) {
	const dir = "/docker-entrypoint.d"
	s := c.s
	if s.unreadAll {
		return false, "more files were not scanned than the detector keeps a record of, so the entrypoint's scripts are not known"
	}
	if r := c.real(dir); r != dir {
		return false, dir + " is a symbolic link, so what the entrypoint runs is not read"
	}
	if why, ok := s.unread[dir]; ok {
		return false, fmt.Sprintf("the entrypoint runs what is in %s, which was not read (%s)", dir, why)
	}
	var paths []string
	add := func(q string) {
		if strings.HasPrefix(q, dir+"/") {
			paths = append(paths, q)
		}
	}
	for q := range s.epSeen {
		add(q)
	}
	for _, m := range []map[string][]byte{s.scripts, s.db} {
		for q := range m {
			if !s.epSeen[q] {
				add(q)
			}
		}
	}
	for _, m := range []map[string]string{c.links, c.hardlinks, s.unread} {
		for q := range m {
			add(q)
		}
	}
	sort.Strings(paths)
	for _, q := range paths {
		if why, ok := s.unread[q]; ok {
			return false, fmt.Sprintf("the entrypoint runs what is in %s, and %s was not read (%s)", dir, q, why)
		}
		if _, isLink := c.links[q]; isLink {
			t := c.real(q)
			if t == "" || !strings.HasPrefix(t, dir+"/") {
				if _, read := c.content(q); !read {
					return false, fmt.Sprintf("%s leads out of %s to %s, which the scan does not read whole", q, dir, t)
				}
			}
		}
		b, read := c.content(q)
		if !read {
			if _, isLink := c.links[q]; isLink && strings.HasPrefix(c.real(q), dir+"/") {
				continue // a link to a directory inside: its files are listed themselves
			}
			return false, fmt.Sprintf("the entrypoint runs what is in %s, and %s was not read", dir, q)
		}
		if !officialScripts[path.Base(q)][sha(b)] {
			return false, fmt.Sprintf("%s holds %s, which is not one of the official image's scripts and can change the configuration", dir, q)
		}
	}
	return true, ""
}

// defaultPath is the PATH a container runs with when its image sets none.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// resolveCommand resolves a command word as the runtime does: an absolute
// path as written, one with a slash against the working directory, a bare
// name through the image's PATH. "" when nothing is found.
func resolveCommand(word, workdir string, env []string, exists func(string) bool) (string, string) {
	if strings.HasPrefix(word, "/") {
		return path.Clean(word), ""
	}
	if workdir == "" {
		workdir = "/"
	}
	if strings.Contains(word, "/") {
		return path.Join("/", workdir, word), ""
	}
	pathVar, set := defaultPath, false
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathVar, set = v, true
		}
	}
	for _, d := range strings.Split(pathVar, ":") {
		if d == "" {
			d = workdir
		}
		if !strings.HasPrefix(d, "/") {
			d = path.Join("/", workdir, d)
		}
		if p := path.Join(d, word); exists(p) {
			return p, ""
		}
	}
	from := "the default PATH"
	if set {
		from = "the image's PATH"
	}
	return "", fmt.Sprintf("nginx is started through %s, which is not found on %s, so what it runs is not known", word, from)
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// commandFor returns, for a filesystem, the start command of each binary
// from the systemd units that run it; an image has its own command.
func (s *scan) commandFor(src *confSource) func(string) ([]string, string, string) {
	if s.kind == engine.Image {
		return nil
	}
	units, unsure := s.systemdStarts(src)
	return func(bin string) ([]string, string, string) {
		if unsure != "" {
			return nil, "", unsure
		}
		var found [][]string
		var from []string
		for _, u := range units {
			if u.cmd[0] == bin || !strings.HasPrefix(u.cmd[0], "/") && path.Base(u.cmd[0]) == path.Base(bin) {
				if u.unsure != "" {
					return nil, "", u.unsure
				}
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
	unit   string
	cmd    []string
	unsure string // why this unit's start is not read in full
}

// unitFiles lists the names in a unit directory: files the walk read,
// links, records of files not read, and below a system root the
// directory on disk. why is set when the directory could not be listed.
func (s *scan) unitFiles(src *confSource, dir string) (names map[string]bool, why string) {
	names = map[string]bool{}
	for n := range s.unitIndex(src)[dir] {
		names[n] = true
	}
	if w, ok := src.unreadAt(dir); ok {
		why = dir + " was not read (" + w + ")"
	}
	if src.root != "" {
		if full, ok := src.diskPath(dir); ok {
			ents, err := os.ReadDir(full)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				why = dir + " could not be listed (" + err.Error() + ")"
			}
			for _, e := range ents {
				names[e.Name()] = true
			}
		}
	}
	return names, why
}

// unitIndex lists, once per scan, the names in each directory under the
// unit directories (files read, links, records of files not read), so a
// unit's drop-in directories are looked up, not searched for.
func (s *scan) unitIndex(src *confSource) map[string]map[string]bool {
	if s.units != nil {
		return s.units
	}
	s.units = map[string]map[string]bool{}
	add := func(p string) {
		for _, d := range unitDirs {
			if strings.HasPrefix(p, d) {
				dir := path.Dir(p)
				if s.units[dir] == nil {
					s.units[dir] = map[string]bool{}
				}
				s.units[dir][path.Base(p)] = true
				return
			}
		}
	}
	for p := range s.db {
		add(p)
	}
	for _, m := range []map[string]string{src.links, src.hardlinks, s.unread} {
		for p := range m {
			add(p)
		}
	}
	return s.units
}

// unitRead reads a unit or drop-in, following links inside the target.
func (s *scan) unitRead(src *confSource, p string) ([]byte, string, bool) {
	r := src.resolve(p)
	if r == "" {
		return nil, "", false
	}
	if to, ok := src.hardlinks[r]; ok {
		r = to
	}
	if r == "/dev/null" {
		return nil, "/dev/null", true // masked
	}
	if b, ok := s.db[r]; ok {
		return b, r, true
	}
	if src.root != "" {
		if b := src.disk(r, maxDB); b != nil {
			return b, r, true
		}
	}
	return nil, r, false
}

// systemdStarts reads every service unit that runs an nginx build: the
// unit of the first directory that has it (/etc, /run, /lib, /usr/lib),
// its drop-ins from every directory applied in order ("ExecStart="
// clears), links followed inside the target. A unit or drop-in that was
// not read, or a command run before or after nginx starts other than an
// nginx test, makes that start unsure; a unit directory that could not
// be read makes every start unsure.
func (s *scan) systemdStarts(src *confSource) ([]unitStart, string) {
	byName := map[string]string{} // unit name -> path, the first directory wins
	var names []string
	for _, d := range unitDirs {
		d = strings.TrimSuffix(d, "/")
		ns, why := s.unitFiles(src, d)
		if why != "" {
			return nil, "a systemd unit directory " + why + ", so the unit that starts nginx is not known"
		}
		for n := range ns {
			if strings.HasSuffix(n, ".service") {
				if _, ok := byName[n]; !ok {
					byName[n] = d + "/" + n
					names = append(names, n)
				}
			}
		}
	}
	sort.Strings(names)
	var out []unitStart
	for _, n := range names {
		u := unitStart{unit: byName[n]}
		b, real, ok := s.unitRead(src, byName[n])
		if real == "/dev/null" {
			continue // masked: not started
		}
		files := [][]byte{b}
		if !ok {
			u.unsure = byName[n] + " was not read"
			if why, un := src.unreadAt(real); un {
				u.unsure += " (" + why + ")"
			}
		}
		var drops []string
		for _, d := range unitDirs {
			dd := strings.TrimSuffix(d, "/") + "/" + n + ".d"
			ns, why := s.unitFiles(src, dd)
			if why != "" && u.unsure == "" {
				u.unsure = "the drop-in directory " + why
			}
			for f := range ns {
				if strings.HasSuffix(f, ".conf") {
					drops = append(drops, dd+"/"+f)
				}
			}
		}
		sort.Slice(drops, func(i, j int) bool { return path.Base(drops[i]) < path.Base(drops[j]) })
		for _, dp := range drops {
			db, _, ok := s.unitRead(src, dp)
			if !ok && u.unsure == "" {
				u.unsure = "the drop-in " + dp + " was not read"
			}
			files = append(files, db)
		}
		var exec string
		var around []string
		var envs []string     // Environment= assignments, in order
		var envFiles []string // EnvironmentFile= paths, "-" kept
		pidFile := ""
		for _, f := range files {
			for _, l := range strings.Split(string(f), "\n") {
				l = strings.TrimSpace(l)
				k, v, ok := strings.Cut(l, "=")
				if !ok {
					continue
				}
				v = strings.TrimSpace(v)
				x := strings.TrimLeft(v, "-@:+!")
				switch strings.TrimSpace(k) {
				case "ExecStart":
					exec = x
				case "ExecStartPre", "ExecStartPost", "ExecCondition":
					if x == "" {
						around = nil
					} else {
						around = append(around, x)
					}
				case "Environment":
					if v == "" {
						envs = nil
					} else {
						envs = append(envs, unitWords(v)...)
					}
				case "EnvironmentFile":
					if v == "" {
						envFiles = nil
					} else {
						envFiles = append(envFiles, v)
					}
				case "PIDFile":
					pidFile = v
				}
			}
		}
		if exec == "" {
			continue
		}
		// EnvironmentFile= overrides Environment=, whatever their order.
		env := map[string]string{}
		for _, kv := range envs {
			if k, v, ok := strings.Cut(kv, "="); ok {
				env[k] = v
			}
		}
		for _, ef := range envFiles {
			optional := strings.HasPrefix(ef, "-")
			ef = strings.TrimPrefix(ef, "-")
			b, real, ok := s.unitRead(src, ef)
			_, unread := src.unreadAt(real)
			switch {
			case unread && u.unsure == "":
				u.unsure = fmt.Sprintf("%s reads its environment from %s, which was not read", u.unit, ef)
			case !ok && !optional && u.unsure == "":
				u.unsure = fmt.Sprintf("%s reads its environment from %s, which is not in the target", u.unit, ef)
			case !ok && src.root == "" && !envFileDir(real) && !unitPath(real) && u.unsure == "":
				// Optional, but outside what the scan reads whole: whether
				// it is there is not known.
				u.unsure = fmt.Sprintf("%s reads its environment from %s, which the scan does not read", u.unit, ef)
			case ok:
				for k, v := range envFile(b) {
					env[k] = v
				}
			}
		}
		cmd := expandUnit(exec, env)
		if len(cmd) == 0 || !nginxStart(path.Base(cmd[0])) {
			continue
		}
		u.cmd = cmd
		for _, a := range around {
			w := expandUnit(a, env)
			if !harmless(w, pidFile) && u.unsure == "" {
				u.unsure = fmt.Sprintf("%s runs %q before or after nginx starts, which can change the configuration", u.unit, a)
			}
		}
		out = append(out, u)
	}
	return out, ""
}

// envFile reads an EnvironmentFile: KEY=VALUE lines, # and ; comments,
// quotes removed.
func envFile(b []byte) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		l = strings.TrimPrefix(l, "export ")
		k, v, ok := strings.Cut(l, "=")
		if !ok || len(out) >= 1024 {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

// expandUnit splits an Exec line into words and puts in the unit's
// environment as systemd does: a word that is one $NAME becomes the
// value's words (none when empty); ${NAME} inside a word is replaced in
// place; an unset variable is empty.
func expandUnit(line string, env map[string]string) []string {
	var out []string
	for _, w := range unitWords(line) {
		if m := bareUnitVar.FindStringSubmatch(w); m != nil {
			out = append(out, strings.Fields(env[m[1]])...)
			continue
		}
		out = append(out, bracedUnitVar.ReplaceAllStringFunc(w, func(r string) string {
			return env[r[2:len(r)-1]]
		}))
	}
	return out
}

var (
	bareUnitVar   = regexp.MustCompile(`^\$([A-Za-z_][A-Za-z0-9_]*)$`)
	bracedUnitVar = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)
)

// harmless reports a command run around nginx's start that cannot change
// its configuration: an nginx test, or rm -f of the pid file.
func harmless(w []string, pidFile string) bool {
	if len(w) == 0 {
		return false
	}
	if nginxStart(path.Base(w[0])) {
		return nginxTest(w[1:])
	}
	if path.Base(w[0]) != "rm" {
		return false
	}
	files := 0
	for _, a := range w[1:] {
		switch {
		case a == "-f" || a == "--force":
		case strings.HasPrefix(a, "-"):
			return false
		case strings.HasSuffix(a, ".pid") || a == pidFile && pidFile != "":
			files++
		default:
			return false
		}
	}
	return files > 0
}

// nginxTest reports nginx arguments that only test or show the
// configuration (-t, -T, -q, -g, -c, -p): they serve nothing.
func nginxTest(args []string) bool {
	test := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			return false
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 't', 'T':
				test = true
			case 'q':
			case 'g', 'c', 'p', 'e':
				if j == len(a)-1 {
					i++
				}
				j = len(a)
			default:
				return false
			}
		}
	}
	return test
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

// workdirOf is an image's working directory, "" when the target has none.
func workdirOf(ctx engine.TargetContext) string {
	if w, ok := ctx.(engine.WorkingDirer); ok {
		return w.WorkingDir()
	}
	return ""
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
	index     *globIndex
	wildGlobs int
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

// globIndex is what Glob looks through, by directory: the files kept, the
// virtual ones, the links, the not-scanned records and the files too large
// to keep. It is built on the first glob.
type globIndex struct {
	files, unread, large map[string][]string
	disk                 map[string]diskList
}

type diskList struct {
	names []string // regular files and links
	err   bool     // the directory could not be listed
}

// maxWildGlobs bounds the globs with a wildcard in their directory part,
// which are matched against every path: past it a glob is not complete.
const maxWildGlobs = 64

func (s *confSource) idx() *globIndex {
	if s.index != nil {
		return s.index
	}
	x := &globIndex{files: map[string][]string{}, unread: map[string][]string{}, large: map[string][]string{}, disk: map[string]diskList{}}
	for _, m := range []map[string][]byte{s.kept, s.virtual} {
		for p := range m {
			x.files[path.Dir(p)] = append(x.files[path.Dir(p)], p)
		}
	}
	for _, m := range []map[string]string{s.links, s.hardlinks} {
		for p := range m {
			x.files[path.Dir(p)] = append(x.files[path.Dir(p)], p)
		}
	}
	for p := range s.unread {
		x.unread[path.Dir(p)] = append(x.unread[path.Dir(p)], p)
	}
	for p := range s.tooLarge {
		x.large[path.Dir(p)] = append(x.large[path.Dir(p)], p)
	}
	s.index = x
	return x
}

// diskDir lists a directory below the system root, once.
func (s *confSource) diskDir(dir string) diskList {
	x := s.idx()
	if l, ok := x.disk[dir]; ok {
		return l
	}
	var l diskList
	if full, ok := s.diskPath(dir); ok {
		ents, err := os.ReadDir(full)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			l.err = true
		}
		for _, e := range ents {
			if e.Type().IsRegular() || e.Type()&fs.ModeSymlink != 0 {
				l.names = append(l.names, e.Name())
			}
		}
	} else {
		l.err = true
	}
	x.disk[dir] = l
	return l
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
	x := s.idx()
	dir, base := path.Dir(pattern), path.Base(pattern)
	if strings.ContainsAny(dir, "*?[") {
		// A wildcard in the directory part: every path is a candidate, so
		// only a few such globs are matched.
		s.wildGlobs++
		if s.wildGlobs > maxWildGlobs {
			return nil, false
		}
		if s.root != "" {
			return s.diskGlob(pattern)
		}
		for _, ps := range x.files {
			for _, p := range ps {
				if match(pattern, p) {
					add(p)
				}
			}
		}
		prefix := dir[:strings.IndexAny(dir, "*?[")]
		for _, ps := range x.unread {
			for _, u := range ps {
				if strings.HasPrefix(u, prefix) {
					complete = false
				}
			}
		}
		for _, ps := range x.large {
			for _, p := range ps {
				if match(pattern, p) {
					complete = false
				}
			}
		}
		if _, ok := s.unreadAt(prefix); ok || s.unreadAll {
			complete = false
		}
		sort.Strings(out)
		return out, complete && keptByAll(pattern)
	}
	// Symbolic and hard links match too (sites-enabled/default ->
	// ../sites-available/default); Read follows them, and one that leads
	// nowhere the scan read is reported as not read.
	for _, p := range x.files[dir] {
		if match(pattern, p) {
			add(p)
		}
	}
	resolved := pattern
	switch r := s.resolve(dir); {
	case r == "":
		complete = false
	case r != dir:
		// A directory reached through a symbolic link: its target's files
		// and links, under the linked name. Whether the list is complete
		// is decided on the directory the files are really in.
		resolved = path.Join(r, base)
		for _, p := range x.files[r] {
			if match(base, path.Base(p)) {
				add(path.Join(dir, path.Base(p)))
			}
		}
	}
	complete = complete && keptByAll(pattern) && keptByAll(resolved)
	// A file or directory the walk could not read where the pattern looks
	// may hold a match.
	for _, pat := range []string{pattern, resolved} {
		d := path.Dir(pat)
		if _, ok := s.unreadAt(d); ok {
			complete = false
		}
		for _, u := range x.unread[d] {
			if match(pat, u) {
				complete = false
			}
		}
		for _, p := range x.large[d] {
			if match(pat, p) {
				complete = false
			}
		}
	}
	if s.root != "" {
		// Below a system root the directory is read from disk: every
		// entry, symbolic links included (Read follows them inside the
		// root). A directory that cannot be listed leaves the list
		// incomplete; one that does not exist matches nothing, as for
		// nginx. What the walk recorded as not read still counts.
		diskComplete := !s.full
		l := s.diskDir(dir)
		if l.err {
			diskComplete = false
		}
		for _, n := range l.names {
			if match(base, n) {
				add(path.Join(dir, n))
			}
		}
		walkGap := false
		for _, pat := range []string{pattern, resolved} {
			if _, ok := s.unreadAt(path.Dir(pat)); ok {
				walkGap = true
			}
		}
		complete = diskComplete && !walkGap
	}
	sort.Strings(out)
	return out, complete
}

// maxDiskGlobEntries bounds the directory entries one wildcard glob
// reads from disk below a system root.
const maxDiskGlobEntries = 20000

// diskGlob matches a pattern with a wildcard in its directory part
// against the disk below the system root, one part at a time, as glob(3)
// does: directories (links to directories too) for the middle parts,
// regular files and links for the last. A directory that cannot be
// listed, one the walk did not read, or more entries than the bound
// leaves the list incomplete.
func (s *confSource) diskGlob(pattern string) ([]string, bool) {
	parts := strings.Split(strings.TrimPrefix(path.Clean(pattern), "/"), "/")
	complete, seen := !s.full, 0
	cur := []string{"/"}
	for i, part := range parts {
		last := i == len(parts)-1
		var next []string
		for _, dir := range cur {
			if _, ok := s.unreadAt(dir); ok && dir != "/" {
				complete = false
			}
			if !strings.ContainsAny(part, "*?[") {
				p := path.Join(dir, part)
				if full, ok := s.diskPath(p); ok {
					if fi, err := os.Stat(full); err == nil && (last && fi.Mode().IsRegular() || !last && fi.IsDir()) {
						next = append(next, p)
					}
				}
				continue
			}
			full, ok := s.diskPath(dir)
			if !ok {
				complete = false
				continue
			}
			ents, err := os.ReadDir(full)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					complete = false
				}
				continue
			}
			for _, e := range ents {
				if seen++; seen > maxDiskGlobEntries {
					return nil, false
				}
				ok, err := globMatch(part, e.Name())
				if err != nil {
					complete = false
				}
				if !ok {
					continue
				}
				p := path.Join(dir, e.Name())
				fi, err := os.Stat(filepath.Join(full, e.Name()))
				if err != nil {
					if e.Type()&fs.ModeSymlink != 0 && last {
						next = append(next, p) // Read reports it as not read
					}
					continue
				}
				if last && fi.Mode().IsRegular() || !last && fi.IsDir() {
					next = append(next, p)
				}
			}
		}
		cur = next
	}
	if s.unreadAll {
		complete = false
	}
	sort.Strings(cur)
	return cur, complete
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
		// The closing ":]" is looked for after the opening "[:", so "[:]"
		// does not close on itself.
		j := strings.Index(p[i+2:], ":]")
		if j < 0 {
			return "", path.ErrBadPattern
		}
		r, ok := classRanges[p[i+2:i+2+j]]
		if !ok {
			return "", path.ErrBadPattern
		}
		p = p[:i] + r + p[i+2+j+2:]
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
