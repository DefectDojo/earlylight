// Package sshole is the detector for *sshole, the OpenSSH password
// authentication bypass on musl libc fixed in OpenSSH 10.6p2 (commit
// 4353fdc43, 2026-11-05) and in Alpine's openssh packages the same day. On
// musl, sshd before the fix compares an account's password field of "*"
// with the "*" that musl's crypt returns when it fails, so a password that
// makes crypt fail logs in to that account.
//
// It finds OpenSSH servers in filesystems and container images, judges each
// by its C library, its release and the apk database, and then checks what
// the target's sshd_config and account files make reachable. It also checks
// live servers (what a banner and the offered methods can tell) and the
// Dockerfiles and scripts in a source tree.
//
// internal/assess knows nothing about the engine; this file adapts it.
package sshole

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/sshole/internal/assess"
	"github.com/DefectDojo/earlylight/internal/archive"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// ID is the detector's ID.
const ID = "sshole"

// Kind IDs.
const (
	KindExposed = assess.KindExposed
	KindServer  = assess.KindServer
	KindHost    = "host"
)

// Detector implements engine.Detector, engine.Reader, engine.Prober,
// engine.RepoScanner and engine.Fixer.
type Detector struct{}

func init() { engine.Register(&Detector{}) }

const about = " On musl libc (Alpine, OpenWrt, Void musl, Buildroot and Yocto musl builds), sshd before OpenSSH 10.6p2" +
	" compares an account's password field of \"*\" with the \"*\" musl's crypt returns when it fails. When the first" +
	" account with a sha256, sha512 or bcrypt hash supplies the salt, a password longer than 256 bytes (or any" +
	" password, for bcrypt) logs in to every \"*\" account sshd lets in. Builds that check passwords with PAM" +
	" (UsePAM yes) are not affected. Fixed in OpenSSH 10.6p2 and in Alpine's openssh packages of 2026-11-05."

// Manifest describes the detector.
func (d *Detector) Manifest() engine.Manifest {
	cwe := []string{"CWE-287", "CWE-253"}
	return engine.Manifest{
		ID:    ID,
		Title: "*sshole: OpenSSH password authentication bypass on musl libc",
		Advisories: []string{
			"https://sshhole.com",
			"https://www.openssh.org/releasenotes.html#10.6p2",
			"https://github.com/openssh/openssh-portable/commit/4353fdc43ef646c43a8dda7025cc1a898caf1482",
		},
		Disclosed: "2026-11-05",
		Targets:   []engine.TargetKind{engine.Filesystem, engine.Image, engine.Host, engine.Repository},
		Kinds: append([]engine.Kind{
			{ID: KindExposed, Title: "OpenSSH server accepts a crafted password for an account with password field \"*\"", Level: "error", SecuritySeverity: "9.8", CWEs: cwe,
				Description: "An OpenSSH server on musl without the fix, whose sshd_config allows password logins for an account with the password field \"*\" while another account's hash makes crypt fail. Anyone who can reach the server can log in as that account." + about},
			{ID: KindServer, Title: "OpenSSH server on musl without the *sshole fix", Level: "warning", SecuritySeverity: "6.5", CWEs: cwe,
				Description: "An OpenSSH server on musl without the fix, where the accounts or settings found today do not complete the bypass. A new account with the password field \"*\", a changed sshd_config or a different entrypoint makes it exploitable." + about},
			{ID: KindHost, Title: "Live OpenSSH server that may be exposed to *sshole", Level: "warning", SecuritySeverity: "6.5", CWEs: cwe,
				Description: "A live server whose banner reports an OpenSSH release before 10.6p2 and which offers password logins. A banner does not reveal the C library, so scan the host's filesystem to decide." + about},
		}, repoKinds()...),
		Tags: []string{"security", "openssh", "musl", "alpine", "*sshole"},
		Data: "OpenSSH releases (fixed in 10.6p2, affected from 7.3p1) and Alpine openssh fixed packages for 3.16 to 3.24 and edge, checked 2026-11-05",
	}
}

// Load has nothing to load: the knowledge is in the code.
func (d *Detector) Load() error { return nil }

// Wants reads executables (possible sshd binaries) and the few files the
// verdict depends on.
func (d *Detector) Wants(p string, head []byte, _ bool) bool {
	return archive.IsExecutable(head) || keep(p) || isScript(head)
}

// Limit is the size Visit keeps a file to, so the engine never reads a
// larger one: a start script or an account, package or configuration file
// is never hundreds of MiB. Executables (possible sshd binaries) are read
// whole.
func (d *Detector) Limit(p string, head []byte, _ bool) int64 {
	if archive.IsExecutable(head) {
		return 0
	}
	var most int64
	if isScript(head) {
		most = maxScript
	}
	if keep(p) {
		most = max(most, keptLimit(p))
	}
	return most
}

// keptLimit is the most read of a file the verdict reads: a package
// database can be large (16 MiB, as java4shell's), the others are small.
func keptLimit(p string) int64 {
	switch p {
	case "/lib/apk/db/installed", "/usr/lib/apk/db/installed", "/usr/lib/opkg/status":
		return maxPackageDB
	}
	return maxKept
}

// isScript reports a "#!" script: a container's entrypoint or startup step.
func isScript(head []byte) bool { return len(head) > 2 && head[0] == '#' && head[1] == '!' }

// Limits on the startup scripts kept per target.
const (
	maxScript  = 256 << 10
	maxScripts = 64 << 20
)

// keep reports whether a file's content feeds a verdict: account files,
// the apk database, the Alpine release and anything that can be an
// sshd_config or a file one includes.
func keep(p string) bool {
	switch p {
	case "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/alpine-release", "/etc/os-release", "/usr/lib/os-release",
		"/lib/apk/db/installed", "/usr/lib/apk/db/installed", "/usr/lib/opkg/status":
		return true
	}
	if strings.HasPrefix(p, "/usr/lib/opkg/info/openssh") && strings.HasSuffix(p, ".list") {
		return true
	}
	if strings.HasPrefix(p, "/etc/tcb/") && strings.HasSuffix(p, "/shadow") {
		return true
	}
	base := path.Base(p)
	return strings.Contains(base, "sshd_config") || strings.Contains(p, "/sshd_config.d/") ||
		strings.Contains(path.Dir(p), "ssh") && (strings.HasSuffix(base, ".conf") || strings.HasSuffix(base, "config"))
}

const (
	maxKept      = 4 << 20
	maxPackageDB = 16 << 20
)

// NewScan starts a filesystem or image scan.
func (d *Detector) NewScan(kind engine.TargetKind) engine.Scan {
	return &scan{kind: kind, files: map[string][]byte{}, scripts: map[string][]byte{}, over: map[string]bool{}, unreadScripts: map[string]bool{}, gaps: map[string]bool{}}
}

type scan struct {
	kind        engine.TargetKind
	binaries    []*assess.Binary
	files       map[string][]byte
	scripts     map[string][]byte
	scriptBytes int
	// over holds the files a verdict reads that were not read (over a size
	// limit, or unreadable): present, but their content is unknown.
	over map[string]bool
	// unreadScripts are files that may be start scripts and were not
	// read; unreadDirs directories whose contents were not listed.
	// Past maxUnread, unreadAll stands for the rest.
	unreadScripts map[string]bool
	unreadDirs    []string
	unreadAll     bool
	// gaps are the files that kept a verdict from being decided.
	gaps map[string]bool
}

// maxUnread bounds the unread files and directories one target records.
const maxUnread = 1 << 16

// unread records a file that was not read: its content is unknown.
func (s *scan) unread(p string) {
	if keep(p) {
		s.over[p] = true
	}
	if len(s.unreadScripts) >= maxUnread {
		s.unreadAll = true
		return
	}
	s.unreadScripts[p] = true // its head is not known here: it may be a script
}

// VisitOverLimit records a file the scan asked for and did not get, over
// its limit or --max-file-size. A configuration that includes it, or a
// start script that was not read, never lets a server be cleared, and an
// account file, package database or sshd_config not read is a coverage gap
// once a server is found (FinishSkips). The record here is an exclusion:
// with no OpenSSH server in the target, none of these files matters.
func (s *scan) VisitOverLimit(p string, _ int64) []engine.Skip {
	s.unread(p)
	return nil
}

// VisitUnread records a file or directory the walk could not read, as
// VisitOverLimit does: an include or start script in it is unknown.
func (s *scan) VisitUnread(p string, dir bool) {
	if !dir {
		s.unread(p)
		return
	}
	if len(s.unreadDirs) >= maxUnread {
		s.unreadAll = true
		return
	}
	s.unreadDirs = append(s.unreadDirs, p)
}

// Forget drops what was kept of p: an image names it again.
func (s *scan) Forget(p string) {
	delete(s.files, p)
	if b, ok := s.scripts[p]; ok {
		s.scriptBytes -= len(b)
		delete(s.scripts, p)
	}
	delete(s.over, p)
	delete(s.unreadScripts, p)
	bs := s.binaries[:0]
	for _, b := range s.binaries {
		if b.Path != p {
			bs = append(bs, b)
		}
	}
	s.binaries = bs
}

// FinishSkips reports, when an OpenSSH server was found, the files the
// verdict reads that were not read and the start scripts that kept a
// verdict from being decided, as coverage gaps.
func (s *scan) FinishSkips() []engine.Skip {
	if len(s.binaries) == 0 {
		return nil
	}
	var out []engine.Skip
	for p := range s.over {
		out = append(out, engine.Skip{Path: p, Reason: "not read (over a size limit, or unreadable), and sshole's verdict depends on it; not checked"})
	}
	for p := range s.gaps {
		if !s.over[p] {
			out = append(out, engine.Skip{Path: p, Reason: "not read (over a size limit, or unreadable), and it can start sshd with other settings, so the verdict is unknown"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func (s *scan) Visit(f engine.File) []engine.Skip {
	if f.Member {
		return nil // installed servers only, not copies inside archives
	}
	if isScript(f.Data) {
		if len(f.Data) <= maxScript && s.scriptBytes+len(f.Data) <= maxScripts {
			s.scripts[f.Path] = f.Data
			s.scriptBytes += len(f.Data)
		} else {
			// Read for its other use (a file named like sshd_config) or
			// past the total: not checked as a start script.
			s.unread(f.Path)
			delete(s.over, f.Path) // read as a file the verdict reads
		}
	}
	if keep(f.Path) && int64(len(f.Data)) <= keptLimit(f.Path) && !archive.IsExecutable(f.Data) {
		s.files[f.Path] = f.Data
		return nil
	}
	if b, ok := assess.Inspect(f.Path, f.Data); ok {
		s.binaries = append(s.binaries, b)
	}
	return nil
}

func (s *scan) Finish(ctx engine.TargetContext) []engine.Finding {
	if len(s.binaries) == 0 {
		return nil
	}
	fs := &files{kept: s.files, over: s.over, unreadDirs: s.unreadDirs, root: ctx.SystemRoot()}
	links, _ := ctx.Links()
	res := resolver{links: links, exists: func(p string) bool {
		if ctx.Exists(p) {
			return true
		}
		return fs.root != "" && fs.diskRegular(p)
	}}
	acc := assess.ParseAccounts(fs.Read("/etc/passwd"), fs.Read("/etc/shadow"), fs.Read("/etc/group"), fs.tcb())
	owners := map[string]assess.Package{}
	for _, db := range []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"} {
		if b := fs.Read(db); b != nil {
			for k, v := range assess.APKOwners(b) {
				owners[k] = v
			}
		}
	}
	if st := fs.Read("/usr/lib/opkg/status"); st != nil {
		lists := map[string][]byte{}
		for _, p := range fs.Glob("/usr/lib/opkg/info/openssh*.list") {
			lists[strings.TrimSuffix(path.Base(p), ".list")] = fs.Read(p)
		}
		for k, v := range assess.OpkgOwners(st, lists) {
			owners[k] = v
		}
	}
	branch := assess.BranchFromRelease(string(fs.Read("/etc/alpine-release")))
	if branch != "" {
		ctx.Annotate("alpine_branch", branch)
	}
	found := assess.Run(assess.Input{
		Binaries: s.binaries,
		Owners:   owners,
		Files:    fs,
		Accounts: acc,
		Resolve:  res.resolve,
		Branch:   branch,
		Image:    s.kind == engine.Image,
		Startup:  assess.Startup{Command: ctx.Command(), Scripts: s.scripts, Unread: s.unreadScripts, UnreadDirs: s.unreadDirs, UnreadAll: s.unreadAll},
	})
	out := make([]engine.Finding, 0, len(found))
	for _, x := range found {
		for _, p := range x.Unread {
			if s.unreadScripts[p] || s.over[p] || fs.inUnreadDir(p) {
				s.gaps[p] = true
			}
		}
		out = append(out, finding(x))
	}
	return out
}

var verdicts = map[assess.Status]engine.Verdict{
	assess.Vulnerable: engine.Vulnerable,
	assess.Fixed:      engine.Fixed,
	assess.Inactive:   engine.Inactive,
	assess.Undecided:  engine.Unknown,
}

func finding(x assess.Finding) engine.Finding {
	v, ok := verdicts[x.Status]
	if !ok {
		v = engine.Unknown
	}
	facts := map[string]string{"release": x.Release, "libc": string(x.Libc), "pam_built": yes(x.PAM)}
	if x.Package != nil {
		facts["package"] = x.Package.Name + " " + x.Package.Version
	}
	if x.UsePAM != "" {
		facts["use_pam"] = x.UsePAM
	}
	if x.Password != "" {
		facts["password_auth"] = x.Password
	}
	if x.Donor != nil {
		facts["salt_from"] = x.Donor.Account
		facts["crypt_fails"] = x.Donor.Fails
	}
	if len(x.AtStart) > 0 {
		facts["startup_scripts"] = strings.Join(x.AtStart, ",")
	}
	if x.StartedWith != "" {
		facts["sshd_options_from"] = x.StartedWith
	}
	if len(x.Targets) > 0 {
		var names []string
		for _, t := range x.Targets {
			names = append(names, t.Account)
		}
		facts["accounts"] = strings.Join(names, ",")
	}
	return engine.Finding{
		Kind:     x.Kind,
		Path:     x.Path,
		Verdict:  v,
		Reason:   x.Reason,
		Message:  x.Message,
		Method:   "elf",
		Facts:    facts,
		Fix:      x.Fix,
		Severity: x.Severity,
		Details:  x,
	}
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// files serves kept file contents, and for a walk below a system root, the
// root's own files from disk.
type files struct {
	kept map[string][]byte
	over map[string]bool // present but not read: Read is nil
	// unreadDirs could not be listed: a pattern in one matches a file
	// that cannot be read.
	unreadDirs []string
	root       string
}

// inUnreadDir reports whether p lies in a directory that was not listed.
func (f *files) inUnreadDir(p string) bool {
	for _, d := range f.unreadDirs {
		if p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

func (f *files) Read(p string) []byte {
	if b, ok := f.kept[p]; ok {
		return b
	}
	if f.root == "" || f.over[p] || f.inUnreadDir(p) {
		return nil
	}
	return f.disk(p)
}

func (f *files) diskPath(p string) (string, bool) {
	clean := path.Clean("/" + p)
	full := filepath.Join(f.root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(f.root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return full, true
}

// diskRegular reports whether a regular file is at p below the system
// root, following symbolic links only while they stay inside it. Nothing is
// read.
func (f *files) diskRegular(p string) bool {
	full, ok := f.diskPath(p)
	if !ok {
		return false
	}
	real, err := filepath.EvalSymlinks(full)
	if err != nil {
		return false
	}
	root, err := filepath.EvalSymlinks(f.root)
	if err != nil {
		return false
	}
	if rel, err := filepath.Rel(root, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	fi, err := os.Stat(real)
	return err == nil && fi.Mode().IsRegular()
}

// diskFile returns the OS path of a regular file below the system root,
// reached through no symbolic link in any component of its path. A file
// too large to read is still found: Glob lists it, Read gives nil.
func (f *files) diskFile(p string) (string, bool) {
	full, ok := f.diskPath(p)
	if !ok {
		return "", false
	}
	rel, _ := filepath.Rel(f.root, full)
	cur := f.root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			return "", false
		}
	}
	fi, err := os.Lstat(full)
	return full, err == nil && fi.Mode().IsRegular()
}

// disk reads a regular file below the system root, never through a
// symbolic link in any component of its path.
func (f *files) disk(p string) []byte {
	full, ok := f.diskFile(p)
	if !ok {
		return nil
	}
	fi, err := os.Lstat(full)
	if err != nil || fi.Size() > keptLimit(p) {
		return nil
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil
	}
	return b
}

func (f *files) Glob(pattern string) []string {
	seen := map[string]bool{}
	var out []string
	match := func(p string) {
		if ok, _ := path.Match(pattern, p); ok && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for p := range f.kept {
		match(p)
	}
	for p := range f.over {
		match(p)
	}
	if f.inUnreadDir(path.Dir(pattern)) && !seen[pattern] {
		// What it matches there is unknown: stand for it with the pattern,
		// which Read cannot give.
		seen[pattern] = true
		out = append(out, pattern)
	}
	if f.root != "" {
		if full, ok := f.diskPath(pattern); ok {
			ms, _ := filepath.Glob(full)
			for _, m := range ms {
				rel, err := filepath.Rel(f.root, m)
				if err != nil {
					continue
				}
				p := "/" + filepath.ToSlash(rel)
				if _, ok := f.diskFile(p); !seen[p] && ok {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func (f *files) tcb() map[string][]byte {
	out := map[string][]byte{}
	for _, p := range f.Glob("/etc/tcb/*/shadow") {
		out[path.Base(path.Dir(p))] = f.Read(p)
	}
	return out
}

// resolver follows symbolic links the way the kernel would, component by
// component, within the target.
type resolver struct {
	links  map[string]string
	exists func(string) bool
}

func (r resolver) resolve(p string) (string, bool) {
	cur := path.Clean("/" + p)
	for hops := 0; hops < 40; hops++ {
		parts := strings.Split(strings.TrimPrefix(cur, "/"), "/")
		changed := false
		prefix := "/"
		for i, part := range parts {
			next := path.Join(prefix, part)
			if to, ok := r.links[next]; ok {
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
			return cur, r.exists(cur)
		}
	}
	return cur, false
}
