// Package assess decides, for each nginx binary and each CVE of the pair,
// what the binary proves (vulnerable, fixed, not affected, unknown) and
// what the configuration it loads says about exposure. Exposure never
// changes a verdict: a server with HTTP/2 off still needs the update. It
// knows nothing about the engine.
package assess

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/conf"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/ngx"
	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/pkgdb"
)

// Kind IDs, one per CVE.
const (
	KindFlow  = "flow-control"
	KindReuse = "connection-reuse"
)

// KindOf is the kind for a CVE.
func KindOf(cve string) string {
	if cve == knowledge.Reuse {
		return KindReuse
	}
	return KindFlow
}

// Input is one target.
type Input struct {
	Binaries []*ngx.Binary
	// Source serves configuration files.
	Source conf.Source
	// Owner returns the package that owns a binary, nil when none does or
	// the database was not read.
	Owner func(p string) *pkgdb.Package
	// Distro is the os-release family (debian, ubuntu, alpine, rhel) and
	// Release its VERSION_ID (Alpine: the branch).
	Distro, Release string
	// Command is what an image's container runs.
	Command []string
	// Ingress is set when the target holds the ingress-nginx controller,
	// which writes nginx.conf at start.
	Ingress bool
}

// Finding is one CVE's verdict on one binary.
type Finding struct {
	CVE      string            `json:"cve"`
	Kind     string            `json:"kind"`
	Path     string            `json:"path"`
	Status   knowledge.Status  `json:"status"`
	Reason   string            `json:"reason"`
	Message  string            `json:"message"`
	Fix      string            `json:"fix,omitempty"`
	Severity string            `json:"severity,omitempty"`
	State    conf.State        `json:"exposure"`
	Facts    map[string]string `json:"facts"`
	Binary   *ngx.Binary       `json:"binary"`
	Package  *pkgdb.Package    `json:"package,omitempty"`
	Config   *conf.Exposure    `json:"config,omitempty"`
}

// Run judges every binary.
func Run(in Input) []Finding {
	var out []Finding
	cache := map[string]cached{}
	for _, b := range in.Binaries {
		main, extra, how := configFor(b, in.Command)
		exp, cfgFiles := exposure(in, main, extra, cache)
		var pkg *pkgdb.Package
		if in.Owner != nil {
			pkg = in.Owner(b.Path)
		}
		for _, c := range knowledge.CVEs {
			st, why := judge(c, b)
			st, why = backport(c, st, why, b, pkg, in)
			f := Finding{CVE: c.ID, Kind: KindOf(c.ID), Path: b.Path, Status: st, Reason: why, Binary: b, Package: pkg, Config: exp}
			f.State = stateFor(c.ID, exp)
			f.Facts = facts(b, pkg, exp, f.State, main, how, cfgFiles, in)
			f.Message = message(c, b, f)
			f.Fix = fixText(f, pkg, in.Distro)
			if st == knowledge.Vulnerable {
				f.Severity = severity(f.State)
			}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].CVE < out[j].CVE
	})
	return out
}

func stateFor(cve string, e *conf.Exposure) conf.State {
	if e == nil {
		return conf.Unknown
	}
	if cve == knowledge.Reuse {
		return e.Reuse
	}
	return e.Flow
}

// judge decides from the binary alone.
func judge(c knowledge.CVE, b *ngx.Binary) (knowledge.Status, string) {
	if b.Conflict != "" {
		return knowledge.Unknown, b.Conflict + ": not judged by either"
	}
	var st knowledge.Status
	var why string
	switch b.Product {
	case ngx.Hidden:
		st, why = knowledge.Unknown, "an nginx binary without a readable version line (renamed, patched or stripped of it): it is never cleared"
		if b.HTTP2 == ngx.No {
			why += "; its configure arguments do not include HTTP/2, which would make it not affected if they are the build's own"
		}
		return st, why
	case ngx.Other:
		return knowledge.Unknown, fmt.Sprintf("an nginx build that names itself %q in its version line: what it is based on is not known", b.Name+"/"+b.Version)
	case ngx.Nginx:
		v, err := knowledge.ParseV(b.Version)
		if err != nil {
			return knowledge.Unknown, "its version could not be read: " + err.Error()
		}
		st, why = knowledge.Nginx(c, v)
	case ngx.OpenResty:
		v, err := knowledge.ParseV(b.Version)
		if err != nil {
			return knowledge.Unknown, "its OpenResty version could not be read: " + err.Error()
		}
		st, why = knowledge.OpenResty(c, v)
	case ngx.Tengine:
		v, err := knowledge.ParseV(b.Version)
		if err != nil {
			return knowledge.Unknown, "its Tengine version could not be read: " + err.Error()
		}
		core, _ := knowledge.ParseV(b.Core)
		st, why = knowledge.Tengine(c, v, core)
	case ngx.Angie:
		v, err := knowledge.ParseV(b.Version)
		if err != nil {
			return knowledge.Unknown, "its Angie version could not be read: " + err.Error()
		}
		st, why = knowledge.Angie(c, v)
	case ngx.Plus:
		core, _ := knowledge.ParseV(b.Core)
		st, why = knowledge.Plus(c, b.PlusRelease, core)
	default:
		return knowledge.Unknown, "not an nginx build the detector knows"
	}
	if b.HTTP2 == ngx.No && (st == knowledge.Vulnerable || st == knowledge.Unknown) {
		return knowledge.NotAffected, "built without HTTP/2: its configure arguments do not have --with-http_v2_module and it has no ngx_http_v2_module, so the flawed code is not in it"
	}
	return st, why
}

// backport clears a vulnerable distribution build when the backport table
// lists a fixed package and the binary is that package's build: the
// package database names it the owner, and its version is the package's
// upstream version. No row exists yet (FACTS.md).
func backport(c knowledge.CVE, st knowledge.Status, why string, b *ngx.Binary, pkg *pkgdb.Package, in Input) (knowledge.Status, string) {
	if st != knowledge.Vulnerable || pkg == nil || in.Distro == "" || knowledge.NginxOrgMaintainer(pkg.Maintainer) {
		return st, why
	}
	up, err := knowledge.UpstreamOf(pkg.Version)
	if err != nil || up.String() != b.Version {
		return st, why
	}
	for _, r := range knowledge.Backports {
		if r.Distro != in.Distro || r.Release != "" && r.Release != in.Release || r.Package != pkg.Source || !has(r.CVEs, c.ID) {
			continue
		}
		cmp, ok := 0, true
		switch pkg.Manager {
		case "dpkg":
			cmp = pkgdb.CompareDpkg(pkg.Version, r.Fixed)
		case "apk":
			cmp, ok = pkgdb.CompareAPK(pkg.Version, r.Fixed)
		default:
			ok = false
		}
		if !ok {
			return knowledge.Unknown, why + fmt.Sprintf("; its package version %s could not be compared with the backport %s", pkg.Version, r.Fixed)
		}
		if cmp >= 0 {
			return knowledge.Fixed, fmt.Sprintf("%s %s carries the backported fix (%s, fixed in %s; %s)", pkg.Name, pkg.Version, r.Distro, r.Fixed, r.Advisory)
		}
	}
	return st, why
}

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// configFor returns the configuration file a binary loads: the image
// command's -c (and -p) when the command runs nginx, else the binary's
// compiled-in default. extra are -g directives.
func configFor(b *ngx.Binary, cmd []string) (string, []conf.Directive, string) {
	main, how := b.ConfPath, "the binary's default"
	prefix := b.Prefix
	var extra []conf.Directive
	if args, ok := nginxArgs(cmd); ok {
		for i := 0; i < len(args); i++ {
			a := args[i]
			val := func(flag string) (string, bool) {
				if a == flag && i+1 < len(args) {
					i++
					return args[i], true
				}
				if strings.HasPrefix(a, flag) && len(a) > len(flag) {
					return a[len(flag):], true
				}
				return "", false
			}
			if v, ok := val("-c"); ok {
				main, how = v, "the container command's -c"
			} else if v, ok := val("-p"); ok {
				prefix = v
			} else if v, ok := val("-g"); ok {
				if ds, err := conf.Parse("-g", v); err == nil {
					extra = append(extra, ds...)
				}
			}
		}
	}
	if main == "" {
		main = "/usr/local/nginx/conf/nginx.conf"
		how = "nginx's default"
	}
	if !strings.HasPrefix(main, "/") && prefix != "" {
		main = path.Join(prefix, main)
	}
	return path.Clean("/" + main), extra, how
}

// nginxArgs returns the arguments after the first word of the command
// that runs nginx (or openresty, angie, tengine), as an entrypoint script
// passes them on.
func nginxArgs(cmd []string) ([]string, bool) {
	for i, w := range cmd {
		switch path.Base(w) {
		case "nginx", "openresty", "angie", "tengine", "nginx-debug":
			return cmd[i+1:], true
		}
	}
	return nil, false
}

type cached struct {
	e     *conf.Exposure
	files int
}

func exposure(in Input, main string, extra []conf.Directive, cache map[string]cached) (*conf.Exposure, int) {
	if in.Ingress {
		e := &conf.Exposure{HTTP2: "on", Flow: conf.Exposed, Reuse: conf.Exposed,
			Where: []string{"ingress-nginx writes nginx.conf at start: HTTP/2 is on by default (ConfigMap use-http2, default true) on its TLS listeners, and every Ingress is proxied"}}
		return e, 0
	}
	if in.Source == nil {
		return nil, 0
	}
	key := main + "\x00" + fmt.Sprint(extra)
	if c, ok := cache[key]; ok {
		return c.e, c.files
	}
	c := conf.Load(in.Source, main, extra)
	e := conf.Analyze(c)
	cache[key] = cached{&e, len(c.Files)}
	return &e, len(c.Files)
}

func severity(s conf.State) string {
	switch s {
	case conf.Exposed:
		return "critical"
	case conf.Unknown:
		return "high"
	}
	return "medium"
}

func facts(b *ngx.Binary, pkg *pkgdb.Package, e *conf.Exposure, st conf.State, main, how string, files int, in Input) map[string]string {
	f := map[string]string{"product": string(b.Product), "http2_module": string(b.HTTP2), "tls_module": string(b.TLS), "exposure": string(st), "config": main, "config_from": how}
	if b.Version != "" {
		f["version"] = b.Version
	}
	if b.Core != "" && b.Core != b.Version {
		f["nginx_core"] = b.Core
	}
	if b.Build != "" {
		f["build"] = b.Build
	}
	if b.Bits != 0 {
		f["bits"] = fmt.Sprint(b.Bits)
	}
	if b.Arch != "" {
		f["arch"] = b.Arch
	}
	if pkg != nil {
		f["package"] = pkg.Name + " " + pkg.Version
	}
	if in.Distro != "" {
		f["distro"] = in.Distro
		if in.Release != "" {
			f["distro"] += " " + in.Release
		}
	}
	if e != nil {
		f["http2"] = e.HTTP2
		if len(e.Where) > 0 {
			f["http2_where"] = strings.Join(e.Where, ", ")
		}
		if len(e.Proxy) > 0 {
			f["proxy_where"] = strings.Join(e.Proxy, ", ")
		}
		if e.WorkerConnections != "" {
			f["worker_connections"] = e.WorkerConnections
		}
		if files > 0 {
			f["config_files"] = fmt.Sprint(files)
		}
	}
	return f
}

func productName(b *ngx.Binary) string {
	switch b.Product {
	case ngx.Hidden:
		return "nginx (version not readable)"
	case ngx.Plus:
		return "NGINX Plus " + b.PlusRelease + " (nginx " + b.Version + ")"
	case ngx.OpenResty:
		return "OpenResty " + b.Version
	case ngx.Tengine:
		return "Tengine " + b.Version
	case ngx.Angie:
		return "Angie " + b.Version
	}
	return b.Name + " " + b.Version
}

func message(c knowledge.CVE, b *ngx.Binary, f Finding) string {
	var verb string
	switch f.Status {
	case knowledge.Vulnerable:
		verb = "is vulnerable to"
	case knowledge.Fixed:
		verb = "has the fix for"
	case knowledge.NotAffected:
		verb = "is not affected by"
	default:
		verb = "may be vulnerable to"
	}
	m := fmt.Sprintf("%s at %s %s %s (%s): %s.", productName(b), b.Path, verb, c.ID, c.Short, f.Reason)
	if f.Status == knowledge.Vulnerable || f.Status == knowledge.Unknown {
		m += " " + exposureText(c.ID, f)
		if b.Bits == 32 && c.ID == knowledge.Flow {
			m += " It is a 32-bit build; the published exploit needs a 64-bit one, but the memory corruption is the same."
		}
		if b.TLS == ngx.No && c.ID == knowledge.Flow {
			m += " It is built without TLS; the published path is through TLS."
		}
	}
	return m
}

func exposureText(cve string, f Finding) string {
	e := f.Config
	where := ""
	if e != nil && len(e.Where) > 0 {
		where = " (" + strings.Join(e.Where, ", ") + ")"
	}
	switch f.State {
	case conf.Exposed:
		if cve == knowledge.Reuse {
			return "HTTP/2 is on in front of a proxy" + where + ": the published preconditions hold, apart from worker_connections being nearly exhausted."
		}
		return "HTTP/2 is on over TLS" + where + ": the published preconditions hold."
	case conf.Cleartext:
		return "HTTP/2 is on only without TLS" + where + "; the published path is through TLS, so this configuration is reported as less exposed, not safe."
	case conf.NoProxy:
		return "HTTP/2 is on" + where + " but no server with it proxies to an upstream; the published path needs a reverse proxy, so this configuration is reported as less exposed, not safe."
	case conf.NotExposed:
		return fmt.Sprintf("HTTP/2 is off in every file of %s that was read: not exposed through this configuration, but the binary still needs the update.", f.Facts["config"])
	}
	why := "the configuration was not found"
	if e != nil && len(e.Unread) > 0 {
		why = e.Unread[0]
	}
	return "Whether HTTP/2 is on is not known: " + why + "."
}

func fixText(f Finding, pkg *pkgdb.Package, distro string) string {
	switch f.Status {
	case knowledge.Fixed, knowledge.NotAffected:
		return ""
	}
	b := f.Binary
	var s string
	switch {
	case b.Product == ngx.OpenResty:
		s = "Update OpenResty to a release on nginx 1.31.9 or later, or one that carries the fix as a patch; none was published on " + knowledge.Checked + "."
	case b.Product == ngx.Tengine:
		s = "Tengine had published no fixed release on " + knowledge.Checked + "; apply upstream commits e27f5fa84 and 2df48a501 or move to nginx 1.31.9 / 1.30.7."
	case b.Product == ngx.Angie:
		s = "Angie had published no fixed release on " + knowledge.Checked + "; update Angie when it does."
	case b.Product == ngx.Plus:
		s = "Update NGINX Plus to 37.0.8.1 or 37.3.0.1 (both CVEs on 37.0 and 37.3; 37.2.0.1 fixes CVE-2026-123633 only)."
	case pkg != nil && !knowledge.NginxOrgMaintainer(pkg.Maintainer) && distro != "" && knowledge.DistroStatus[distro] != "":
		s = knowledge.DistroStatus[distro] + ". Update the " + pkg.Name + " package when a fixed one is published, or move to nginx.org's 1.31.9 / 1.30.7 packages."
	default:
		s = knowledge.UpdateText
	}
	if f.Status == knowledge.Vulnerable && f.State != conf.NotExposed {
		s += " " + knowledge.Interim
	}
	if f.Status == knowledge.Unknown {
		s = "Check which release this is (nginx -V) and update to a fixed one if it is not. " + s
	}
	return s
}
