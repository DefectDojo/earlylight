// Package assess decides, for each PHP runtime found, whether it is vulnerable to
// CVE-2026-109618 and CVE-2026-109619, fixed, or unknown, and why.
//
// The rules, in order:
//
//  1. A PHP release at or above the fixed release of its branch is fixed. A
//     distribution cannot ship an upstream release without the upstream fix.
//  2. A file that a package manager installed (the database lists it, and its
//     recorded digest matches the file) is judged only by that vendor's data for
//     that exact package stream: fixed at or above the vendor's fixed version,
//     vulnerable below it or at or below a version the vendor lists as vulnerable.
//     Distributions backport fixes without changing the version PHP reports
//     (Ubuntu 24.04's fixed build still reports 8.3.6), so the version string
//     says nothing here. With no data for that vendor, the result is unknown.
//  3. A file no package manager installed (the official Docker image, a source
//     build, a static build) carries the release it reports: below the fixed
//     release it is vulnerable.
//
// Anything that does not fit (a modified packaged file, an unreadable package
// database, an unrecognised version) is unknown, with the reason. Nothing is
// called fixed without proof.
package assess

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/detect"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/version"
)

// Status is a verdict.
type Status string

const (
	Vulnerable Status = "vulnerable"
	Fixed      Status = "fixed"
	Unknown    Status = "unknown"
)

// CVEResult is the verdict for one CVE.
type CVEResult struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Reason string `json:"reason"`
}

// Finding is the verdict for one PHP runtime file.
type Finding struct {
	Path       string `json:"path"`
	PHPVersion string `json:"php_version"`
	SAPI       string `json:"sapi"`
	// WebFacing is true for SAPIs that serve web requests (FPM, CGI, the Apache
	// module, LiteSpeed, FrankenPHP), which the advisories rate most exposed.
	WebFacing bool                 `json:"web_facing"`
	Status    Status               `json:"status"`
	Severity  string               `json:"severity"`
	Reason    string               `json:"reason"`
	CVEs      []CVEResult          `json:"cves"`
	Package   *pkgdb.Package       `json:"package,omitempty"`
	OS        *knowledge.OSRelease `json:"os,omitempty"`
	Fix       string               `json:"fix,omitempty"`
}

// Input is what a scan collected.
type Input struct {
	Binaries []*detect.Binary
	Index    *pkgdb.Index
	// Aliases returns every path equivalent to p (symlinked directories, hard
	// links), including p. Nil means p only.
	Aliases func(p string) []string
	OS      *knowledge.OSRelease
	Data    *knowledge.Data
}

// Run assesses every binary, sorted by path.
func Run(in Input) []Finding {
	out := make([]Finding, 0, len(in.Binaries))
	for _, b := range in.Binaries {
		out = append(out, One(in, b))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func all(st Status, reason string) []CVEResult {
	rs := make([]CVEResult, len(knowledge.CVEs))
	for i, c := range knowledge.CVEs {
		rs[i] = CVEResult{ID: c.ID, Status: st, Reason: reason}
	}
	return rs
}

// One assesses a single binary.
func One(in Input, b *detect.Binary) Finding {
	f := Finding{Path: b.Path, PHPVersion: b.Version, SAPI: b.SAPI, WebFacing: detect.WebSAPI(b.SAPI), OS: in.OS}
	finish := func(st Status, reason string, cves []CVEResult) Finding {
		f.Status, f.Reason, f.CVEs = st, reason, cves
		f.Severity = severity(st, f.WebFacing)
		f.Fix = fixAdvice(f, b)
		return f
	}
	if b.Problem != "" {
		return finish(Unknown, b.Problem, all(Unknown, b.Problem))
	}
	v, err := version.ParsePHP(b.Version)
	if err != nil {
		r := fmt.Sprintf("unrecognised PHP version string %q", b.Version)
		return finish(Unknown, r, all(Unknown, r))
	}
	up, upReason := knowledge.Upstream(v)
	// Rule 1.
	if up == knowledge.UpstreamFixed {
		return finish(Fixed, upReason, all(Fixed, upReason))
	}

	owner, ownReason := owningPackage(in, b)
	if owner != nil {
		p := owner.Package
		f.Package = &p
		// Rule 2.
		return distroVerdict(in, f, p, finish)
	}
	if ownReason != "" {
		r := ownReason
		if up == knowledge.UpstreamVulnerable {
			r = fmt.Sprintf("PHP %s reports a vulnerable release, but %s", b.Version, ownReason)
		}
		return finish(Unknown, r, all(Unknown, r))
	}
	// Rule 3.
	if up == knowledge.UpstreamVulnerable {
		r := upReason + "; no package manager installed this file, so no vendor backport applies"
		return finish(Vulnerable, r, all(Vulnerable, upReason))
	}
	return finish(Unknown, upReason, all(Unknown, upReason))
}

// owningPackage returns the package that installed b, or nil. When it returns
// nil with a reason, ownership could not be settled and the binary must not be
// judged by its version string.
func owningPackage(in Input, b *detect.Binary) (*pkgdb.Owner, string) {
	paths := []string{b.Path}
	if in.Aliases != nil {
		paths = in.Aliases(b.Path)
	}
	var owners []pkgdb.Owner
	seen := map[string]bool{}
	for _, p := range paths {
		for _, o := range in.Index.Owners(p) {
			k := string(o.Package.Format) + "|" + o.Package.Name + "|" + o.Package.Arch
			if !seen[k] {
				seen[k] = true
				owners = append(owners, o)
			}
		}
	}
	if len(owners) == 0 {
		if in.Index != nil && len(in.Index.Problems) > 0 {
			return nil, "no package database lists this file, and a package database could not be read fully (" + strings.Join(in.Index.Problems, "; ") + ")"
		}
		if in.Index != nil {
			for _, p := range in.Index.Packages() {
				if len(p.Files) == 0 && strings.HasPrefix(strings.ToLower(p.Package.Source), "php") {
					return nil, fmt.Sprintf("package %s %s is installed but its file list is not on disk, so it may own this file", p.Package.Name, p.Package.Version)
				}
			}
		}
		return nil, ""
	}
	var matched []pkgdb.Owner
	var mismatched []string
	for _, o := range owners {
		switch digestMatch(o.File, b) {
		case matchYes:
			matched = append(matched, o)
		case matchNo:
			mismatched = append(mismatched, o.Package.Name+" "+o.Package.Version)
		case matchNoDigest:
			if consistent(o.Package.Version, b.Version) {
				matched = append(matched, o)
			} else {
				mismatched = append(mismatched, o.Package.Name+" "+o.Package.Version+" (no digest recorded, and its version does not match the file's PHP "+b.Version+")")
			}
		}
	}
	switch {
	case len(matched) == 1:
		return &matched[0], ""
	case len(matched) > 1:
		names := make([]string, len(matched))
		for i, o := range matched {
			names[i] = o.Package.Name + " " + o.Package.Version
		}
		return nil, "several installed packages claim this file (" + strings.Join(names, ", ") + ")"
	default:
		return nil, "the file differs from what the package that lists it installed (" + strings.Join(mismatched, ", ") + "): it was replaced or modified after installation"
	}
}

type match int

const (
	matchNoDigest match = iota
	matchYes
	matchNo
)

func digestMatch(f pkgdb.File, b *detect.Binary) match {
	if len(f.Digest) == 0 {
		return matchNoDigest
	}
	var got []byte
	switch strings.ToLower(f.Algo) {
	case "md5":
		got = b.MD5
	case "sha1":
		got = b.SHA1
	case "sha256":
		got = b.SHA256
	case "sha256-160":
		// apk3 records SHA-256 truncated to 160 bits.
		got = b.SHA256[:20]
	case "sha224":
		got = b.SHA224
	case "sha384":
		got = b.SHA384
	case "sha512":
		got = b.SHA512
	default:
		return matchNoDigest
	}
	if bytes.Equal(got, f.Digest) {
		return matchYes
	}
	return matchNo
}

// consistent reports whether a package version plausibly carries the PHP
// version a file reports: its upstream part (epoch removed) starts with it.
func consistent(pkgVersion, php string) bool {
	v := pkgVersion
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if !strings.HasPrefix(v, php) {
		return false
	}
	rest := v[len(php):]
	return rest == "" || !(rest[0] >= '0' && rest[0] <= '9') && rest[0] != '.'
}

func distroVerdict(in Input, f Finding, p pkgdb.Package, finish func(Status, string, []CVEResult) Finding) Finding {
	who := fmt.Sprintf("%s %s (%s package %s)", p.Name, p.Version, p.Format, p.Source)
	if in.OS == nil || in.OS.ID == "" {
		r := "installed by " + who + ", but the operating system could not be identified (no os-release), so the vendor's fix data cannot be applied"
		return finish(Unknown, r, all(Unknown, r))
	}
	entries := in.Data.Lookup(*in.OS, string(p.Format), p.Source, p.Version, p.Vendor)
	if len(entries) == 0 {
		r := fmt.Sprintf("installed by %s on %s; this tool has no fix data for that package stream, and the vendor may have backported the fix without changing the version PHP reports", who, osName(in.OS))
		return finish(Unknown, r, all(Unknown, r))
	}
	if len(entries) > 1 {
		r := fmt.Sprintf("installed by %s; the fix data has %d entries for it, which is a data error", who, len(entries))
		return finish(Unknown, r, all(Unknown, r))
	}
	e := entries[0]
	cmp := knowledge.Comparators[e.Format]
	var rs []CVEResult
	for _, c := range knowledge.CVEs {
		st := e.CVEs[c.ID]
		r := CVEResult{ID: c.ID}
		switch {
		case st.NotAffected:
			r.Status, r.Reason = Fixed, fmt.Sprintf("%s states %s %s is not affected", e.Distro, e.Release, e.Source)
		case st.Fixed != "":
			if n, err := cmp(p.Version, st.Fixed); err != nil {
				r.Status, r.Reason = Unknown, fmt.Sprintf("cannot compare %s with %s: %v", p.Version, st.Fixed, err)
			} else if n >= 0 {
				r.Status, r.Reason = Fixed, fmt.Sprintf("%s is at or above %s's fixed version %s", p.Version, e.Distro, st.Fixed)
			} else {
				r.Status, r.Reason = Vulnerable, fmt.Sprintf("%s is below %s's fixed version %s", p.Version, e.Distro, st.Fixed)
			}
		default:
			if n, err := cmp(p.Version, st.VulnerableThrough); err != nil {
				r.Status, r.Reason = Unknown, fmt.Sprintf("cannot compare %s with %s: %v", p.Version, st.VulnerableThrough, err)
			} else if n <= 0 {
				r.Status, r.Reason = Vulnerable, fmt.Sprintf("%s had released no fix for %s %s as of %s, and %s is at or below the newest known vulnerable version %s", e.Distro, e.Release, e.Source, snapshotDay(in.Data), p.Version, st.VulnerableThrough)
			} else {
				r.Status, r.Reason = Unknown, fmt.Sprintf("%s is newer than the newest version known vulnerable (%s), and no fix was known on %s; check %s's advisory", p.Version, st.VulnerableThrough, snapshotDay(in.Data), e.Distro)
			}
		}
		rs = append(rs, r)
	}
	st := combine(rs)
	return finish(st, "installed by "+who+" on "+osName(in.OS)+": "+summarize(rs), rs)
}

func combine(rs []CVEResult) Status {
	st := Fixed
	for _, r := range rs {
		if r.Status == Vulnerable {
			return Vulnerable
		}
		if r.Status == Unknown {
			st = Unknown
		}
	}
	return st
}

func summarize(rs []CVEResult) string {
	// When both CVEs share a reason, say it once.
	if len(rs) > 1 {
		same := true
		for _, r := range rs[1:] {
			if r.Reason != rs[0].Reason || r.Status != rs[0].Status {
				same = false
			}
		}
		if same {
			return rs[0].Reason
		}
	}
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.ID + ": " + r.Reason
	}
	return strings.Join(parts, "; ")
}

func snapshotDay(d *knowledge.Data) string {
	if len(d.Snapshot) >= 10 {
		return d.Snapshot[:10]
	}
	return d.Snapshot
}

func osName(o *knowledge.OSRelease) string {
	if o.Pretty != "" {
		return o.Pretty
	}
	return strings.TrimSpace(o.ID + " " + o.VersionID)
}

func severity(st Status, web bool) string {
	switch st {
	case Vulnerable:
		if web {
			return "critical"
		}
		return "high"
	case Unknown:
		return "review"
	}
	return "none"
}

func fixAdvice(f Finding, b *detect.Binary) string {
	if f.Status != Vulnerable {
		if f.Status == Unknown && f.Package != nil {
			return fmt.Sprintf("Check the security advisories for %s on %s and upgrade the package if a fix is listed.", f.Package.Source, distroOf(f))
		}
		return ""
	}
	v, err := version.ParsePHP(b.Version)
	if err != nil {
		return ""
	}
	fixed, ok := knowledge.FixedRelease(v.Branch())
	if f.Package != nil {
		return fmt.Sprintf("Upgrade %s to the fixed package from %s, or restrict exposure until one is released (see the README's mitigations).", f.Package.Name, distroOf(f))
	}
	if !ok {
		return fmt.Sprintf("PHP %s has no upstream fix. Move to PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 or later.", v.Branch())
	}
	return fmt.Sprintf("Rebuild on PHP %s or later (for the official Docker image, a php:%s tag), then redeploy.", fixed, fixed)
}

func distroOf(f Finding) string {
	if f.OS != nil {
		return osName(f.OS)
	}
	return "your distribution"
}
