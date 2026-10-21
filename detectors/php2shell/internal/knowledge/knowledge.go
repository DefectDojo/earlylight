// Package knowledge holds everything the scanner knows about CVE-2026-109618 and
// CVE-2026-109619: the upstream releases that fix them and, per distribution, the
// package versions that fix them or are known to be vulnerable. Every
// distribution entry carries the evidence it was taken from. Load checks the
// data for internal consistency and refuses to run on data that contradicts
// itself.
package knowledge

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/version"
)

// CVE describes one of the vulnerabilities.
type CVE struct {
	ID    string `json:"id"`
	GHSA  string `json:"ghsa"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// CVEs are the two vulnerabilities fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12
// on October 21, 2026.
var CVEs = []CVE{
	{
		ID:    "CVE-2026-109618",
		GHSA:  "GHSA-w8hw-w9fx-j79w",
		Title: "Remote code execution through memory corruption after an out-of-memory error",
		URL:   "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
	},
	{
		ID:    "CVE-2026-109619",
		GHSA:  "GHSA-6wmf-4rv5-p3rp",
		Title: "Remote code execution through request state left behind in a persistent worker",
		URL:   "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
	},
}

// CVEIDs lists the CVE identifiers in order.
func CVEIDs() []string {
	ids := make([]string, len(CVEs))
	for i, c := range CVEs {
		ids[i] = c.ID
	}
	return ids
}

// upstreamFixed is the first release of each supported branch that fixes both
// CVEs (php.net, October 21, 2026; GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp list
// the same ranges: affected below these, patched at these).
var upstreamFixed = map[version.Branch]version.PHP{
	{Major: 8, Minor: 2}: {Major: 8, Minor: 2, Patch: 35},
	{Major: 8, Minor: 3}: {Major: 8, Minor: 3, Patch: 36},
	{Major: 8, Minor: 4}: {Major: 8, Minor: 4, Patch: 27},
	{Major: 8, Minor: 5}: {Major: 8, Minor: 5, Patch: 12},
}

// oldestFixedBranch and newestKnownBranch bound the table: branches before 8.2
// have no upstream fix (end of life), branches after 8.5 were not released when
// the fix shipped, so any final release of them postdates it.
var (
	oldestFixedBranch = version.Branch{Major: 8, Minor: 2}
	newestKnownBranch = version.Branch{Major: 8, Minor: 5}
)

// UpstreamStatus is what the upstream version alone proves.
type UpstreamStatus int

const (
	// UpstreamUnknown: the version alone settles nothing (a development or
	// pre-release build of a branch whose fix is not provably in or out).
	UpstreamUnknown UpstreamStatus = iota
	// UpstreamFixed: the upstream release includes the fix.
	UpstreamFixed
	// UpstreamVulnerable: an upstream release without the fix. A distribution may
	// still have backported it into a package with this version string.
	UpstreamVulnerable
)

// Upstream judges a PHP version string by upstream releases alone, with a reason.
func Upstream(v version.PHP) (UpstreamStatus, string) {
	b := v.Branch()
	if b.Less(oldestFixedBranch) {
		if b.Major < 5 {
			return UpstreamUnknown, fmt.Sprintf("PHP %s predates the versions the advisories cover", v)
		}
		return UpstreamVulnerable, fmt.Sprintf("PHP %s is below 8.2.35, and the %s branch is end of life with no upstream fix", v, b)
	}
	if newestKnownBranch.Less(b) {
		if v.IsRelease() {
			return UpstreamFixed, fmt.Sprintf("PHP %s was released after the fix", v)
		}
		return UpstreamUnknown, fmt.Sprintf("PHP %s is an unreleased build of a later branch; whether it includes the fix depends on when it was built", v)
	}
	fixed := upstreamFixed[b]
	c := v.CompareRelease(fixed)
	switch {
	case c > 0 && v.IsRelease():
		return UpstreamFixed, fmt.Sprintf("PHP %s is at or above the fixed release %s", v, fixed)
	case c == 0 && v.IsRelease():
		return UpstreamFixed, fmt.Sprintf("PHP %s is the fixed release", v)
	case c < 0:
		// A pre-release below the fixed patch is older than the fix too.
		return UpstreamVulnerable, fmt.Sprintf("PHP %s is below the fixed release %s", v, fixed)
	default:
		return UpstreamUnknown, fmt.Sprintf("PHP %s is a pre-release or development build at or above %s; whether it includes the fix depends on when it was built", v, fixed)
	}
}

// FixedRelease returns the upstream release of b that fixes both CVEs.
func FixedRelease(b version.Branch) (version.PHP, bool) {
	v, ok := upstreamFixed[b]
	return v, ok
}

// Branches lists the branches with an upstream fix, oldest first.
func Branches() []version.Branch {
	var bs []version.Branch
	for b := range upstreamFixed {
		bs = append(bs, b)
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].Less(bs[j]) })
	return bs
}

// CVEState is a distribution's state for one CVE in one package stream.
type CVEState struct {
	// Fixed is the first package version with the fix, if one has been released.
	Fixed string `json:"fixed,omitempty"`
	// VulnerableThrough is the newest package version known not to have the fix
	// (listed vulnerable by the vendor, or the version the vendor's archive served
	// on the snapshot date while the vendor listed no fix). Any version up to and
	// including it is vulnerable.
	VulnerableThrough string `json:"vulnerable_through,omitempty"`
	// NotAffected is true when the vendor states this stream is not affected.
	NotAffected bool `json:"not_affected,omitempty"`
}

// Entry is one distribution package stream: a source package in one release.
type Entry struct {
	// Distro is the os-release ID ("debian", "ubuntu", "alpine", "rhel", "amzn",
	// "sles", "opensuse-leap", ...). OSIDs lists every os-release ID the entry
	// applies to, which includes Distro.
	Distro string   `json:"distro"`
	OSIDs  []string `json:"os_ids"`
	// Release matches os-release: VERSION_ID, or VERSION_ID's prefix for Alpine
	// ("3.22" matches "3.22.2"), or VERSION_CODENAME for Debian testing/unstable.
	Release  string `json:"release"`
	Codename string `json:"codename,omitempty"`
	Format   string `json:"format"`         // dpkg, apk or rpm
	Source   string `json:"source_package"` // php8.2, php83, php, php8.3 ...
	Branch   string `json:"branch"`         // the PHP branch the stream carries, "8.2"
	// VersionPattern matches the package versions this vendor builds for this
	// stream, so a package from another repository (a PPA, Remi, sury.org) that
	// reuses the source name is not judged by this vendor's data.
	VersionPattern string `json:"version_pattern"`
	// Vendor, when set, must match the rpm Vendor tag (case-insensitive substring).
	Vendor   string              `json:"vendor,omitempty"`
	CVEs     map[string]CVEState `json:"cves"`
	Evidence []string            `json:"evidence"`

	pattern *regexp.Regexp
}

// Matches reports whether a package version belongs to this stream's vendor.
func (e *Entry) Matches(pkgVersion, vendor string) bool {
	if !e.pattern.MatchString(pkgVersion) {
		return false
	}
	if e.Vendor != "" && !strings.Contains(strings.ToLower(vendor), strings.ToLower(e.Vendor)) {
		return false
	}
	return true
}

// Data is the distribution knowledge base.
type Data struct {
	// Snapshot is when the distribution data was collected (RFC 3339).
	Snapshot string  `json:"snapshot"`
	Entries  []Entry `json:"entries"`
}

//go:embed data/distros.json
var distrosJSON []byte

// Load parses the embedded distribution data and checks it.
func Load() (*Data, error) { return Parse(distrosJSON) }

// Comparator compares two package versions of one format.
type Comparator func(a, b string) (int, error)

// Comparators maps a package format to its version comparison.
var Comparators = map[string]Comparator{
	"dpkg": version.CompareDpkg,
	"apk":  version.CompareAPK,
	"rpm":  func(a, b string) (int, error) { return version.CompareRPM(a, b), nil },
}

// Parse parses distribution data and checks every entry: known format and CVEs,
// a compiling version pattern that matches its own versions, a fixed version
// above the newest vulnerable one, and evidence for every claim.
func Parse(b []byte) (*Data, error) {
	var d Data
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("distribution data: %w", err)
	}
	if d.Snapshot == "" {
		return nil, fmt.Errorf("distribution data: no snapshot date")
	}
	known := map[string]bool{}
	for _, id := range CVEIDs() {
		known[id] = true
	}
	seen := map[string]bool{}
	for i := range d.Entries {
		e := &d.Entries[i]
		where := fmt.Sprintf("entry %d (%s %s %s)", i, e.Distro, e.Release, e.Source)
		cmp, ok := Comparators[e.Format]
		if !ok {
			return nil, fmt.Errorf("%s: unknown format %q", where, e.Format)
		}
		if e.Distro == "" || e.Release == "" || e.Source == "" {
			return nil, fmt.Errorf("%s: distro, release and source_package are required", where)
		}
		if len(e.OSIDs) == 0 || !contains(e.OSIDs, e.Distro) {
			return nil, fmt.Errorf("%s: os_ids must include the distro", where)
		}
		if _, err := parseBranch(e.Branch); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if len(e.Evidence) == 0 {
			return nil, fmt.Errorf("%s: no evidence", where)
		}
		key := e.Distro + "|" + e.Release + "|" + e.Source + "|" + e.VersionPattern + "|" + e.Vendor
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate entry", where)
		}
		seen[key] = true
		if !strings.HasPrefix(e.VersionPattern, "^") || !strings.HasSuffix(e.VersionPattern, "$") {
			return nil, fmt.Errorf("%s: version_pattern must be anchored with ^ and $", where)
		}
		re, err := regexp.Compile(e.VersionPattern)
		if err != nil {
			return nil, fmt.Errorf("%s: version_pattern: %w", where, err)
		}
		e.pattern = re
		if len(e.CVEs) != len(CVEs) {
			return nil, fmt.Errorf("%s: needs a state for each of %v", where, CVEIDs())
		}
		for id, st := range e.CVEs {
			if !known[id] {
				return nil, fmt.Errorf("%s: unknown CVE %s", where, id)
			}
			if st.NotAffected && (st.Fixed != "" || st.VulnerableThrough != "") {
				return nil, fmt.Errorf("%s %s: not_affected cannot also list versions", where, id)
			}
			if !st.NotAffected && st.Fixed == "" && st.VulnerableThrough == "" {
				return nil, fmt.Errorf("%s %s: state says nothing", where, id)
			}
			for _, v := range []string{st.Fixed, st.VulnerableThrough} {
				if v != "" && !re.MatchString(v) {
					return nil, fmt.Errorf("%s %s: version %q does not match the entry's own version_pattern", where, id, v)
				}
				if v != "" {
					if _, err := cmp(v, v); err != nil {
						return nil, fmt.Errorf("%s %s: version %q: %w", where, id, v, err)
					}
				}
			}
			if st.Fixed != "" && st.VulnerableThrough != "" {
				c, err := cmp(st.VulnerableThrough, st.Fixed)
				if err != nil {
					return nil, fmt.Errorf("%s %s: %w", where, id, err)
				}
				if c >= 0 {
					return nil, fmt.Errorf("%s %s: vulnerable_through %s is not below fixed %s", where, id, st.VulnerableThrough, st.Fixed)
				}
			}
		}
	}
	return &d, nil
}

func parseBranch(s string) (version.Branch, error) {
	v, err := version.ParsePHP(s + ".0")
	if err != nil || v.Extra != "" || !v.IsRelease() {
		return version.Branch{}, fmt.Errorf("branch %q is not MAJOR.MINOR", s)
	}
	return v.Branch(), nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// OSRelease is the part of /etc/os-release the lookup needs.
type OSRelease struct {
	ID        string   `json:"id"`
	IDLike    []string `json:"id_like,omitempty"`
	VersionID string   `json:"version_id,omitempty"`
	Codename  string   `json:"codename,omitempty"`
	Pretty    string   `json:"pretty_name,omitempty"`
}

// Lookup returns the entries for a package installed on os: same format and
// source package, os-release ID and release matching, and the package's
// version and vendor matching the entry's vendor pattern.
func (d *Data) Lookup(os OSRelease, format, source, pkgVersion, vendor string) []*Entry {
	var out []*Entry
	for i := range d.Entries {
		e := &d.Entries[i]
		if e.Format != format || e.Source != source || !contains(e.OSIDs, os.ID) {
			continue
		}
		if !releaseMatches(e, os) || !e.Matches(pkgVersion, vendor) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func releaseMatches(e *Entry, os OSRelease) bool {
	if e.Release == os.VersionID {
		return true
	}
	// Alpine and some rpm distributions put a point release in VERSION_ID
	// ("3.22.2", "9.4"); the entry names the branch or major version.
	if os.VersionID != "" && strings.HasPrefix(os.VersionID, e.Release+".") {
		return true
	}
	// Debian testing and unstable have no VERSION_ID; match on the codename.
	return os.VersionID == "" && e.Codename != "" && e.Codename == os.Codename
}
