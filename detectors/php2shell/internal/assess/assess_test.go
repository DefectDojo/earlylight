package assess

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/detect"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/pkgdb"
)

// testData is a small, self-consistent knowledge base for the rules below. It
// mirrors the real entries' shape but is fixed, so these tests do not move when
// the shipped data is updated.
const testData = `{
 "snapshot": "2026-10-21T18:00:00Z",
 "entries": [
  {"distro":"ubuntu","os_ids":["ubuntu"],"release":"24.04","format":"dpkg","source_package":"php8.3","branch":"8.3",
   "version_pattern":"^8\\.3\\.6-0ubuntu0\\.24\\.04\\.[0-9]+$",
   "cves":{"CVE-2026-109618":{"fixed":"8.3.6-0ubuntu0.24.04.13"},"CVE-2026-109619":{"fixed":"8.3.6-0ubuntu0.24.04.13"}},
   "evidence":["test"]},
  {"distro":"debian","os_ids":["debian"],"release":"12","format":"dpkg","source_package":"php8.2","branch":"8.2",
   "version_pattern":"^8\\.2\\.[0-9]+-[0-9]+~deb12u[0-9]+$",
   "cves":{"CVE-2026-109618":{"fixed":"8.2.35-1~deb12u1","vulnerable_through":"8.2.34-1~deb12u1"},"CVE-2026-109619":{"fixed":"8.2.35-1~deb12u1","vulnerable_through":"8.2.34-1~deb12u1"}},
   "evidence":["test"]},
  {"distro":"alpine","os_ids":["alpine"],"release":"3.22","format":"apk","source_package":"php83","branch":"8.3",
   "version_pattern":"^8\\.3\\.[0-9]+-r[0-9]+$",
   "cves":{"CVE-2026-109618":{"vulnerable_through":"8.3.29-r0"},"CVE-2026-109619":{"vulnerable_through":"8.3.29-r0"}},
   "evidence":["test"]},
  {"distro":"ubuntu","os_ids":["ubuntu"],"release":"22.04","format":"dpkg","source_package":"php8.1","branch":"8.1",
   "version_pattern":"^8\\.1\\.2-1ubuntu2\\.[0-9]+$",
   "cves":{"CVE-2026-109618":{"fixed":"8.1.2-1ubuntu2.28"},"CVE-2026-109619":{"vulnerable_through":"8.1.2-1ubuntu2.27"}},
   "evidence":["test"]}
 ]}`

func data(t *testing.T) *knowledge.Data {
	t.Helper()
	d, err := knowledge.Parse([]byte(testData))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func bin(p, v, zend string, content string) *detect.Binary {
	m, s1, s2 := md5.Sum([]byte(content)), sha1.Sum([]byte(content)), sha256.Sum256([]byte(content))
	return &detect.Binary{Path: p, Version: v, Zend: zend, SAPI: detect.SAPI(p), MD5: m[:], SHA1: s1[:], SHA256: s2[:]}
}

func owned(format pkgdb.Format, name, ver, src, file, algo, content string) pkgdb.Installed {
	var d []byte
	switch algo {
	case "md5":
		x := md5.Sum([]byte(content))
		d = x[:]
	case "sha1":
		x := sha1.Sum([]byte(content))
		d = x[:]
	case "sha256":
		x := sha256.Sum256([]byte(content))
		d = x[:]
	}
	return pkgdb.Installed{Package: pkgdb.Package{Format: format, Name: name, Version: ver, Source: src}, Files: []pkgdb.File{{Path: file, Algo: algo, Digest: d}}}
}

var (
	noble    = &knowledge.OSRelease{ID: "ubuntu", VersionID: "24.04", Pretty: "Ubuntu 24.04.3 LTS"}
	jammy    = &knowledge.OSRelease{ID: "ubuntu", VersionID: "22.04"}
	bookworm = &knowledge.OSRelease{ID: "debian", VersionID: "12"}
	alpine   = &knowledge.OSRelease{ID: "alpine", VersionID: "3.22.2"}
)

func TestRules(t *testing.T) {
	d := data(t)
	const body = "php binary bytes"
	cases := []struct {
		name   string
		b      *detect.Binary
		pkgs   []pkgdb.Installed
		os     *knowledge.OSRelease
		want   Status
		reason string
	}{
		{name: "official image, vulnerable", b: bin("/usr/local/sbin/php-fpm", "8.3.35", "4.3.35", body), want: Vulnerable, reason: "no package manager installed this file"},
		{name: "official image, fixed", b: bin("/usr/local/sbin/php-fpm", "8.3.36", "4.3.36", body), want: Fixed},
		{name: "upstream above fix wins even when packaged", b: bin("/usr/bin/php8.3", "8.3.36", "4.3.36", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.36-1+ubuntu24.04.1+deb.sury.org+1", "php8.3", "/usr/bin/php8.3", "md5", body)}, os: noble, want: Fixed},
		{name: "end of life branch, unpackaged", b: bin("/usr/local/bin/php", "8.1.33", "4.1.33", body), want: Vulnerable, reason: "end of life"},
		{name: "ubuntu backport fixed despite old version string", b: bin("/usr/bin/php8.3", "8.3.6", "4.3.6", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "php8.3", "/usr/bin/php8.3", "md5", body)}, os: noble, want: Fixed},
		{name: "ubuntu before the backport", b: bin("/usr/sbin/php-fpm8.3", "8.3.6", "4.3.6", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-fpm", "8.3.6-0ubuntu0.24.04.12", "php8.3", "/usr/sbin/php-fpm8.3", "md5", body)}, os: noble, want: Vulnerable},
		{name: "sury package below the fix is not judged by Ubuntu's data", b: bin("/usr/bin/php8.3", "8.3.35", "4.3.35", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.35-1+ubuntu24.04.1+deb.sury.org+1", "php8.3", "/usr/bin/php8.3", "md5", body)}, os: noble, want: Unknown, reason: "no fix data"},
		{name: "debian mirror lag", b: bin("/usr/bin/php8.2", "8.2.34", "4.2.34", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.2-cli", "8.2.34-1~deb12u1", "php8.2", "/usr/bin/php8.2", "md5", body)}, os: bookworm, want: Vulnerable},
		{name: "alpine stable, no fix yet", b: bin("/usr/bin/php83", "8.3.29", "4.3.29", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.APK, "php83", "8.3.29-r0", "php83", "/usr/bin/php83", "sha1", body)}, os: alpine, want: Vulnerable, reason: "no fix"},
		{name: "alpine newer than the data knows", b: bin("/usr/bin/php83", "8.3.29", "4.3.29", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.APK, "php83", "8.3.29-r1", "php83", "/usr/bin/php83", "sha1", body)}, os: alpine, want: Unknown, reason: "newer than the newest version known vulnerable"},
		{name: "jammy: one CVE fixed, the other not", b: bin("/usr/bin/php8.1", "8.1.2", "4.1.2", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.1-cli", "8.1.2-1ubuntu2.28", "php8.1", "/usr/bin/php8.1", "md5", body)}, os: jammy, want: Unknown},
		{name: "packaged file replaced after install", b: bin("/usr/bin/php8.3", "8.3.6", "4.3.6", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "php8.3", "/usr/bin/php8.3", "md5", "other bytes")}, os: noble, want: Unknown, reason: "replaced or modified"},
		{name: "packaged without digest, consistent version", b: bin("/usr/bin/php8.3", "8.3.6", "4.3.6", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.6-0ubuntu0.24.04.12", "php8.3", "/usr/bin/php8.3", "", "")}, os: noble, want: Vulnerable},
		{name: "packaged without digest, inconsistent version", b: bin("/usr/bin/php8.3", "8.3.35", "4.3.35", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.6-0ubuntu0.24.04.12", "php8.3", "/usr/bin/php8.3", "", "")}, os: noble, want: Unknown, reason: "does not match"},
		{name: "packaged, no os-release", b: bin("/usr/bin/php8.3", "8.3.6", "4.3.6", body),
			pkgs: []pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "php8.3", "/usr/bin/php8.3", "md5", body)}, want: Unknown, reason: "os-release"},
		{name: "php package without file list may own it", b: bin("/usr/bin/php8.2", "8.2.34", "4.2.34", body),
			pkgs: []pkgdb.Installed{{Package: pkgdb.Package{Format: pkgdb.Dpkg, Name: "php8.2-cli", Version: "8.2.34-1~deb12u1", Source: "php8.2"}}}, os: bookworm, want: Unknown, reason: "file list"},
		{name: "detector problem", b: &detect.Binary{Path: "/usr/local/bin/php", Version: "8.3.35", Problem: "the file carries several PHP versions"}, want: Unknown},
		{name: "development build above the fix", b: bin("/usr/local/bin/php", "8.6.0-dev", "4.6.0-dev", body), want: Unknown},
		{name: "pre-release below the fix", b: bin("/usr/local/bin/php", "8.4.0RC1", "4.4.0RC1", body), want: Vulnerable},
		{name: "later branch release", b: bin("/usr/local/bin/php", "8.6.0", "4.6.0", body), want: Fixed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := pkgdb.NewIndex(c.pkgs, []string{"/var/lib/dpkg/status"}, nil)
			if c.pkgs == nil {
				ix = pkgdb.NewIndex(nil, nil, nil)
			}
			f := One(Input{Index: ix, OS: c.os, Data: d}, c.b)
			if f.Status != c.want {
				t.Fatalf("status %s, want %s (%s)", f.Status, c.want, f.Reason)
			}
			if !strings.Contains(f.Reason, c.reason) {
				t.Errorf("reason %q does not mention %q", f.Reason, c.reason)
			}
			if len(f.CVEs) != len(knowledge.CVEs) {
				t.Errorf("%d CVE results", len(f.CVEs))
			}
			if f.Status == Vulnerable && f.Fix == "" {
				t.Error("vulnerable without fix advice")
			}
		})
	}
}

func TestUnreadableDatabaseBlocksVersionVerdict(t *testing.T) {
	ix := pkgdb.NewIndex(nil, nil, []string{"/var/lib/rpm/rpmdb.sqlite: corrupt"})
	f := One(Input{Index: ix, Data: data(t)}, bin("/usr/bin/php", "8.2.13", "4.2.13", "x"))
	if f.Status != Unknown || !strings.Contains(f.Reason, "could not be read") {
		t.Fatalf("%s: %s", f.Status, f.Reason)
	}
}

func TestAliases(t *testing.T) {
	const body = "x"
	ix := pkgdb.NewIndex([]pkgdb.Installed{owned(pkgdb.Dpkg, "php8.3-cli", "8.3.6-0ubuntu0.24.04.13", "php8.3", "/bin/php8.3", "md5", body)}, []string{"s"}, nil)
	aliases := func(p string) []string {
		if p == "/usr/bin/php8.3" {
			return []string{"/bin/php8.3", "/usr/bin/php8.3"}
		}
		return []string{p}
	}
	f := One(Input{Index: ix, OS: noble, Data: data(t), Aliases: aliases}, bin("/usr/bin/php8.3", "8.3.6", "4.3.6", body))
	if f.Status != Fixed {
		t.Fatalf("%s: %s", f.Status, f.Reason)
	}
}
