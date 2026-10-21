// Package assess decides whether each finding is live trust or an inert copy.
//
// A certificate can sit in a file without being trusted: a distribution's source
// directory, a p11-kit blocklist, or an entry the file itself marks distrusted. The
// rules here only ever mark a finding inactive on positive evidence (a blocklist
// path, an explicit distrust flag, a "!" line in /etc/ca-certificates.conf). Without
// that evidence the finding stays active, so the scanner errs toward reporting.
package assess

import (
	"bufio"
	"bytes"
	"path"
	"regexp"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/emudhra/internal/detect"
)

// Status of a finding.
type Status string

const (
	Active   Status = "active"   // trusted, or a binary that needs a rebuild
	Inactive Status = "inactive" // present but provably not trusted
	// Platform: a store whose trust the operating system or browser decides with
	// its own blocklist (macOS keychains, Chromium with CRLSet, Firefox with
	// OneCRL). Reported, but not counted as active.
	Platform Status = "platform"
)

// Result is a finding with its status and the reason for it.
type Result struct {
	detect.Finding
	Status Status `json:"status"`
	Reason string `json:"status_reason,omitempty"`
}

// Context supplies what the rules need to know about the rest of the scanned root.
// Paths are absolute inside the root (for example "/etc/ca-certificates.conf").
type Context struct {
	Read   func(absPath string) []byte // file content, nil when absent
	Exists func(absPath string) bool   // whether a regular file was scanned at that path
	Env    []string                    // container image Config.Env, "KEY=value" entries
}

func (c Context) env(key string) (string, bool) {
	for _, e := range c.Env {
		if k, v, ok := strings.Cut(e, "="); ok && k == key {
			return v, true
		}
	}
	return "", false
}

var blocklistDirs = []string{
	// openSUSE / SLES
	"/etc/pki/trust/blacklist/",
	"/etc/pki/trust/blocklist/",
	"/usr/share/pki/trust/blacklist/",
	"/usr/share/pki/trust/blocklist/",
	// FreeBSD (certctl) and NetBSD
	"/etc/ssl/untrusted/",
	"/etc/ssl/blacklisted/",
	"/usr/share/certs/untrusted/",
	"/usr/share/certs/blacklisted/",
	"/usr/local/share/certs/untrusted/",
	"/etc/openssl/untrusted/",
	// Fedora / RHEL / Arch (p11-kit)
	"/etc/pki/ca-trust/source/blocklist/",
	"/etc/pki/ca-trust/source/blacklist/",
	"/usr/share/pki/ca-trust-source/blocklist/",
	"/usr/share/pki/ca-trust-source/blacklist/",
	"/etc/ca-certificates/trust-source/blocklist/",
	"/etc/ca-certificates/trust-source/blacklist/",
	"/usr/share/ca-certificates/trust-source/blocklist/",
	"/usr/share/ca-certificates/trust-source/blacklist/",
}

const debianSourceDir = "/usr/share/ca-certificates/"

// Assess assigns a status to every finding. Paths in findings must be absolute
// within the scanned root.
func Assess(findings []detect.Finding, ctx Context) []Result {
	var conf map[string]bool // nil: no ca-certificates.conf; else name -> enabled
	confLoaded := false
	// Keys an administrator blocklisted through p11-kit. The same key in a p11-kit
	// source bundle is then not trusted, whatever the bundle itself says.
	blocked := map[string]string{}
	for _, f := range findings {
		if inArchive(f.Path) {
			continue // member names are attacker-controlled; never let them blocklist a key
		}
		if p := path.Clean("/" + f.Path); f.SPKI != "" && inBlocklistDir(p) {
			blocked[f.SPKI] = p
		}
	}
	out := make([]Result, 0, len(findings))
	for _, f := range findings {
		r := Result{Finding: f, Status: Active}
		p := path.Clean("/" + f.Path)
		member := inArchive(f.Path)
		switch {
		case f.Kind == detect.UnpatchedGo && f.Binary == "macho":
			r.Status, r.Reason = Platform, "macOS Go binary: Go verifies system roots with Apple's verifier, which blocks these intermediates; rebuild with go1.27.3 anyway if it loads its own roots"
		case f.Kind == detect.UnpatchedGo:
			r.Reason = "binary must be rebuilt with go1.26.10 / go1.27.3 or later"
		case certifiPatchedTo(rawPath(f.Path), ctx) != "":
			r.Status, r.Reason = Inactive, "this certifi is patched to return "+certifiPatchedTo(rawPath(f.Path), ctx)+" instead of its own bundle; that file is checked separately"
		case !member && platformStore(p) != "":
			r.Status, r.Reason = Platform, platformStore(p)
		case f.Blocklisted:
			r.Status, r.Reason = Inactive, "the same binary contains a blocklist of all eight compromised keys, so it rejects chains through them"
		case f.Trust == "distrusted":
			r.Status, r.Reason = Inactive, "the file marks this certificate x-distrusted (p11-kit)"
		case f.Trust == "no-usable-purpose":
			r.Status, r.Reason = Inactive, "the file trusts this CA only for purposes none of the compromised intermediates can issue for (they allow TLS and code signing only)"
		case !member && isRHELObjsignBundle(p):
			r.Finding.Purposes = []string{"code-signing"}
			r.Reason = "code-signing trust bundle: exposed through the two compromised code-signing CAs"
		case !member && isRHELEmailBundle(p):
			r.Status, r.Reason = Inactive, "e-mail (S/MIME) trust bundle; none of the compromised intermediates can issue e-mail certificates"
		case !member && isTestFixture(p):
			r.Status, r.Reason = Inactive, "test fixture (under testdata/ or a _test file), not loaded as a trust store"
		case !member && inBlocklistDir(p):
			r.Status, r.Reason = Inactive, "file is in a p11-kit blocklist directory, so this certificate is distrusted"
		case !member && blocked[f.SPKI] != "" && inP11KitSource(p):
			r.Status, r.Reason = Inactive, "p11-kit source; the same key is blocklisted by "+blocked[f.SPKI]
		case !member && isNodeBinary(p) && nodeUsesOpenSSLStore(ctx):
			r.Status, r.Reason = Inactive, "the image sets NODE_OPTIONS=--use-openssl-ca, so node uses the system trust store, not its bundled one (unless the runtime overrides it)"
		case !member && botocoreBundle(p) && awsCABundleSet(ctx):
			r.Status, r.Reason = Inactive, "the image sets AWS_CA_BUNDLE, which botocore uses instead of this file (unless the runtime overrides it)"
		case !member && botocoreUsesCertifi(p, ctx):
			r.Status, r.Reason = Inactive, "botocore loads certifi's bundle instead of this one when certifi is installed, and it is"
		case !member && strings.HasPrefix(p, debianSourceDir):
			if !confLoaded {
				conf, confLoaded = parseConf(ctx.Read("/etc/ca-certificates.conf")), true
			}
			name := strings.TrimPrefix(p, debianSourceDir)
			switch enabled, listed := conf[name]; {
			case conf == nil:
				r.Reason = "source certificate; /etc/ca-certificates.conf not found, so it may be enabled"
			case listed && !enabled:
				r.Status, r.Reason = Inactive, "source certificate disabled with '!' in /etc/ca-certificates.conf"
			case !listed:
				r.Status, r.Reason = Inactive, "source certificate not selected in /etc/ca-certificates.conf"
			default:
				r.Reason = "source certificate enabled in /etc/ca-certificates.conf"
			}
		}
		if r.Status == Active && r.Reason == "" && len(f.Purposes) > 0 {
			r.Reason = "the file restricts this CA to: " + strings.Join(f.Purposes, ", ")
		}
		out = append(out, r)
	}
	return out
}

var p11kitSourceDirs = []string{
	"/usr/share/pki/trust/",
	"/etc/pki/trust/",
	"/usr/share/pki/ca-trust-source/",
	"/etc/pki/ca-trust/source/",
	"/usr/share/ca-certificates/trust-source/",
	"/etc/ca-certificates/trust-source/",
}

func inP11KitSource(p string) bool {
	for _, d := range p11kitSourceDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// botocoreUsesCertifi: botocore's httpsession.where() returns certifi.where() when
// certifi imports, and only falls back to its own cacert.pem otherwise. That holds
// for botocore and for the copy vendored inside awscli v1.
func botocoreUsesCertifi(p string, ctx Context) bool {
	for _, suffix := range []string{"/botocore/cacert.pem", "/awscli/botocore/cacert.pem"} {
		site, ok := strings.CutSuffix(p, suffix)
		if !ok {
			continue
		}
		if !strings.HasSuffix(site, "/site-packages") && !strings.HasSuffix(site, "/dist-packages") {
			continue
		}
		return ctx.Exists != nil && ctx.Exists(site+"/certifi/cacert.pem")
	}
	return false
}

// inArchive reports whether a finding is inside an archive ("outer!/member").
// Location rules apply only to real filesystem paths: a member's name is chosen
// by whoever built the archive and proves nothing about how it is trusted.
// rawPath is a finding's path as recorded, only made absolute: content-based
// rules look siblings up by it, so a cleaned path can never alias another file.
func rawPath(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func inArchive(p string) bool {
	return strings.Contains(p, "!/")
}

func isNodeBinary(p string) bool {
	b := path.Base(p)
	return b == "node" || b == "nodejs"
}

func nodeUsesOpenSSLStore(ctx Context) bool {
	v, ok := ctx.env("NODE_OPTIONS")
	if !ok {
		return false
	}
	for _, opt := range strings.Fields(v) {
		if opt == "--use-openssl-ca" {
			return true
		}
	}
	return false
}

func botocoreBundle(p string) bool {
	return strings.HasSuffix(p, "/botocore/cacert.pem")
}

func awsCABundleSet(ctx Context) bool {
	v, ok := ctx.env("AWS_CA_BUNDLE")
	return ok && v != ""
}

func isRHELObjsignBundle(p string) bool {
	return p == "/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem"
}

var (
	topLevelWhereRe = regexp.MustCompile(`(?m)^def where\(\)[^\n]*:\n((?:[ \t]+[^\n]*\n|[ \t]*\n)*)`)
	returnRe        = regexp.MustCompile(`(?m)^[ \t]+return[ \t]+(?:["']([^"']+)["']|([A-Za-z_][A-Za-z0-9_]*))[ \t]*$`)
)

// certifiPatchedTo: Debian, Ubuntu and Fedora patch certifi (and pip's vendored
// copy) so where() returns the system bundle, and its own cacert.pem is never
// used. The evidence is the sibling core.py, in the same directory or the same
// archive. Python keeps the last top-level definition, so the last unindented
// "def where()" decides; its return value must be a string literal or a
// module-level constant assigned one, naming an absolute path other than a
// cacert.pem.
func certifiPatchedTo(p string, ctx Context) string {
	dir, ok := strings.CutSuffix(p, "/certifi/cacert.pem")
	if !ok || ctx.Read == nil || strings.Contains(p, "/../") || strings.Contains(p, "!/../") {
		return ""
	}
	core := ctx.Read(dir + "/certifi/core.py")
	if core == nil {
		return ""
	}
	defs := topLevelWhereRe.FindAllSubmatch(core, -1)
	if len(defs) == 0 {
		return ""
	}
	body := defs[len(defs)-1][1]
	m := returnRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	target := string(m[1])
	if target == "" {
		// return NAME: resolve a top-level NAME = '...' assignment
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(string(m[2])) + `[ \t]*=[ \t]*["']([^"']+)["'][ \t]*$`)
		a := re.FindAllSubmatch(core, -1)
		if len(a) == 0 {
			return ""
		}
		target = string(a[len(a)-1][1])
	}
	if !strings.HasPrefix(target, "/") || strings.HasSuffix(target, "cacert.pem") {
		return ""
	}
	return target
}

// Install locations of browsers that keep their own blocklist. Only these exact
// prefixes count: a file merely named like a browser framework elsewhere (an
// Electron app, a copy in a project) gets no exemption.
var chromiumDirs = []string{
	"/Applications/Google Chrome.app/Contents/Frameworks/",
	"/Applications/Google Chrome Beta.app/Contents/Frameworks/",
	"/Applications/Microsoft Edge.app/Contents/Frameworks/",
	"/Applications/Brave Browser.app/Contents/Frameworks/",
	"/opt/google/chrome/",
	"/opt/google/chrome-beta/",
	"/opt/microsoft/msedge/",
	"/opt/brave.com/brave/",
}

var mozillaDirs = []string{
	"/Applications/Firefox.app/Contents/",
	"/Applications/Thunderbird.app/Contents/",
	"/usr/lib/firefox/",
	"/usr/lib64/firefox/",
	"/usr/lib/firefox-esr/",
	"/usr/lib64/firefox-esr/",
	"/opt/firefox/",
	"/usr/lib/thunderbird/",
	"/usr/lib64/thunderbird/",
}

func anyPrefix(p string, prefixes []string) bool {
	for _, d := range prefixes {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// platformStore explains files whose trust the OS or browser decides.
func platformStore(p string) string {
	base := path.Base(p)
	switch {
	case strings.HasPrefix(p, "/System/Library/Keychains/"), strings.HasPrefix(p, "/Library/Keychains/"),
		strings.HasPrefix(p, "/System/Library/Security/"), base == "X509Anchors",
		strings.HasSuffix(base, ".keychain"), strings.HasSuffix(base, ".keychain-db"):
		return "macOS trust store: Apple's verifier decides trust and blocks the compromised intermediates (from October 19); test with the advisory's test server"
	case anyPrefix(p, chromiumDirs):
		return "Chromium-based browser: Chrome blocks the compromised intermediates with a CRLSet update (from October 17); keep the browser updated"
	case anyPrefix(p, mozillaDirs):
		return "Firefox / Thunderbird: Mozilla blocks the compromised intermediates with OneCRL (from October 17); keep it updated"
	}
	return ""
}

// isRHELEmailBundle: update-ca-trust writes one PEM bundle per purpose. The e-mail
// bundle is used only for S/MIME.
func isRHELEmailBundle(p string) bool {
	return p == "/etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem"
}

func isTestFixture(p string) bool {
	if strings.Contains(p, "/testdata/") {
		return true
	}
	base := path.Base(p)
	return strings.HasSuffix(base, "_test.go")
}

func inBlocklistDir(p string) bool {
	for _, d := range blocklistDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// parseConf reads Debian's /etc/ca-certificates.conf: one path per line relative to
// /usr/share/ca-certificates, "!" prefix to deselect, "#" comments.
func parseConf(b []byte) map[string]bool {
	if b == nil {
		return nil
	}
	m := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// update-ca-certificates includes a certificate if any line selects it,
		// so a "!" line never overrides a plain one, whatever the order.
		if name, ok := strings.CutPrefix(line, "!"); ok {
			if _, seen := m[name]; !seen {
				m[name] = false
			}
			continue
		}
		m[line] = true
	}
	return m
}
