// Package assess decides whether an OpenSSH server is exposed to *sshole:
// on musl libc, sshd before 10.6p2 compares a password field of "*" with
// crypt's failure result "*", so a password that makes crypt fail logs in.
// crypt fails when sshd borrows the salt of another account (the "donor")
// whose hash is sha256 or sha512 crypt and the password is longer than 256
// bytes, or always when that salt is a bcrypt or malformed one. PAM, when
// sshd uses it, checks passwords itself and is not affected.
//
// Everything here works from what the target holds: the binaries, the apk
// database, sshd_config and the account files. It knows nothing about the
// engine.
package assess

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// CVE is empty until one is assigned.
const CVE = ""

// Status is a verdict.
type Status string

const (
	Vulnerable Status = "vulnerable"
	Fixed      Status = "fixed"
	Inactive   Status = "inactive"
	Undecided  Status = "unknown"
)

// Kinds.
const (
	KindExposed = "exposed" // every condition holds
	KindServer  = "sshd"    // an affected build; conditions incomplete, fixed or not in use
)

// Target is an account sshd would accept a crafted password for.
type Target struct {
	Account string `json:"account"`
	// Reach is "yes" when every check passes for any connection, "maybe"
	// when it depends on the connection (a Match on address or host).
	Reach string `json:"reach"`
	Why   string `json:"why,omitempty"`
}

// Finding is the verdict on one installed OpenSSH server.
type Finding struct {
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`
	Status   Status   `json:"status"`
	Reason   string   `json:"reason,omitempty"`
	Message  string   `json:"message"`
	Fix      string   `json:"fix,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Release  string   `json:"release,omitempty"`
	Libc     Libc     `json:"libc"`
	PAM      bool     `json:"pam_built"`
	UsePAM   string   `json:"use_pam,omitempty"`
	Helpers  []string `json:"helpers,omitempty"`
	Package  *Package `json:"package,omitempty"`
	Config   string   `json:"config,omitempty"`
	// Password says whether sshd accepts password logins ("yes", "no",
	// "maybe" when it depends on the connection).
	Password string   `json:"password_auth,omitempty"`
	Donor    *Donor   `json:"donor,omitempty"`
	Targets  []Target `json:"targets,omitempty"`
	// StartedWith names where sshd -o options came from (the container
	// command or a startup script).
	StartedWith string `json:"started_with,omitempty"`
	// AtStart lists startup scripts that change accounts or sshd_config.
	AtStart []string `json:"at_start,omitempty"`
	// Missing lists the conditions that do not hold today.
	Missing []string `json:"missing,omitempty"`
}

// Input is a target's evidence.
type Input struct {
	Binaries []*Binary
	Owners   map[string]Package // apk database: file -> package
	Files    Files
	Accounts Accounts
	// Resolve returns the path a file path names after symlinks, and
	// whether a regular file is there.
	Resolve func(p string) (string, bool)
	// Branch is the Alpine branch ("3.22", "edge"), when the target is Alpine.
	Branch string
	// Image is true for container images, whose accounts and configuration
	// an entrypoint can still change.
	Image bool
	// Startup is the image's command and startup scripts, for images.
	Startup Startup
	Now     time.Time
}

// Run assesses every OpenSSH server in the input.
func Run(in Input) []Finding {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	byPath := map[string]*Binary{}
	for _, b := range in.Binaries {
		byPath[b.Path] = b
	}
	resolve := func(p string) *Binary {
		if b, ok := byPath[p]; ok {
			return b
		}
		if in.Resolve != nil {
			if r, ok := in.Resolve(p); ok {
				return byPath[r]
			}
		}
		return nil
	}
	used := map[string]bool{}
	var units [][]*Binary
	for _, b := range in.Binaries {
		if b.Role != "sshd" {
			continue
		}
		u := []*Binary{b}
		for _, h := range b.Helpers {
			if hb := resolve(h); hb != nil && hb != b {
				u = append(u, hb)
				used[hb.Path] = true
			}
		}
		units = append(units, u)
	}
	for _, b := range in.Binaries {
		if b.Role != "sshd" && !used[b.Path] {
			units = append(units, []*Binary{b}) // a helper no listener names
		}
	}
	var out []Finding
	for _, u := range units {
		if f, ok := assessUnit(in, u); ok {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func assessUnit(in Input, u []*Binary) (Finding, bool) {
	main := u[0]
	f := Finding{Path: main.Path, Kind: KindServer, Release: main.Release, Libc: main.Libc}
	for _, b := range u {
		f.PAM = f.PAM || b.PAM
		if b != main {
			f.Helpers = append(f.Helpers, b.Path)
		}
		if b.Libc != main.Libc && main.Libc == Unknown {
			f.Libc = b.Libc
		}
	}
	switch f.Libc {
	case Glibc, Bionic:
		return f, false // glibc's crypt returns NULL on failure: not affected
	}

	// Fixed? The package database speaks for vendor backports; otherwise
	// the release the binary reports.
	fixed, why := false, ""
	for _, b := range u {
		if p, ok := in.Owners[b.Path]; ok && strings.HasPrefix(p.Name, "openssh") {
			pp := p
			f.Package = &pp
			judge := apkStatus
			if p.Format == "opkg" {
				judge = opkgStatus
			}
			if fx, w, ok := judge(p.Version); ok {
				fixed, why = fx, w
			}
			break
		}
	}
	if why == "" {
		switch {
		case !main.Version.Less(FixedRelease):
			fixed, why = true, "OpenSSH "+main.Release+" has the fix (10.6p2 and later)"
		case main.Version.Less(FirstAffected):
			fixed, why = true, "OpenSSH "+main.Release+" predates 7.3p1 and never borrows another account's salt"
		default:
			why = "OpenSSH " + main.Release + " is older than 10.6p2 and no package database records a backported fix"
		}
	}
	f.Fix = fixText(in, f)
	if fixed {
		f.Status, f.Reason = Fixed, why
		f.Message = fmt.Sprintf("OpenSSH %s server has the *sshole fix", main.Release)
		f.Fix = ""
		return f, true
	}
	if f.Libc != Musl {
		f.Status = Undecided
		f.Reason = fmt.Sprintf("the C library (%s) could not be identified as musl or glibc; *sshole affects musl builds only", f.Libc)
		f.Message = fmt.Sprintf("OpenSSH %s server without the *sshole fix on an unidentified C library", main.Release)
		return f, true
	}

	cfgPath := main.Config
	if cfgPath == "" {
		cfgPath = "/etc/ssh/sshd_config"
	}
	scripts := in.Startup.startScripts(in.Resolve)
	inv, invoked := pickInvocation(invocations(in.Startup, scripts), u)
	if invoked && inv.config != "" {
		cfgPath = inv.config
	}
	f.Config = cfgPath
	cfg := ParseConfig(in.Files, cfgPath)
	if invoked && len(inv.opts) > 0 {
		cfg.Prepend(inv.opts)
		f.StartedWith = inv.where
	}
	if !cfg.Read {
		f.Status, f.Severity = Vulnerable, "medium"
		f.Missing = append(f.Missing, cfgPath+" is not in the target, so the password settings are unknown")
		f.Message = fmt.Sprintf("OpenSSH %s server on musl without the *sshole fix (%s not found)", main.Release, cfgPath)
		for _, sc := range scripts {
			if strings.Contains(sc.text, "sshd_config") {
				f.AtStart = append(f.AtStart, sc.where)
			}
		}
		if len(f.AtStart) > 0 {
			f.Message += fmt.Sprintf("; its startup script (%s) writes sshd_config when the container starts", strings.Join(f.AtStart, ", "))
		}
		f.Reason = why
		return f, true
	}
	f.UsePAM = strings.ToLower(cfg.Global("usepam", "no"))
	if f.PAM && f.UsePAM == "yes" {
		f.Status = Inactive
		f.Reason = "this build uses PAM (UsePAM yes), and PAM checks passwords without crypt's failure result"
		f.Message = fmt.Sprintf("OpenSSH %s server on musl without the *sshole fix, with PAM checking passwords", main.Release)
		return f, true
	}

	donor := PickSalt(in.Accounts)
	f.Donor = &donor
	var missing []string
	if !in.Accounts.Read {
		missing = append(missing, "/etc/passwd is not in the target")
	} else if donor.Fails == "none" {
		if donor.Account == "" {
			missing = append(missing, "no account has a $-style password hash, so sshd falls back to the DES salt \"xx\", which never fails")
		} else {
			missing = append(missing, fmt.Sprintf("the first account with a $-style hash (%s, %.3s...) is not a sha256, sha512 or bcrypt hash, so crypt does not fail", donor.Account, donor.Setting))
		}
	}

	passwordSeen := map[string]bool{}
	stars := 0
	for _, acc := range in.Accounts.List {
		if acc.Field != "*" {
			continue
		}
		stars++
		t, pw := reach(in, cfg, acc)
		passwordSeen[pw] = true
		if t.Reach != "no" {
			f.Targets = append(f.Targets, t)
		} else {
			missing = append(missing, fmt.Sprintf("%s has password field \"*\" but %s", acc.Name, t.Why))
		}
	}
	switch {
	case len(passwordSeen) == 0:
		f.Password = passwordValues(cfg, Account{Name: "\x00"}, nil)
	case len(passwordSeen) == 1:
		for k := range passwordSeen {
			f.Password = k
		}
	default:
		f.Password = "maybe"
	}
	if in.Accounts.Read && stars == 0 {
		missing = append(missing, "no account has the password field \"*\"")
	}
	f.Missing = missing
	f.Reason = why

	exposed := len(f.Targets) > 0 && donor.Fails != "none"
	if exposed {
		f.Kind, f.Status = KindExposed, Vulnerable
		names := make([]string, 0, len(f.Targets))
		sure := false
		for _, t := range f.Targets {
			names = append(names, t.Account)
			sure = sure || t.Reach == "yes"
		}
		f.Severity = "critical"
		if !sure {
			f.Severity = "high"
		}
		length := "longer than 256 bytes"
		if donor.Fails == "any" {
			length = "of any length"
		}
		f.Message = fmt.Sprintf("OpenSSH %s server on musl without the *sshole fix accepts a password %s for %s (password field \"*\"); %s's %s hash supplies the salt",
			main.Release, length, strings.Join(names, ", "), donor.Account, hashType(donor.Setting))
		if !sure {
			f.Message += "; whether a connection reaches it depends on Match conditions"
		}
		if in.Image {
			f.Message += " (as the image ships; an entrypoint can still change accounts or sshd_config)"
		}
		return f, true
	}
	f.Status, f.Severity = Vulnerable, "medium"
	f.Message = fmt.Sprintf("OpenSSH %s server on musl without the *sshole fix; not exploitable as configured: %s", main.Release, strings.Join(missing, "; "))
	if sig := startupSignals(scripts); sig.any() {
		if t, ok := atStart(in, cfg, donor, sig); ok {
			f.Kind, f.Severity = KindExposed, "high"
			f.Targets = t
			f.AtStart = sig.where
			f.Message = fmt.Sprintf("OpenSSH %s server on musl without the *sshole fix is not exposed as the image ships, but its startup script (%s) %s when the container starts, after which a crafted password logs in to %s",
				main.Release, strings.Join(sig.where, ", "), sig.describe(), targetNames(t))
			return f, true
		}
		f.AtStart = sig.where
		f.Message += fmt.Sprintf("; its startup script (%s) %s when the container starts, which this scan judges only as far as the image shows", strings.Join(sig.where, ", "), sig.describe())
	}
	return f, true
}

func targetNames(ts []Target) string {
	var n []string
	for _, t := range ts {
		n = append(n, t.Account)
	}
	return strings.Join(n, ", ")
}

// pickInvocation finds the command line that starts this server.
func pickInvocation(invs []invocation, u []*Binary) (invocation, bool) {
	for _, inv := range invs {
		for _, b := range u {
			if inv.binary == b.Path || path.Base(inv.binary) == path.Base(b.Path) {
				return inv, true
			}
		}
	}
	return invocation{}, false
}

// atStart applies what the startup scripts do (turn password logins on,
// set a password field to "*", set passwords with chpasswd) and returns the
// accounts a crafted password would then reach.
func atStart(in Input, cfg Config, donor Donor, sig signals) ([]Target, bool) {
	fails := donor.Fails
	if donor.Account == "" && sig.passwords {
		fails = "long" // chpasswd writes a sha512 hash, the first one pick_salt sees
	}
	if fails == "none" || sig.usePAMOn {
		return nil, false
	}
	c := cfg
	if sig.passwordOn {
		c.Prepend([]Directive{{Key: "passwordauthentication", Args: []string{"yes"}, File: "startup"}})
	}
	var out []Target
	for _, acc := range in.Accounts.List {
		if acc.Field != "*" {
			continue
		}
		if t, _ := reach(in, c, acc); t.Reach != "no" {
			t.Reach = "maybe"
			out = append(out, t)
		}
	}
	if sig.starSet {
		// An account the script creates or changes: an ordinary user with
		// a shell.
		acc := Account{Name: "(an account the startup script sets to \"*\")", UID: 1000, GID: 1000, Shell: "/bin/sh", Field: "*", Expire: -1}
		if t, _ := reach(in, c, acc); t.Reach != "no" {
			t.Reach = "maybe"
			out = append(out, t)
		}
	}
	return out, len(out) > 0
}

func hashType(setting string) string {
	switch {
	case strings.HasPrefix(setting, "$6$"):
		return "sha512-crypt"
	case strings.HasPrefix(setting, "$5$"):
		return "sha256-crypt"
	case strings.HasPrefix(setting, "$2"):
		return "bcrypt"
	}
	return "password"
}

// passwordValues says whether password authentication alone can succeed
// for acc: PasswordAuthentication on, and an AuthenticationMethods list
// that needs nothing but a password.
func passwordValues(cfg Config, acc Account, groups []string) string {
	pa := cfg.Values("passwordauthentication", acc, groups, "yes")
	am := cfg.Values("authenticationmethods", acc, groups, "any")
	yes, no := false, false
	for _, v := range pa {
		if strings.EqualFold(v, "yes") {
			yes = true
		} else {
			no = true
		}
	}
	amOK, amNo := false, false
	for _, v := range am {
		if passwordAlone(v) {
			amOK = true
		} else {
			amNo = true
		}
	}
	switch {
	case !yes || !amOK:
		return "no"
	case no || amNo:
		return "maybe"
	}
	return "yes"
}

func passwordAlone(v string) bool {
	if strings.EqualFold(v, "any") {
		return true
	}
	for _, list := range strings.Fields(v) {
		only := true
		for _, m := range strings.Split(list, ",") {
			if !strings.EqualFold(m, "password") {
				only = false
			}
		}
		if only {
			return true
		}
	}
	return false
}

// reach applies sshd's checks for one "*" account: password logins
// allowed, PermitRootLogin for uid 0, AllowUsers/DenyUsers/AllowGroups/
// DenyGroups, an existing shell (unless chrooted) and account expiry.
func reach(in Input, cfg Config, acc Account) (Target, string) {
	groups := in.Accounts.GroupsOf(acc)
	t := Target{Account: acc.Name}
	res := Yes
	var why []string
	add := func(tri Tri, reason string) {
		if tri == No {
			res = No
			why = append(why, reason)
		} else if tri == Maybe && res != No {
			res = Maybe
			why = append(why, reason)
		}
	}
	pw := passwordValues(cfg, acc, groups)
	switch pw {
	case "no":
		add(No, "password logins are off (PasswordAuthentication or AuthenticationMethods)")
	case "maybe":
		add(Maybe, "password logins depend on Match conditions")
	}
	if acc.UID == 0 {
		v := cfg.Values("permitrootlogin", acc, groups, "prohibit-password")
		tri := No
		for _, x := range v {
			if strings.EqualFold(x, "yes") {
				tri = Maybe
				if len(v) == 1 {
					tri = Yes
				}
			}
		}
		add(tri, "PermitRootLogin does not allow passwords for uid 0")
	}
	add(listsAllow(cfg, acc, groups), "AllowUsers, DenyUsers, AllowGroups or DenyGroups excludes it")

	chroot := cfg.Values("chrootdirectory", acc, groups, "none")
	needShell := false
	for _, c := range chroot {
		if strings.EqualFold(c, "none") {
			needShell = true
		}
	}
	if needShell {
		sh := acc.Shell
		if sh == "" {
			sh = "/bin/sh"
		}
		if in.Resolve != nil {
			if _, ok := in.Resolve(sh); !ok {
				tri := No
				if len(chroot) > 1 {
					tri = Maybe
				}
				add(tri, "its shell "+sh+" does not exist")
			}
		}
	}
	if acc.Expire >= 0 && in.Now.Unix()/86400 > acc.Expire {
		add(No, "the account has expired")
	}
	switch res {
	case Yes:
		t.Reach = "yes"
	case Maybe:
		t.Reach = "maybe"
	default:
		t.Reach = "no"
	}
	t.Why = strings.Join(why, "; ")
	return t, pw
}

func listsAllow(cfg Config, acc Account, groups []string) Tri {
	type list struct {
		key   string
		allow bool
		group bool
	}
	res := Yes
	for _, l := range []list{{"denyusers", false, false}, {"allowusers", true, false}, {"denygroups", false, true}, {"allowgroups", true, true}} {
		alts := cfg.Lists(l.key, acc, groups)
		pass, fail := false, false
		for _, pats := range alts {
			if pats == nil {
				pass = true
				continue
			}
			var m Tri
			if l.group {
				m = No
				for _, g := range groups {
					for _, p := range pats {
						if matchPatternList(g, p) {
							m = Yes
						}
					}
				}
			} else {
				m = No
				for _, p := range pats {
					m = maxTri(m, userPattern(p, acc.Name))
				}
			}
			ok := m
			if !l.allow {
				ok = notTri(m)
			}
			switch ok {
			case Yes:
				pass = true
			case No:
				fail = true
			default:
				pass, fail = true, true
			}
		}
		switch {
		case !pass:
			return No
		case fail:
			res = Maybe
		}
	}
	return res
}

// userPattern matches an AllowUsers/DenyUsers entry: USER or USER@HOST,
// where the host part depends on the connection.
func userPattern(p, name string) Tri {
	u, host, hasHost := strings.Cut(p, "@")
	if !matchPatternList(name, u) {
		return No
	}
	if hasHost && host != "*" {
		return Maybe
	}
	return Yes
}

func maxTri(a, b Tri) Tri {
	if b > a {
		return b
	}
	return a
}

func notTri(t Tri) Tri {
	switch t {
	case Yes:
		return No
	case No:
		return Yes
	}
	return Maybe
}

// fixText says how to fix this server.
func fixText(in Input, f Finding) string {
	mitigate := "Until then, set PasswordAuthentication no (for example in /etc/ssh/sshd_config.d/00-sshole.conf, before any file that turns it on), or change each password field of \"*\" to \"*NP*\", which still allows key logins."
	if f.Package != nil && f.Package.Format == "apk" {
		name := f.Package.Name
		if v, ok := AlpineFixedFor(in.Branch); ok {
			return fmt.Sprintf("Upgrade %s to %s or later (apk upgrade --no-cache %s) and restart sshd. %s", name, v, name, mitigate)
		}
		return fmt.Sprintf("Upgrade %s (apk upgrade --no-cache %s); if this Alpine release has no fixed package, move to a supported Alpine branch. Fixed: %s. %s",
			name, name, alpineFixedSummary(), mitigate)
	}
	if f.Package != nil && f.Package.Format == "opkg" {
		return fmt.Sprintf("Upgrade %s from the OpenWrt packages feed (opkg update && opkg upgrade %s): 23.05 9.8p1-2, 24.10 9.9_p2-2 and 25.12 10.6_p2-1 have the fix; 22.03 and older have none. Restart sshd. %s", f.Package.Name, f.Package.Name, mitigate)
	}
	return "Update OpenSSH to 10.6p2 or later, or rebuild with upstream commit 4353fdc43 (\"avoid password authn bypass\"), and restart sshd. " + mitigate
}

func alpineFixedSummary() string {
	var parts []string
	for _, b := range AlpineBranches() {
		v, _ := AlpineFixedFor(b)
		parts = append(parts, b+" "+v)
	}
	return strings.Join(parts, ", ")
}

// BranchFromRelease turns /etc/alpine-release ("3.22.2", "3.23_alpha2026") into
// a branch ("3.22", "edge").
func BranchFromRelease(s string) string {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "_alpha") || strings.Contains(s, "_git") {
		return "edge"
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}
