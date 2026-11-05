package assess

import (
	"github.com/DefectDojo/earlylight/detectors/sshole/internal/testelf"
	"path"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	muslInterp  = "/lib/ld-musl-x86_64.so.1"
	glibcInterp = "/lib64/ld-linux-x86-64.so.2"
	sha512Alice = "$6$pRu5B1iB4..BuPoN$MkyXJ0p3G5hVfF0uZ0xn6"
)

func TestInspect(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		data    []byte
		ok      bool
		libc    Libc
		pam     bool
		release string
		role    string
		helpers int
	}{
		{"alpine listener", "/usr/sbin/sshd", testelf.ELF(muslInterp, []string{"libcrypto.so.3", "libc.musl-x86_64.so.1"}, testelf.SSHDStrings("10.0p2", "/usr/lib/ssh/sshd-session", "/usr/lib/ssh/sshd-auth")...), true, Musl, false, "10.0p2", "sshd", 2},
		{"alpine pam auth", "/usr/lib/ssh/sshd-auth.pam", testelf.ELF(muslInterp, []string{"libpam.so.0", "libc.musl-x86_64.so.1"}, testelf.SSHDStrings("10.0p2")...), true, Musl, true, "10.0p2", "sshd-auth", 0},
		{"glibc", "/usr/sbin/sshd", testelf.ELF(glibcInterp, []string{"libc.so.6"}, testelf.SSHDStrings("9.2p1")...), true, Glibc, false, "9.2p1", "sshd", 0},
		{"static musl", "/opt/sshd", testelf.ELF("", nil, append(testelf.SSHDStrings("9.9p2"), "/etc/tcb/%s/shadow")...), true, Musl, false, "9.9p2", "sshd", 0},
		{"static unknown", "/opt/sshd", testelf.ELF("", nil, testelf.SSHDStrings("9.9p2")...), true, Unknown, false, "9.9p2", "sshd", 0},
		{"musl via needed only", "/usr/sbin/sshd", testelf.ELF("", []string{"libc.musl-aarch64.so.1"}, testelf.SSHDStrings("9.6p1")...), true, Musl, false, "9.6p1", "sshd", 0},
		{"ssh client", "/usr/bin/ssh", testelf.ELF(muslInterp, nil, "OpenSSH_10.0p2", "/etc/ssh/ssh_config"), false, "", false, "", "", 0},
		{"no release", "/usr/sbin/sshd", testelf.ELF(muslInterp, nil, "OpenSSH_7.4*", "/etc/ssh/sshd_config"), false, "", false, "", "", 0},
		{"not elf", "/usr/sbin/sshd", []byte("#!/bin/sh\nexec sshd_config OpenSSH_10.0p2"), false, "", false, "", "", 0},
	}
	for _, c := range cases {
		b, ok := Inspect(c.path, c.data)
		if ok != c.ok {
			t.Errorf("%s: ok = %v", c.name, ok)
			continue
		}
		if !ok {
			continue
		}
		if b.Libc != c.libc || b.PAM != c.pam || b.Release != c.release || b.Role != c.role || len(b.Helpers) != c.helpers {
			t.Errorf("%s: got libc %s pam %v release %s role %s helpers %v", c.name, b.Libc, b.PAM, b.Release, b.Role, b.Helpers)
		}
	}
}

func TestParseRelease(t *testing.T) {
	for in, want := range map[string]string{"10.6p2": "10.6p2", "OpenSSH_9.9p1": "9.9p1", "10.0": "10.0", "OpenSSH_7.4*": ""} {
		v, ok := ParseRelease(in)
		if (want == "") == ok || ok && v.String() != want {
			t.Errorf("%s: %v %v", in, v, ok)
		}
	}
	if !(Version{10, 6, 1}).Less(FixedRelease) || (Version{10, 6, 2}).Less(FixedRelease) || (Version{10, 7, 0}).Less(FixedRelease) {
		t.Error("ordering around the fixed release")
	}
}

func TestCryptFails(t *testing.T) {
	// Measured with musl 1.2.5 on Alpine 3.22: crypt() returning "*"
	// (failure) for short and for 257-byte keys.
	cases := map[string]string{
		"$6$abc$":                       "long",
		"$5$abc$":                       "long",
		"$6$rounds=5000$abc$":           "long",
		"$6$rounds=1$ab$":               "long",
		"$6$rounds=99999999$ab$":        "any",
		"$6$rounds=abc$ab$":             "any",
		"$6$rounds=5000":                "any",
		"$1$abc$":                       "none",
		"$1$":                           "none",
		"$2b$10$":                       "any",
		"$2a$12$":                       "any",
		"$2y$05$":                       "any",
		"$2b$10$abcdefghijklmnopqrstuu": "none",
		"$y$j9T$abc$":                   "none",
		"xx":                            "none",
	}
	for s, want := range cases {
		if got := CryptFails(s); got != want {
			t.Errorf("%s: %s, want %s", s, got, want)
		}
	}
}

func TestPickSalt(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n"
	cases := []struct {
		shadow, account, fails string
	}{
		{"root:*::0:::::\nbin:!::0:::::\nalice:" + sha512Alice + ":20762:0:99999:7:::\nbob:*:20762:0:99999:7:::\n", "alice", "long"},
		{"root:*::0:::::\nalice:$1$abc$xyz:1::::::\nbob:$6$ab$cd:1::::::\n", "alice", "none"}, // the first $-hash decides
		{"root:$2b$10$abcdefghijklmnopqrstuu" + strings.Repeat("A", 31) + ":1::::::\n", "root", "any"},
		{"root:*::0:::::\n", "", "none"},
	}
	for i, c := range cases {
		d := PickSalt(ParseAccounts([]byte(passwd), []byte(c.shadow), nil, nil))
		if d.Account != c.account || d.Fails != c.fails {
			t.Errorf("%d: %+v", i, d)
		}
	}
	// pick_salt copies at most 31 bytes: a long rounds= value cut before
	// its '$' makes crypt fail for every password.
	long := "root:$6$rounds=00000000000000000000005000$abc$hash:1::::::\n"
	if d := PickSalt(ParseAccounts([]byte(passwd), []byte(long), nil, nil)); d.Fails != "any" || len(d.Setting) != 31 {
		t.Errorf("truncated setting: %+v", d)
	}
}

func TestShadowLookup(t *testing.T) {
	passwd := []byte("bob:*:1001:1001::/home/bob:/bin/sh\ncarol:x:1002:1002::/home/carol:/bin/sh\ndan:x:1003:1003::/:/bin/sh\nerin:x:1004:1004::/:/bin/sh\n")
	shadow := []byte("bob:" + strings.Repeat("y", 300) + ":1::::::\n" + // too long for musl's buffer
		"carol:bad:notanumber::::::\ncarol:*:1::::::\n" + // first line unparsable: musl keeps looking
		"dan:$6$x$y:1:::::5:\n")
	tcb := map[string][]byte{"erin": []byte("erin:*:1::::::\n")}
	a := ParseAccounts(passwd, shadow, nil, tcb)
	got := map[string]string{}
	for _, acc := range a.List {
		got[acc.Name] = acc.From + " " + acc.Field
	}
	want := map[string]string{"bob": "passwd *", "carol": "shadow *", "dan": "shadow $6$x$y", "erin": "tcb *"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if a.List[2].Expire != 5 {
		t.Errorf("expire %d", a.List[2].Expire)
	}
}

// memFiles is a target filesystem for tests.
type memFiles map[string]string

func (m memFiles) Read(p string) []byte {
	if s, ok := m[p]; ok {
		return []byte(s)
	}
	return nil
}

func (m memFiles) Glob(pattern string) []string {
	var out []string
	for p := range m {
		if ok, _ := path.Match(pattern, p); ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

const (
	stdPasswd = "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\nsvc:x:1002:1002::/:/sbin/nologin\n"
	stdShadow = "root:*::0:::::\nalice:" + sha512Alice + ":20762:0:99999:7:::\nbob:*:20762:0:99999:7:::\nsvc:!::0:::::\n"
	stdConfig = "Include /etc/ssh/sshd_config.d/*.conf\nAuthorizedKeysFile .ssh/authorized_keys\nSubsystem sftp internal-sftp\n"
)

type world struct {
	files    memFiles
	binaries []*Binary
	owners   map[string]Package
	branch   string
}

func newWorld(release string, pam bool, extra map[string]string) *world {
	v, _ := ParseRelease(release)
	w := &world{files: memFiles{
		"/etc/passwd":          stdPasswd,
		"/etc/shadow":          stdShadow,
		"/etc/group":           "root:x:0:root\nalice:x:1000:\nbob:x:1001:\nwheel:x:10:bob\n",
		"/etc/ssh/sshd_config": stdConfig,
		"/bin/sh":              "",
		"/sbin/nologin":        "",
	}}
	for k, val := range extra {
		if val == "\x00delete" {
			delete(w.files, k)
			continue
		}
		w.files[k] = val
	}
	w.binaries = []*Binary{
		{Path: "/usr/sbin/sshd", Role: "sshd", Release: release, Version: v, Libc: Musl, Helpers: []string{"/usr/lib/ssh/sshd-session"}, Config: "/etc/ssh/sshd_config"},
		{Path: "/usr/lib/ssh/sshd-session", Role: "sshd-session", Release: release, Version: v, Libc: Musl, PAM: pam},
	}
	return w
}

func (w *world) run() []Finding {
	return Run(Input{
		Binaries: w.binaries,
		Owners:   w.owners,
		Files:    w.files,
		Accounts: ParseAccounts(w.files.Read("/etc/passwd"), w.files.Read("/etc/shadow"), w.files.Read("/etc/group"), nil),
		Resolve: func(p string) (string, bool) {
			_, ok := w.files[p]
			return p, ok
		},
		Branch: w.branch,
		Now:    time.Unix(20800*86400, 0),
	})
}

func one(t *testing.T, fs []Finding) Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("%d findings: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestRun(t *testing.T) {
	cases := []struct {
		name     string
		release  string
		pam      bool
		extra    map[string]string
		libc     Libc
		owner    *Package
		kind     string
		status   Status
		severity string
		targets  string
		none     bool
	}{
		{name: "exposed", release: "10.0p2", kind: KindExposed, status: Vulnerable, severity: "critical", targets: "bob"},
		{name: "fixed upstream", release: "10.6p2", kind: KindServer, status: Fixed},
		{name: "later release", release: "10.7p1", kind: KindServer, status: Fixed},
		{name: "before 7.3", release: "7.2p2", kind: KindServer, status: Fixed},
		{name: "glibc", release: "9.2p1", libc: Glibc, none: true},
		{name: "unknown libc", release: "9.2p1", libc: Unknown, kind: KindServer, status: Undecided},
		{name: "alpine backport", release: "10.0p2", owner: &Package{"openssh-server", "10.0_p1-r11", "apk"}, kind: KindServer, status: Fixed},
		{name: "alpine old release", release: "10.0p2", owner: &Package{"openssh-server", "10.0_p1-r10", "apk"}, kind: KindExposed, status: Vulnerable},
		{name: "alpine 3.24", release: "10.3p1", owner: &Package{"openssh-server", "10.3_p1-r2", "apk"}, kind: KindServer, status: Fixed},
		{name: "alpine unpatched version", release: "10.1p1", owner: &Package{"openssh-server", "10.1_p1-r5", "apk"}, kind: KindExposed, status: Vulnerable},
		{name: "pam in use", release: "10.0p2", pam: true, extra: map[string]string{"/etc/ssh/sshd_config.d/pam.conf": "UsePAM yes\n"}, kind: KindServer, status: Inactive},
		{name: "pam built but off", release: "10.0p2", pam: true, kind: KindExposed, status: Vulnerable},
		{name: "UsePAM without PAM build", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/pam.conf": "UsePAM yes\n"}, kind: KindExposed, status: Vulnerable},
		{name: "passwords off", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n"}, kind: KindServer, status: Vulnerable, severity: "medium"},
		{name: "first value wins", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n", "/etc/ssh/sshd_config.d/10.conf": "PasswordAuthentication yes\n"}, kind: KindServer, status: Vulnerable, severity: "medium"},
		{name: "match address", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\nMatch Address 10.0.0.0/8\n PasswordAuthentication yes\n"}, kind: KindExposed, status: Vulnerable, severity: "high"},
		{name: "match user other", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\nMatch User alice\n PasswordAuthentication yes\n"}, kind: KindServer, status: Vulnerable},
		{name: "match group", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\nMatch Group wheel\n PasswordAuthentication yes\n"}, kind: KindExposed, status: Vulnerable, severity: "critical"},
		{name: "key required", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "AuthenticationMethods publickey,password\n"}, kind: KindServer, status: Vulnerable},
		{name: "password alone allowed", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "AuthenticationMethods publickey password\n"}, kind: KindExposed, status: Vulnerable},
		{name: "deny users", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "DenyUsers bob\n"}, kind: KindServer, status: Vulnerable},
		{name: "allow users host part", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config.d/00.conf": "AllowUsers bob@10.*\n"}, kind: KindExposed, status: Vulnerable, severity: "high"},
		{name: "root needs PermitRootLogin yes", release: "10.0p2", extra: map[string]string{"/etc/shadow": strings.Replace(stdShadow, "bob:*", "bob:!", 1)}, kind: KindServer, status: Vulnerable},
		{name: "root with PermitRootLogin yes", release: "10.0p2", extra: map[string]string{"/etc/shadow": strings.Replace(stdShadow, "bob:*", "bob:!", 1), "/etc/ssh/sshd_config.d/00.conf": "PermitRootLogin yes\n"}, kind: KindExposed, status: Vulnerable, targets: "root"},
		{name: "no donor", release: "10.0p2", extra: map[string]string{"/etc/shadow": strings.Replace(stdShadow, sha512Alice, "!", 1)}, kind: KindServer, status: Vulnerable},
		{name: "md5 donor", release: "10.0p2", extra: map[string]string{"/etc/shadow": strings.Replace(stdShadow, sha512Alice, "$1$abc$def", 1)}, kind: KindServer, status: Vulnerable},
		{name: "shell missing", release: "10.0p2", extra: map[string]string{"/bin/sh": "\x00delete"}, kind: KindServer, status: Vulnerable},
		{name: "chroot skips the shell check", release: "10.0p2", extra: map[string]string{"/bin/sh": "\x00delete", "/etc/ssh/sshd_config.d/00.conf": "ChrootDirectory /srv\n"}, kind: KindExposed, status: Vulnerable},
		{name: "expired", release: "10.0p2", extra: map[string]string{"/etc/shadow": strings.Replace(stdShadow, "bob:*:20762:0:99999:7:::", "bob:*:20762:0:99999:7::20000:", 1)}, kind: KindServer, status: Vulnerable},
		{name: "no config", release: "10.0p2", extra: map[string]string{"/etc/ssh/sshd_config": "\x00delete"}, kind: KindServer, status: Vulnerable, severity: "medium"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(c.release, c.pam, c.extra)
			if c.libc != "" {
				for _, b := range w.binaries {
					b.Libc = c.libc
				}
			}
			if c.owner != nil {
				w.owners = map[string]Package{"/usr/sbin/sshd": *c.owner}
				w.branch = "3.22"
			}
			fs := w.run()
			if c.none {
				if len(fs) != 0 {
					t.Fatalf("want no finding, got %+v", fs)
				}
				return
			}
			f := one(t, fs)
			if f.Kind != c.kind || f.Status != c.status {
				t.Fatalf("got %s %s (%s; %s)", f.Kind, f.Status, f.Message, f.Reason)
			}
			if c.severity != "" && f.Severity != c.severity {
				t.Errorf("severity %s, want %s", f.Severity, c.severity)
			}
			if c.targets != "" {
				var names []string
				for _, x := range f.Targets {
					names = append(names, x.Account)
				}
				if strings.Join(names, ",") != c.targets {
					t.Errorf("targets %v, want %s", names, c.targets)
				}
			}
			if f.Status == Vulnerable && f.Fix == "" {
				t.Error("no fix text")
			}
			if f.Status == Fixed && f.Reason == "" {
				t.Error("cleared without a reason")
			}
		})
	}
}

func TestHelperLinking(t *testing.T) {
	// The Alpine PAM flavour: the listener links no libpam, its helpers do.
	w := newWorld("10.0p2", false, map[string]string{"/etc/ssh/sshd_config.d/pam.conf": "UsePAM yes\n"})
	v, _ := ParseRelease("10.0p2")
	w.binaries = []*Binary{
		{Path: "/usr/sbin/sshd.pam", Role: "sshd", Release: "10.0p2", Version: v, Libc: Musl, Helpers: []string{"/usr/lib/ssh/sshd-session.pam", "/usr/lib/ssh/sshd-auth.pam"}, Config: "/etc/ssh/sshd_config"},
		{Path: "/usr/lib/ssh/sshd-session.pam", Role: "sshd-session", Release: "10.0p2", Version: v, Libc: Musl, PAM: true},
		{Path: "/usr/lib/ssh/sshd-auth.pam", Role: "sshd-auth", Release: "10.0p2", Version: v, Libc: Musl, PAM: true},
	}
	f := one(t, w.run())
	if f.Status != Inactive || len(f.Helpers) != 2 {
		t.Fatalf("%+v", f)
	}
}

func TestBranchFromRelease(t *testing.T) {
	for in, want := range map[string]string{"3.22.2\n": "3.22", "3.24.0": "3.24", "3.23_alpha20260101": "edge", "": ""} {
		if got := BranchFromRelease(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	for _, b := range AlpineBranches() {
		if v, ok := AlpineFixedFor(b); !ok {
			t.Errorf("%s: no fixed version", b)
		} else if fixed, _, ok := APKFixed(v); !ok || !fixed {
			t.Errorf("%s: %s is not judged fixed", b, v)
		}
	}
}
