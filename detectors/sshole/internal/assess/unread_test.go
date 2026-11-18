package assess

import (
	"fmt"
	"strings"
	"testing"
)

// unreadFiles lists some files that Read cannot give (over the limit).
type unreadFiles struct {
	memFiles
	unread []string
}

func (u unreadFiles) Glob(pattern string) []string {
	out := u.memFiles.Glob(pattern)
	for _, p := range u.unread {
		if strings.HasPrefix(p, strings.TrimSuffix(pattern, "*.conf")) {
			out = append(out, p)
		}
	}
	return out
}

// What the configuration names but was not read is listed as unread: an
// included file Read cannot give, and anything past the parser's limits.
func TestConfigUnread(t *testing.T) {
	fs := unreadFiles{memFiles{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"}, []string{"/etc/ssh/sshd_config.d/50-site.conf"}}
	c := ParseConfig(fs, "/etc/ssh/sshd_config")
	if strings.Join(c.Unread, ",") != "/etc/ssh/sshd_config.d/50-site.conf" || c.Global("usepam", "no") != "yes" {
		t.Errorf("unread %v", c.Unread)
	}
	m := memFiles{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"}
	for i := 0; i <= maxIncludes; i++ {
		m[fmt.Sprintf("/etc/ssh/sshd_config.d/%03d.conf", i)] = "Port 22\n"
	}
	if c := ParseConfig(m, "/etc/ssh/sshd_config"); len(c.Unread) != 1 || !strings.Contains(c.Unread[0], "more than 256") {
		t.Errorf("past the include limit: unread %v", c.Unread)
	}
	// Includes nested past the parser's depth.
	m = memFiles{}
	for i := 0; i <= 17; i++ {
		m[fmt.Sprintf("/etc/ssh/%d.conf", i)] = fmt.Sprintf("Include /etc/ssh/%d.conf\n", i+1)
	}
	m["/etc/ssh/sshd_config"] = "Include /etc/ssh/0.conf\n"
	if c := ParseConfig(m, "/etc/ssh/sshd_config"); len(c.Unread) != 1 || !strings.Contains(c.Unread[0], "nested too deeply") {
		t.Errorf("nested too deeply: unread %v", c.Unread)
	}
	// Directives past the parser's limit.
	if c := ParseConfig(memFiles{"/etc/ssh/sshd_config": strings.Repeat("Port 22\n", maxDirectives+1) + "UsePAM no\n"}, "/etc/ssh/sshd_config"); len(c.Unread) != 1 || !strings.Contains(c.Unread[0], "directives") {
		t.Errorf("past the directive limit: unread %v", c.Unread)
	}
	if c := ParseConfig(memFiles{"/etc/ssh/sshd_config": "UsePAM yes\n"}, "/etc/ssh/sshd_config"); len(c.Unread) != 0 {
		t.Errorf("all read: unread %v", c.Unread)
	}
}

// Round-3 review finding 5: how the start command finds its scripts, read
// or not: by PATH, through a symbolic link, and named by another script.
func TestStartCommandLookups(t *testing.T) {
	resolve := func(p string) (string, bool) {
		if p == "/entrypoint" {
			return "/usr/local/bin/real-entrypoint.sh", true
		}
		return p, false
	}
	read := map[string][]byte{
		"/usr/local/bin/start.sh":           []byte("#!/bin/sh\nexec /opt/run.sh\n"),
		"/usr/local/bin/real-entrypoint.sh": []byte("#!/bin/sh\nexec /usr/sbin/sshd -D\n"),
		"/opt/run.sh":                       []byte("#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n"),
	}
	where := func(sc []script) string {
		var out []string
		for _, s := range sc {
			out = append(out, s.where)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		cmd  []string
		want string
	}{
		{[]string{"start.sh"}, "start.sh,/opt/run.sh"},                    // PATH, then a script it names
		{[]string{"/entrypoint"}, "/entrypoint"},                          // a symbolic link
		{[]string{"tini", "--", "/bin/sh", "/opt/run.sh"}, "/opt/run.sh"}, // a wrapper and a shell
	} {
		st := Startup{Command: c.cmd, Scripts: read}
		if got := where(st.startScripts(resolve)); got != c.want {
			t.Errorf("%v: %s, want %s", c.cmd, got, c.want)
		}
	}

	// The same lookups find a script that was not read.
	for _, c := range []struct {
		cmd    []string
		unread string
		dirs   []string
		want   string
	}{
		{[]string{"start.sh"}, "/usr/local/bin/start.sh", nil, "/usr/local/bin/start.sh"},
		{[]string{"/entrypoint"}, "/usr/local/bin/real-entrypoint.sh", nil, "/usr/local/bin/real-entrypoint.sh"},
		{[]string{"start.sh"}, "/opt/run.sh", nil, "/opt/run.sh"}, // named by a script that was read
		{[]string{"/usr/bin/other"}, "/opt/run.sh", nil, ""},      // not run at start
		{nil, "/etc/cont-init.d/10-sshd", nil, "/etc/cont-init.d/10-sshd"},
		{[]string{"start.sh"}, "", []string{"/usr/local/bin"}, "/usr/local/bin"}, // its directory was not listed
		{nil, "", []string{"/etc"}, "/etc"},                                      // holds the init directories
	} {
		u := map[string]bool{}
		if c.unread != "" {
			u[c.unread] = true
		}
		st := Startup{Command: c.cmd, Scripts: map[string][]byte{}, Unread: u, UnreadDirs: c.dirs}
		for p, b := range read {
			if p != c.unread {
				st.Scripts[p] = b
			}
		}
		got := strings.Join(st.unreadStart(resolve, st.startScripts(resolve)), ",")
		if got != c.want {
			t.Errorf("%v with %q %v unread: %q, want %q", c.cmd, c.unread, c.dirs, got, c.want)
		}
	}
	if got := (Startup{UnreadAll: true}).unreadStart(nil, nil); len(got) != 1 {
		t.Errorf("past the record limit: %v", got)
	}
}

// A start script behind a wrapper that takes arguments ("tini --", "gosu
// USER") is read like one named first: one that turns PAM off is not
// cleared.
func TestStartScriptBehindWrapper(t *testing.T) {
	for _, cmd := range [][]string{
		{"/entrypoint.sh"},
		{"tini", "--", "/entrypoint.sh"},
		{"/sbin/tini", "-s", "--", "/entrypoint.sh"},
		{"gosu", "app", "/entrypoint.sh"},
	} {
		w := newWorld("10.0p2", true, map[string]string{"/etc/ssh/sshd_config": "UsePAM yes\n"})
		in := Input{
			Binaries: w.binaries, Files: w.files,
			Accounts: ParseAccounts(w.files.Read("/etc/passwd"), w.files.Read("/etc/shadow"), w.files.Read("/etc/group"), nil),
			Resolve:  func(p string) (string, bool) { _, ok := w.files[p]; return p, ok },
			Now:      w.now(),
			Image:    true,
			Startup:  Startup{Command: cmd, Scripts: map[string][]byte{"/entrypoint.sh": []byte("#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n")}},
		}
		if f := one(t, Run(in)); f.Status == Inactive {
			t.Errorf("%v: %s (%s)", cmd, f.Status, f.Reason)
		}
	}
}

// Final review finding 2: start scripts that start sshd in different ways
// are each judged, and the worst kept: one that turns PAM off is never
// voided by another that does not.
func TestStartScriptsDisagree(t *testing.T) {
	pamOff := "#!/bin/sh\n/usr/sbin/sshd -o UsePAM=no\nexec \"$@\"\n"
	plain := "#!/bin/sh\npgrep sshd || /usr/sbin/sshd -D\n"
	for _, c := range []struct {
		name    string
		cmd     []string
		scripts map[string]string
		cleared bool
	}{
		{"entrypoint then a CMD script", []string{"/entry.sh", "/cmd.sh"}, map[string]string{"/entry.sh": pamOff, "/cmd.sh": plain}, false},
		{"two scripts", []string{"/a.sh", "/b.sh"}, map[string]string{"/a.sh": plain, "/b.sh": pamOff}, false},
		{"a shell and two scripts", []string{"/bin/sh", "/a.sh", "/b.sh"}, map[string]string{"/a.sh": pamOff, "/b.sh": plain}, false},
		{"a CMD found on PATH", []string{"/entry.sh", "start"}, map[string]string{"/entry.sh": pamOff, "/usr/local/bin/start": plain}, false},
		{"two init scripts", nil, map[string]string{"/etc/cont-init.d/10-a": pamOff, "/etc/cont-init.d/20-b": plain}, false},
		{"two scripts that agree", []string{"/a.sh", "/b.sh"}, map[string]string{"/a.sh": plain, "/b.sh": plain}, true},
	} {
		w := newWorld("10.0p2", true, map[string]string{"/etc/ssh/sshd_config": "UsePAM yes\n"})
		scripts := map[string][]byte{}
		for p, b := range c.scripts {
			scripts[p] = []byte(b)
		}
		in := Input{
			Binaries: w.binaries, Files: w.files,
			Accounts: ParseAccounts(w.files.Read("/etc/passwd"), w.files.Read("/etc/shadow"), w.files.Read("/etc/group"), nil),
			Resolve:  func(p string) (string, bool) { _, ok := w.files[p]; return p, ok },
			Now:      w.now(),
			Image:    true,
			Startup:  Startup{Command: c.cmd, Scripts: scripts},
		}
		f := one(t, Run(in))
		if (f.Status == Inactive) != c.cleared || !c.cleared && (f.Status != Vulnerable || f.Severity != "critical") {
			t.Errorf("%s: %s %s (%s)", c.name, f.Status, f.Severity, f.Reason)
		}
	}
}
