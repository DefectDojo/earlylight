package assess

import "testing"

// Final review A1: each case is a server sshd_config
// alone leaves exposed (UsePAM no on a PAM build); none may be cleared by a
// script or text the command only passes as an argument.
func TestArgumentNeverLowers(t *testing.T) {
	sup := "#!/bin/sh\nexec supervisord\n"
	yes := "#!/bin/sh\n/usr/sbin/sshd -D -o UsePAM=yes\n"
	for _, c := range []struct {
		name    string
		cmd     []string
		scripts map[string]string
		cfg     string
		want    string // status/severity
	}{
		{"A: binary program, script argument", []string{"/usr/bin/app", "--hook", "/opt/debug.sh"}, map[string]string{"/opt/debug.sh": yes}, "UsePAM no\n", "vulnerable/critical"},
		{"A: argument word found in PATH", []string{"/usr/bin/app", "start"}, map[string]string{"/usr/bin/start": yes}, "UsePAM no\n", "vulnerable/critical"},
		{"B: argument script names the script", []string{"/entry.sh", "/opt/debug.sh"}, map[string]string{"/entry.sh": sup, "/opt/debug.sh": "#!/bin/sh\n. /opt/real.sh\n", "/opt/real.sh": yes}, "UsePAM no\n", "vulnerable/critical"},
		{"C: sh -c text as arguments", []string{"/entry.sh", "sh", "-c", "sshd -D -o UsePAM=yes"}, map[string]string{"/entry.sh": "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n"}, "UsePAM no\n", "vulnerable/critical"},
		{"C: sh -c text that only mentions sshd", []string{"/entry.sh", "sh", "-c", "while pgrep sshd >/dev/null; do sleep 5; done"}, map[string]string{"/entry.sh": "#!/bin/sh\n/usr/sbin/sshd -o UsePAM=no\nexec \"$@\"\n"}, "UsePAM yes\n", "vulnerable/critical"},
		{"E: argument script says UsePAM yes", []string{"/entry.sh", "/opt/alt.sh"}, map[string]string{"/entry.sh": "#!/bin/sh\nsed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config\nexec /usr/sbin/sshd -D\n", "/opt/alt.sh": "#!/bin/sh\necho 'UsePAM yes' >> /etc/ssh/sshd_config\n"}, "PasswordAuthentication no\nUsePAM no\n", "vulnerable/high"},
	} {
		w := newWorld("10.0p2", true, map[string]string{"/etc/ssh/sshd_config": c.cfg})
		scripts := map[string][]byte{}
		for k, v := range c.scripts {
			scripts[k] = []byte(v)
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
		if got := string(f.Status) + "/" + f.Severity; got != c.want {
			t.Errorf("%s: got %s, want %s (%s)", c.name, got, c.want, f.Reason)
		}
	}
}
