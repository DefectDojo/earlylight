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

// Second final review, finding 1: the same rule when the entrypoint is
// written "sh SCRIPT". A -c after the shell's script belongs to the script,
// a script named without a slash may not be the one found on PATH, and the
// value of a wrapper's option is not the program. main judged each of
// these by sshd_config and the script it names by path; none may be lower.
func TestShellOperandNeverLowers(t *testing.T) {
	yes := "#!/bin/sh\n/usr/sbin/sshd -D -o UsePAM=yes\n"
	no := "#!/bin/sh\nexec /usr/sbin/sshd -D -o UsePAM=no\n"
	starts := "#!/bin/sh\n/usr/sbin/sshd -o UsePAM=no\nexec \"$@\"\n"
	watch := "while pgrep sshd >/dev/null; do sleep 5; done"
	for _, c := range []struct {
		name    string
		cmd     []string
		scripts map[string]string
		cfg     string
		want    string // status/severity
	}{
		{"sh SCRIPT, then sh -c text that only mentions sshd", []string{"/bin/sh", "/entry.sh", "sh", "-c", watch}, map[string]string{"/entry.sh": starts}, "UsePAM yes\n", "vulnerable/critical"},
		{"dumb-init sh SCRIPT, then sh -c text", []string{"dumb-init", "/bin/sh", "/entry.sh", "sh", "-c", watch}, map[string]string{"/entry.sh": starts}, "UsePAM yes\n", "vulnerable/critical"},
		{"sh SCRIPT, then sh -c text with UsePAM=yes", []string{"/bin/sh", "/entry.sh", "sh", "-c", "sshd -D -o UsePAM=yes"}, map[string]string{"/entry.sh": no}, "UsePAM no\n", "vulnerable/critical"},
		{"tini -- sh SCRIPT, then sh -c text", []string{"/sbin/tini", "--", "/bin/sh", "/entry.sh", "sh", "-c", "sshd -D -o UsePAM=yes"}, map[string]string{"/entry.sh": no}, "UsePAM no\n", "vulnerable/critical"},
		{"sh SCRIPT -c text: the script's own arguments", []string{"sh", "/entry.sh", "-c", "sshd -D -o UsePAM=yes"}, map[string]string{"/entry.sh": no}, "UsePAM no\n", "vulnerable/critical"},
		{"busybox ash SCRIPT -c text", []string{"/bin/busybox", "ash", "/entry.sh", "-c", "sshd -D -o UsePAM=yes"}, map[string]string{"/entry.sh": no}, "UsePAM no\n", "vulnerable/critical"},
		{"bash -o pipefail SCRIPT, then sh -c text", []string{"bash", "-o", "pipefail", "/entry.sh", "sh", "-c", "sshd -D -o UsePAM=yes"}, map[string]string{"/entry.sh": no}, "UsePAM no\n", "vulnerable/critical"},
		{"sh NAME: the script on PATH may not be the one in the working directory", []string{"sh", "entry.sh"}, map[string]string{"/usr/local/bin/entry.sh": yes}, "UsePAM no\n", "vulnerable/critical"},
		{"tini -- bash NAME", []string{"/sbin/tini", "--", "bash", "entry.sh"}, map[string]string{"/usr/local/bin/entry.sh": yes}, "UsePAM no\n", "vulnerable/critical"},
		{"the value of a wrapper's option is not the program", []string{"env", "-u", "start", "/usr/bin/app"}, map[string]string{"/usr/bin/start": yes}, "UsePAM no\n", "vulnerable/critical"},
		{"a -lc text with = in it is not an assignment", []string{"bash", "-lc", "sshd -D -o LogLevel=DEBUG", "entry.sh"}, map[string]string{"/usr/local/bin/entry.sh": yes}, "UsePAM no\n", "vulnerable/critical"},
		// What the command's own shell runs still decides.
		{"control: sh -c text is the command", []string{"sh", "-c", "/usr/sbin/sshd -D -o UsePAM=yes"}, nil, "UsePAM no\n", "inactive/"},
		{"control: sh -e -c text", []string{"/bin/sh", "-e", "-c", "/usr/sbin/sshd -D -o UsePAM=yes"}, nil, "UsePAM no\n", "inactive/"},
		{"control: busybox sh -c text", []string{"busybox", "sh", "-c", "/usr/sbin/sshd -D -o UsePAM=yes"}, nil, "UsePAM no\n", "inactive/"},
		{"control: sh /SCRIPT is the program", []string{"/bin/sh", "/entry.sh"}, map[string]string{"/entry.sh": yes}, "UsePAM no\n", "inactive/"},
		{"control: tini -- /SCRIPT", []string{"/sbin/tini", "--", "/entry.sh"}, map[string]string{"/entry.sh": yes}, "UsePAM no\n", "inactive/"},
		{"control: env A=1 /SCRIPT", []string{"env", "A=1", "/entry.sh"}, map[string]string{"/entry.sh": yes}, "UsePAM no\n", "inactive/"},
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
