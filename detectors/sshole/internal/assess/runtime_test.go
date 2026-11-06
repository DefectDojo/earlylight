package assess

import (
	"strings"
	"testing"
)

func runStartup(w *world, st Startup) []Finding {
	return Run(Input{
		Binaries: w.binaries, Owners: w.owners, Files: w.files,
		Accounts: ParseAccounts(w.files.Read("/etc/passwd"), w.files.Read("/etc/shadow"), w.files.Read("/etc/group"), nil),
		Resolve: func(p string) (string, bool) {
			_, ok := w.files[p]
			return p, ok
		},
		Image: true, Startup: st, Now: w.now(),
	})
}

func TestStartupCommand(t *testing.T) {
	// The config turns passwords off, the command turns them back on.
	w := newWorld("10.0p2", false, map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n"})
	f := one(t, runStartup(w, Startup{Command: []string{"/usr/sbin/sshd", "-D", "-e", "-o", "PasswordAuthentication=yes"}}))
	if f.Kind != KindExposed || f.StartedWith != "the container command" {
		t.Fatalf("%+v", f)
	}
	// -f points at another config.
	w = newWorld("10.0p2", false, map[string]string{"/srv/sshd.conf": "PasswordAuthentication no\n"})
	f = one(t, runStartup(w, Startup{Command: []string{"tini", "--", "/usr/sbin/sshd", "-D", "-f", "/srv/sshd.conf"}}))
	if f.Kind != KindServer || f.Config != "/srv/sshd.conf" {
		t.Fatalf("%+v", f)
	}
	// sh -c text.
	w = newWorld("10.0p2", false, map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n"})
	f = one(t, runStartup(w, Startup{Command: []string{"/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D -oPasswordAuthentication=yes"}}))
	if f.Kind != KindExposed {
		t.Fatalf("%+v", f)
	}
}

func TestStartupScripts(t *testing.T) {
	quiet := map[string]string{"/etc/shadow": strings.Replace(stdShadow, "bob:*", "bob:!", 1), "/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n"}
	cases := []struct {
		name    string
		script  string
		kind    string
		atStart bool
	}{
		{"turns on passwords and sets a star", "#!/bin/sh\nsed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config\nusermod -p '*' \"$USER\"\nexec /usr/sbin/sshd -D\n", KindExposed, true},
		{"star but passwords stay off", "#!/bin/sh\necho \"$USER:*\" | chpasswd -e\nexec /usr/sbin/sshd -D\n", KindServer, true},
		{"nothing relevant", "#!/bin/sh\nssh-keygen -A\nexec /usr/sbin/sshd -D\n", KindServer, false},
		{"UsePAM on", "#!/bin/sh\necho 'PasswordAuthentication yes' >> /etc/ssh/sshd_config\necho 'UsePAM yes' >> /etc/ssh/sshd_config\nusermod -p '*' x\n", KindServer, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld("10.0p2", false, quiet)
			f := one(t, runStartup(w, Startup{Command: []string{"/entrypoint.sh"}, Scripts: map[string][]byte{"/entrypoint.sh": []byte(c.script)}}))
			if f.Kind != c.kind || (len(f.AtStart) > 0) != c.atStart {
				t.Fatalf("%s %+v: %s", f.Kind, f.AtStart, f.Message)
			}
			if f.Kind == KindExposed && (f.Severity != "high" || !strings.Contains(f.Message, "/entrypoint.sh")) {
				t.Errorf("%+v", f)
			}
		})
	}
}

func TestStartupDonorFromChpasswd(t *testing.T) {
	// No $-hash in the image; the script sets a password with chpasswd
	// (sha512), turns passwords on and has a "*" account.
	w := newWorld("10.0p2", false, map[string]string{"/etc/shadow": strings.Replace(stdShadow, sha512Alice, "!", 1)})
	script := "#!/bin/sh\necho \"admin:$ADMIN_PASSWORD\" | chpasswd\nexec /usr/sbin/sshd -D\n"
	f := one(t, runStartup(w, Startup{Command: []string{"entrypoint"}, Scripts: map[string][]byte{"/usr/local/bin/entrypoint": []byte(script)}}))
	if f.Kind != KindExposed || !strings.Contains(f.Message, "sets passwords with chpasswd") {
		t.Fatalf("%+v", f)
	}
}

func TestInitDirs(t *testing.T) {
	w := newWorld("10.0p2", false, map[string]string{"/etc/ssh/sshd_config.d/00.conf": "PasswordAuthentication no\n"})
	f := one(t, runStartup(w, Startup{Command: []string{"/init"}, Scripts: map[string][]byte{
		"/etc/s6-overlay/s6-rc.d/init-ssh/run": []byte("#!/bin/sh\nif [ \"$PASSWORD_ACCESS\" = true ]; then sed -i '/PasswordAuthentication/c\\\\PasswordAuthentication yes' /etc/ssh/sshd_config; fi\n"),
	}}))
	if f.Kind != KindExposed || f.AtStart[0] != "/etc/s6-overlay/s6-rc.d/init-ssh/run" {
		t.Fatalf("%+v", f)
	}
}

func TestOpkg(t *testing.T) {
	status := []byte("Package: openssh-server\nVersion: 9.9_p2-1\nStatus: install user installed\n\nPackage: zlib\nVersion: 1.3-1\nStatus: install user installed\n")
	owners := OpkgOwners(status, map[string][]byte{"openssh-server": []byte("/usr/sbin/sshd\n/etc/ssh/sshd_config\n")})
	if p := owners["/usr/sbin/sshd"]; p.Name != "openssh-server" || p.Format != "opkg" {
		t.Fatalf("%+v", owners)
	}
	for v, want := range map[string]bool{"9.9_p2-1": false, "9.9_p2-2": true, "9.8p1-2": true, "9.8p1-1": false, "10.6_p2-1": true, "9.2p1-3": false} {
		if fixed, _, ok := opkgStatus(v); !ok || fixed != want {
			t.Errorf("%s: %v %v", v, fixed, ok)
		}
	}
}
