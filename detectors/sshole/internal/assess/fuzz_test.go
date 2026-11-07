package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/sshole/internal/testelf"
)

func FuzzInspect(f *testing.F) {
	f.Add(testelf.ELF("/lib/ld-musl-x86_64.so.1", []string{"libpam.so.0"}, testelf.SSHDStrings("10.0p2", "/usr/lib/ssh/sshd-session")...))
	f.Fuzz(func(t *testing.T, b []byte) { Inspect("/usr/sbin/sshd", b) })
}

func FuzzAccounts(f *testing.F) {
	f.Add("root:x:0:0::/:/bin/sh\nbob:x:1:1::/:/bin/sh\n", "root:$6$rounds=5000$a$b:1::::::\nbob:*:1::::::\n")
	f.Fuzz(func(t *testing.T, passwd, shadow string) {
		a := ParseAccounts([]byte(passwd), []byte(shadow), []byte(passwd), nil)
		d := PickSalt(a)
		if len(d.Setting) > 31 {
			t.Fatalf("setting longer than sshd's buffer: %q", d.Setting)
		}
	})
}

func FuzzConfig(f *testing.F) {
	f.Add("Include x/*.conf\nPasswordAuthentication=no\nMatch User bob,!alice Address 10.*\n PasswordAuthentication \"yes\" # c\n")
	f.Fuzz(func(t *testing.T, s string) {
		fs := memFiles{"/etc/ssh/sshd_config": s, "/etc/ssh/x/a.conf": s}
		c := ParseConfig(fs, "/etc/ssh/sshd_config")
		acc := Account{Name: "bob"}
		c.Values("passwordauthentication", acc, nil, "yes")
		c.Lists("allowusers", acc, nil)
		passwordValues(c, acc, nil)
	})
}

func FuzzStartup(f *testing.F) {
	f.Add("/bin/sh", "-c", "#!/bin/sh\nusermod -p '*' x; exec /usr/sbin/sshd -D -o PasswordAuthentication=yes -f /x")
	f.Fuzz(func(t *testing.T, a, b, script string) {
		st := Startup{Command: []string{a, b, script}, Scripts: map[string][]byte{"/entrypoint.sh": []byte(script), "/etc/cont-init.d/x": []byte(script)}}
		sc := st.startScripts(nil)
		invocations(st, sc)
		startupSignals(sc).describe()
	})
}
