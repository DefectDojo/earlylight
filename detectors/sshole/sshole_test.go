package sshole_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/DefectDojo/earlylight/detectors/sshole"
	"github.com/DefectDojo/earlylight/detectors/sshole/internal/testelf"
	"github.com/DefectDojo/earlylight/internal/cli"
	"github.com/DefectDojo/earlylight/internal/engine"
)

var cfg = cli.Config{Tool: "earlylight", Version: "test", Summary: "test"}

func write(t *testing.T, root, rel string, data []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
}

type report struct {
	Targets []struct {
		Error    string           `json:"error"`
		Findings []engine.Finding `json:"findings"`
	} `json:"targets"`
}

func run(t *testing.T, args ...string) report {
	t.Helper()
	var out, errb bytes.Buffer
	full := append([]string{args[0], args[1], "--format", "json"}, args[2:]...)
	cli.Run(cfg, full, &out, &errb)
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errb.String())
	}
	return r
}

// alpineRoot lays out an Alpine system with an unfixed sshd.
func alpineRoot(t *testing.T, apkVersion string) string {
	root := t.TempDir()
	sshd := testelf.ELF("/lib/ld-musl-x86_64.so.1", []string{"libc.musl-x86_64.so.1"}, testelf.SSHDStrings("10.0p2", "/usr/lib/ssh/sshd-session", "/usr/lib/ssh/sshd-auth")...)
	write(t, root, "usr/sbin/sshd", sshd, 0o755)
	write(t, root, "usr/lib/ssh/sshd-session", testelf.ELF("/lib/ld-musl-x86_64.so.1", nil, testelf.SSHDStrings("10.0p2")...), 0o755)
	write(t, root, "usr/lib/ssh/sshd-auth", testelf.ELF("/lib/ld-musl-x86_64.so.1", nil, testelf.SSHDStrings("10.0p2")...), 0o755)
	write(t, root, "bin/busybox", testelf.ELF("/lib/ld-musl-x86_64.so.1", nil, "busybox"), 0o755)
	if err := os.Symlink("/bin/busybox", filepath.Join(root, "bin/sh")); err != nil {
		t.Fatal(err)
	}
	write(t, root, "etc/alpine-release", []byte("3.22.2\n"), 0o644)
	write(t, root, "etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n"), 0o644)
	write(t, root, "etc/shadow", []byte("root:*::0:::::\nalice:$6$salt$hash:20762:0:99999:7:::\nbob:*:20762:0:99999:7:::\n"), 0o640)
	write(t, root, "etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\nSubsystem sftp internal-sftp\n"), 0o644)
	write(t, root, "lib/apk/db/installed", []byte("P:openssh-server\nV:"+apkVersion+"\nF:usr/sbin\nR:sshd\nF:usr/lib/ssh\nR:sshd-session\nR:sshd-auth\n\n"), 0o644)
	return root
}

func TestScanFS(t *testing.T) {
	r := run(t, "scan", "fs", "--detector", "sshole", "--as-root", alpineRoot(t, "10.0_p1-r10"))
	fs := r.Targets[0].Findings
	if len(fs) != 1 || fs[0].Kind != sshole.KindExposed || fs[0].Verdict != engine.Vulnerable || fs[0].Facts["accounts"] != "bob" {
		t.Fatalf("%+v", fs)
	}
	if !strings.Contains(fs[0].Fix, "10.0_p1-r11") {
		t.Errorf("fix %q", fs[0].Fix)
	}
	r = run(t, "scan", "fs", "--detector", "sshole", "--as-root", alpineRoot(t, "10.0_p1-r11"))
	if fs := r.Targets[0].Findings; len(fs) != 1 || fs[0].Verdict != engine.Fixed {
		t.Fatalf("%+v", fs)
	}
}

// sshServer runs an in-process SSH server that offers password logins or
// not, and records whether any password arrived.
func sshServer(t *testing.T, passwords bool, version string) (string, *bool) {
	t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got := false
	sc := &ssh.ServerConfig{ServerVersion: version}
	sc.AddHostKey(signer)
	sc.PublicKeyCallback = func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, errors.New("no") }
	if passwords {
		sc.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			got = true
			return nil, errors.New("no")
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ssh.NewServerConn(c, sc)
			}()
		}
	}()
	return l.Addr().String(), &got
}

func TestProbe(t *testing.T) {
	d := &sshole.Detector{}
	cases := []struct {
		version   string
		passwords bool
		verdict   engine.Verdict
		none      bool
	}{
		{"SSH-2.0-OpenSSH_10.0", true, engine.Unknown, false},
		{"SSH-2.0-OpenSSH_10.0", false, engine.Inactive, false},
		{"SSH-2.0-OpenSSH_10.6p2", true, engine.Fixed, false},
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", true, "", true},
		{"SSH-2.0-dropbear_2025.88", true, "", true},
	}
	for _, c := range cases {
		addr, got := sshServer(t, c.passwords, c.version)
		_, n, fs, err := d.Probe(context.Background(), addr, 5*time.Second)
		if err != nil || n != 1 {
			t.Fatalf("%s: %v %d", c.version, err, n)
		}
		if *got {
			t.Fatalf("%s: the probe sent a password", c.version)
		}
		if c.none {
			if len(fs) != 0 {
				t.Errorf("%s: %+v", c.version, fs)
			}
			continue
		}
		if len(fs) != 1 || fs[0].Verdict != c.verdict {
			t.Errorf("%s: %+v", c.version, fs)
		}
	}
}

func TestProbeNotSSH(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	_, _, _, err = (&sshole.Detector{}).Probe(context.Background(), l.Addr().String(), 2*time.Second)
	if !errors.Is(err, engine.ErrNotApplicable) {
		t.Fatalf("want not applicable, got %v", err)
	}
	// A host scan where no detector applies fails with the reason.
	tg := engine.ScanHost([]engine.Detector{&sshole.Detector{}}, l.Addr().String(), engine.Options{Timeout: 2 * time.Second})
	if tg.Error == "" {
		t.Fatal("no error")
	}
}

func TestRepoAndFix(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", []byte("FROM alpine:3.22\nRUN apk add --no-cache openssh-server && usermod -p '*' bob\n"), 0o644)
	r := run(t, "scan", "repo", "--offline", "--detector", "sshole", root)
	if n := len(r.Targets[0].Findings); n != 2 {
		t.Fatalf("%d findings: %+v", n, r.Targets[0].Findings)
	}
	var out, errb bytes.Buffer
	if code := cli.Run(cfg, []string{"fix", "--offline", "--detector", "sshole", root}, &out, &errb); code != 0 {
		t.Fatalf("fix exit %d\n%s%s", code, out.String(), errb.String())
	}
	b, _ := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if string(b) != "FROM alpine:3.22\nRUN apk add --no-cache 'openssh-server>=10.0_p1-r11' && usermod -p '*NP*' bob\n" {
		t.Fatalf("%s", b)
	}
	r = run(t, "scan", "repo", "--offline", "--detector", "sshole", root)
	if n := len(r.Targets[0].Findings); n != 0 {
		t.Fatalf("left: %+v", r.Targets[0].Findings)
	}
}
