package repo

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, s string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func scan(t *testing.T, root string, opts Options) []Finding {
	t.Helper()
	res, err := Scan(context.Background(), root, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings
}

func rules(fs []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Rule+":"+f.File+":"+itoa(f.Line)]++
	}
	return out
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

const svc = `FROM alpine:3.22 AS base
RUN apk add --no-cache \
      openssh-server \
      bash
RUN adduser -D bob \
 && usermod -p '*' bob \
 && echo 'carol:*' | chpasswd -e \
 && sed -i 's/^dave:!/dave:*/' /etc/shadow \
 && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
FROM base
RUN apk add openssh-server-pam=10.0_p1-r10
`

func TestScan(t *testing.T) {
	root := t.TempDir()
	write(t, root, "svc/Dockerfile", svc)
	write(t, root, "old/Dockerfile", "FROM alpine:3.14\nRUN apk add --no-cache openssh\n")
	write(t, root, "arg/Dockerfile", "ARG ALPINE=3.21\nFROM python:3.12-alpine${ALPINE}\nRUN apk add -U --virtual .ssh openssh-server~9.9\n")
	write(t, root, "wolfi/Dockerfile", "FROM cgr.dev/chainguard/wolfi-base\nRUN apk add openssh-server\n")
	write(t, root, "ok/Dockerfile", "FROM alpine:3.22\nRUN apk add 'openssh-server>=10.0_p1-r11' && apk add openssh-server=10.0_p1-r12\n")
	write(t, root, "edge/Containerfile", "FROM alpine:edge\nRUN apk add openssh-server-krb5\n")
	write(t, root, "unknown/Dockerfile", "FROM registry.example/base:1\nRUN apk add openssh-server\n")
	write(t, root, "ansible/users.yml", "- user:\n    name: deploy\n    password: '*'\n- shell: usermod name=x password=* other=1\n")
	write(t, root, "entrypoint.sh", "#!/bin/sh\necho \"app:*:20000:0:99999:7:::\" >> /etc/shadow\nexec sshd -D\n")
	write(t, root, "etc/sshd_config", "# PasswordAuthentication yes\nPasswordAuthentication yes\n")
	write(t, root, "node_modules/x/Dockerfile", "FROM alpine:3.22\nRUN apk add openssh\n")
	got := rules(scan(t, root, Options{}))
	want := []string{
		"apk-unpinned:svc/Dockerfile:3",
		"star-account:svc/Dockerfile:6",
		"star-account:svc/Dockerfile:7",
		"star-account:svc/Dockerfile:8",
		"password-config:svc/Dockerfile:9",
		"apk-pin:svc/Dockerfile:11",
		"eol-base:old/Dockerfile:2",
		"apk-unpinned:arg/Dockerfile:3",
		"apk-unpinned:edge/Containerfile:2",
		"not-checked:unknown/Dockerfile:2",
		"star-account:ansible/users.yml:3",
		"star-account:ansible/users.yml:4",
		"star-account:entrypoint.sh:2",
		"password-config:etc/sshd_config:2",
	}
	for _, w := range want {
		if got[w] != 1 {
			t.Errorf("missing %s", w)
		}
		delete(got, w)
	}
	for k := range got {
		t.Errorf("unexpected %s", k)
	}
}

func TestFixRoundTrip(t *testing.T) {
	root := t.TempDir()
	write(t, root, "svc/Dockerfile", strings.ReplaceAll(svc, "\n", "\r\n"))
	write(t, root, "entrypoint.sh", "#!/bin/sh\necho 'app:*:1:0:99999:7:::' > /etc/shadow\n")
	write(t, root, "ansible/users.yml", "- user:\n    password: \"*\"\n")
	write(t, root, "one/Dockerfile", "FROM alpine:3.23\nRUN apk add openssh && usermod -p '*' a && usermod -p \"*\" b\n")
	ctx := context.Background()
	for _, f := range scan(t, root, Options{}) {
		if f.Level == "note" {
			continue
		}
		ch, already, err := Plan(ctx, root, f, Options{})
		if already || err != nil {
			t.Fatalf("%s:%d %s: %v %v", f.File, f.Line, f.Rule, already, err)
		}
		if err := Apply(root, ch); err != nil {
			t.Fatal(err)
		}
	}
	left := 0
	for _, f := range scan(t, root, Options{}) {
		if f.Level != "note" {
			left++
			t.Errorf("left: %s:%d %s %s", f.File, f.Line, f.Rule, f.Message)
		}
	}
	b, _ := os.ReadFile(filepath.Join(root, "svc/Dockerfile"))
	s := string(b)
	for _, want := range []string{"'openssh-server>=10.0_p1-r11' \\\r\n", "usermod -p '*NP*' bob", "echo 'carol:*NP*' | chpasswd -e", "s/^dave:!/dave:*NP*/", "'openssh-server-pam=10.0_p1-r11'\r\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("Dockerfile lacks %q:\n%s", want, s)
		}
	}
	if left == 0 && strings.Count(s, "\r\n") != strings.Count(svc, "\n") {
		t.Error("line endings changed")
	}
}

func TestPlanDeclines(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine\nRUN apk add openssh-server\n")
	fs := scan(t, root, Options{})
	if len(fs) != 1 || fs[0].Fixable {
		t.Fatalf("alpine:latest offline should be reported but not fixable: %+v", fs)
	}
	if _, _, err := Plan(context.Background(), root, fs[0], Options{}); err == nil {
		t.Fatal("planned an edit with no branch")
	} else if _, ok := IsDeclined(err); !ok {
		t.Fatalf("not a decline: %v", err)
	}
	// With the base resolved, the same line is fixable.
	opts := Options{Base: func(context.Context, string) (bool, string, error) { return true, "3.24", nil }}
	fs = scan(t, root, opts)
	if len(fs) != 1 || !fs[0].Fixable || fs[0].Props["fixed"] != "10.3_p1-r2" {
		t.Fatalf("%+v", fs)
	}
	// A file changed after the scan is not edited.
	write(t, root, "Dockerfile", "FROM alpine\nRUN apk add openssh-server-pam\n")
	if _, _, err := Plan(context.Background(), root, fs[0], opts); err == nil {
		t.Fatal("edited a changed line")
	}
	// A word that only moved is found again.
	write(t, root, "Dockerfile", "FROM alpine\nRUN apk add  openssh-server\n")
	if ch, _, err := Plan(context.Background(), root, fs[0], opts); err != nil || !strings.Contains(ch.Edits[0].New, "apk add  'openssh-server>=10.3_p1-r2'") {
		t.Fatalf("moved word: %v %+v", err, ch)
	}
	// A failed resolution leaves it unchecked.
	bad := Options{Base: func(context.Context, string) (bool, string, error) { return false, "", errors.New("denied") }}
	write(t, root, "Dockerfile", "FROM registry.example/x\nRUN apk add openssh-server\n")
	if fs := scan(t, root, bad); len(fs) != 1 || fs[0].Rule != RuleNotChecked || !strings.Contains(fs[0].Message, "denied") {
		t.Fatalf("%+v", fs)
	}
}

func TestAlpineOf(t *testing.T) {
	mk := func(files map[string]string) func() (io.ReadCloser, error) {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for n, c := range files {
			tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
			tw.Write([]byte(c))
		}
		tw.Close()
		return func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b.Bytes())), nil }
	}
	if a, br, err := AlpineOf(mk(map[string]string{"etc/alpine-release": "3.24.3\n"})); err != nil || !a || br != "3.24" {
		t.Errorf("alpine: %v %q %v", a, br, err)
	}
	if a, _, _ := AlpineOf(mk(map[string]string{"lib/ld-musl-x86_64.so.1": ""})); !a {
		t.Error("musl without release file")
	}
	if a, _, _ := AlpineOf(mk(map[string]string{"etc/debian_version": "12"})); a {
		t.Error("debian taken for alpine")
	}
}

func TestSplitShell(t *testing.T) {
	cmds := splitShell(`FOO=1 sudo apk add "openssh-server" && echo 'a:*' | chpasswd -e; printf '%s\n' x >> /etc/shadow`)
	if len(cmds) != 4 {
		t.Fatalf("%d commands", len(cmds))
	}
	if p, _ := cmds[0].program(); p != "apk" {
		t.Errorf("program %q", p)
	}
	if !cmds[2].piped || cmds[1].piped {
		t.Error("pipe")
	}
	if len(cmds[3].redirs) != 1 || cmds[3].redirs[0].target.val != "/etc/shadow" {
		t.Errorf("redirs %+v", cmds[3].redirs)
	}
}

func FuzzScanText(f *testing.F) {
	f.Add(svc)
	f.Add("RUN apk add 'x\nFROM\n\\")
	f.Fuzz(func(t *testing.T, s string) {
		sc := &scanner{ctx: context.Background(), bases: map[string]baseInfo{}}
		for _, x := range sc.dockerfile("Dockerfile", s) {
			if x.edit != nil && x.edit.Line < 1 {
				t.Fatal("edit before line 1")
			}
		}
		sc.script("a.sh", s)
		sc.yaml("a.yml", s)
		splitShell(s)
	})
}
