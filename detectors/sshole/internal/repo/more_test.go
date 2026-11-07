package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/refs"
)

// fixAll plans and applies every fixable finding, rescanning after each,
// and returns what is left.
func fixAll(t *testing.T, root string) []Finding {
	t.Helper()
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		changed := false
		for _, f := range scan(t, root, Options{}) {
			if !f.Fixable {
				continue
			}
			ch, already, err := Plan(ctx, root, f, Options{})
			if already {
				continue
			}
			if err != nil {
				t.Fatalf("%s:%d %s: %v", f.File, f.Line, f.Rule, err)
			}
			if err := Apply(root, ch); err != nil {
				t.Fatal(err)
			}
			changed = true
			break // rescan: line numbers may have moved
		}
		if !changed {
			break
		}
	}
	var left []Finding
	for _, f := range scan(t, root, Options{}) {
		if f.Level != "note" {
			left = append(left, f)
		}
	}
	return left
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestVariables(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.22\nARG PKGS=\"bash openssh-server curl\"\nENV EXTRA openssh-server-pam\nRUN apk add --no-cache $PKGS ${EXTRA} $UNSET\n")
	got := rules(scan(t, root, Options{}))
	for _, w := range []string{"apk-unpinned:Dockerfile:4", "not-checked:Dockerfile:4"} {
		if got[w] == 0 {
			t.Errorf("missing %s in %v", w, got)
		}
	}
	if got["apk-unpinned:Dockerfile:4"] != 2 {
		t.Errorf("want both variables judged: %v", got)
	}
	if left := fixAll(t, root); len(left) != 0 {
		t.Fatalf("left %+v", left)
	}
	s := read(t, root, "Dockerfile")
	if !strings.Contains(s, `ARG PKGS="bash openssh-server>=10.0_p1-r11 curl"`) || !strings.Contains(s, "ENV EXTRA openssh-server-pam>=10.0_p1-r11") {
		t.Fatalf("%s", s)
	}
}

func TestEOLUpgrade(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.14\nRUN apk add --no-cache openssh\n")
	write(t, root, "py/Dockerfile", "FROM python:3.9-alpine3.14\nRUN apk add openssh\n")
	fs := scan(t, root, Options{})
	var fixable, manual int
	for _, f := range fs {
		if f.Rule == RuleEOL && f.Fixable {
			fixable++
		} else if f.Rule == RuleEOL {
			manual++
		}
	}
	if fixable != 1 || manual != 1 {
		t.Fatalf("%+v", fs)
	}
	left := fixAll(t, root)
	if len(left) != 1 || left[0].File != "py/Dockerfile" {
		t.Fatalf("left %+v", left)
	}
	if s := read(t, root, "Dockerfile"); s != "FROM alpine:3.16\nRUN apk add --no-cache 'openssh>=9.0_p1-r6'\n" {
		t.Fatalf("%q", s)
	}
}

func TestAnsible(t *testing.T) {
	root := t.TempDir()
	write(t, root, "roles/ssh/tasks/main.yml", `- name: install sshd
  community.general.apk:
    name:
      - openssh-server
      - bash
    state: present
- name: inline
  apk: name=openssh state=present update_cache=yes
- name: no state
  apk:
    name: openssh-server
- name: already latest
  apk:
    name: openssh-server
    state: latest
- name: other package
  apk: name=bash
`)
	got := rules(scan(t, root, Options{}))
	for _, w := range []string{"ansible-apk:roles/ssh/tasks/main.yml:2", "ansible-apk:roles/ssh/tasks/main.yml:8", "ansible-apk:roles/ssh/tasks/main.yml:10"} {
		if got[w] != 1 {
			t.Errorf("missing %s: %v", w, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("extra findings: %v", got)
	}
	if left := fixAll(t, root); len(left) != 0 {
		t.Fatalf("left %+v", left)
	}
	s := read(t, root, "roles/ssh/tasks/main.yml")
	for _, want := range []string{"    state: latest\n- name: inline", "apk: name=openssh state=latest update_cache=yes", "    name: openssh-server\n    state: latest\n- name: already"} {
		if !strings.Contains(s, want) {
			t.Errorf("lacks %q:\n%s", want, s)
		}
	}
}

func TestBuildSystems(t *testing.T) {
	root := t.TempDir()
	write(t, root, "configs/board_defconfig", "BR2_aarch64=y\nBR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "glibc/board_defconfig", "BR2_TOOLCHAIN_BUILDROOT_GLIBC=y\nBR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "client/board_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n# BR2_PACKAGE_OPENSSH_SERVER is not set\n")
	write(t, root, "unknown/board_defconfig", "BR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "openwrt/.config", "CONFIG_TARGET_x86=y\nCONFIG_PACKAGE_openssh-server=y\nCONFIG_PACKAGE_dropbear=n\n")
	write(t, root, "meta-x/conf/distro/x.conf", "DISTRO = \"x\"\nTCLIBC = \"musl\"\n")
	write(t, root, "meta-x/recipes-core/images/x-image.bb", "IMAGE_INSTALL:append = \" openssh bash\"\n")
	got := rules(scan(t, root, Options{}))
	for _, w := range []string{"build-config:configs/board_defconfig:3", "not-checked:unknown/board_defconfig:1", "build-config:openwrt/.config:2", "build-config:meta-x/recipes-core/images/x-image.bb:1"} {
		if got[w] != 1 {
			t.Errorf("missing %s: %v", w, got)
		}
	}
	if len(got) != 4 {
		t.Errorf("extra findings: %v", got)
	}
	// Without a musl TCLIBC, a Yocto image with OpenSSH is glibc: nothing.
	os.Remove(filepath.Join(root, "meta-x/conf/distro/x.conf"))
	if got := rules(scan(t, root, Options{})); got["build-config:meta-x/recipes-core/images/x-image.bb:1"] != 0 {
		t.Errorf("glibc Yocto reported: %v", got)
	}
}

func TestBuildrootPatchFix(t *testing.T) {
	root := t.TempDir()
	write(t, root, "br2-acme/external.desc", "name: ACME\ndesc: acme boards\n")
	write(t, root, "br2-acme/configs/acme_defconfig", "BR2_aarch64=y\nBR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "br2-beta/external.desc", "name: BETA\n")
	write(t, root, "br2-beta/configs/beta_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_GLOBAL_PATCH_DIR=\"$(BR2_EXTERNAL_BETA_PATH)/board/patches\"\nBR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "plain_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	left := fixAll(t, root)
	if len(left) != 1 || left[0].File != "plain_defconfig" || left[0].Fixable {
		t.Fatalf("left %+v", left)
	}
	if s := read(t, root, "br2-acme/configs/acme_defconfig"); !strings.HasSuffix(s, "BR2_PACKAGE_OPENSSH=y\nBR2_GLOBAL_PATCH_DIR=\"$(BR2_EXTERNAL_ACME_PATH)/patches\"\n") {
		t.Fatalf("%q", s)
	}
	for _, p := range []string{"br2-acme/patches/openssh/9.9p2/" + PatchName, "br2-acme/patches/openssh/10.6p1/" + PatchName, "br2-beta/board/patches/openssh/10.2p1/" + PatchName} {
		if !strings.Contains(read(t, root, p), "MIN_PASSWORD_HASH_LEN") {
			t.Errorf("%s lacks the patch", p)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "br2-acme/patches/openssh/10.6p2")); err == nil {
		t.Error("patched a fixed version")
	}
}

func TestYoctoPatchFix(t *testing.T) {
	root := t.TempDir()
	write(t, root, "meta-acme/conf/layer.conf", "BBFILE_COLLECTIONS += \"acme\"\nLAYERSERIES_COMPAT_acme = \"scarthgap\"\n")
	write(t, root, "meta-acme/conf/distro/acme.conf", "TCLIBC = \"musl\"\n")
	write(t, root, "meta-acme/recipes-core/images/acme-image.bb", "IMAGE_INSTALL:append = \" openssh\"\n")
	write(t, root, "meta-two/conf/layer.conf", "LAYERSERIES_COMPAT_two = \"scarthgap walnascar\"\n")
	write(t, root, "meta-two/recipes-core/images/two-image.bb", "IMAGE_FEATURES += \"ssh-server-openssh\"\n")
	fs := scan(t, root, Options{})
	var acme, two *Finding
	for i := range fs {
		switch fs[i].File {
		case "meta-acme/recipes-core/images/acme-image.bb":
			acme = &fs[i]
		case "meta-two/recipes-core/images/two-image.bb":
			two = &fs[i]
		}
	}
	if acme == nil || !acme.Fixable || two == nil || two.Fixable || !strings.Contains(two.Fix, "different openssh versions") {
		t.Fatalf("%+v\n%+v", acme, two)
	}
	ch, _, err := Plan(context.Background(), root, *acme, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(root, ch); err != nil {
		t.Fatal(err)
	}
	bb := read(t, root, "meta-acme/recipes-connectivity/openssh/openssh_9.6p1.bbappend")
	if !strings.Contains(bb, "SRC_URI += \"file://"+PatchName+"\"") || !strings.Contains(read(t, root, "meta-acme/recipes-connectivity/openssh/files/"+PatchName), "MIN_PASSWORD_HASH_LEN") {
		t.Fatalf("%s", bb)
	}
	// With the patch in a bbappend, the tree is no longer reported.
	for _, f := range scan(t, root, Options{}) {
		if f.Rule == RuleBuild && f.File == acme.File {
			t.Errorf("still reported: %+v", f)
		}
	}
}

func TestOverrideFor(t *testing.T) {
	root := t.TempDir()
	write(t, root, "compose.yaml", "services:\n  a:\n    image: x/a:1\n    command: /usr/sbin/sshd -D -o 'PasswordAuthentication yes'\n  b:\n    image: x/b:1\n    entrypoint: [\"/start.sh\"]\n  c:\n    image: x/c:1\n")
	write(t, root, "k8s.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: s\n      image: x/d:1\n      args: [\"-D\", \"-e\"]\n---\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: t\n      image: x/e:1\n      command: [\"/usr/sbin/sshd\"]\n")
	rs, _, err := refs.Scan(root, refs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rs {
		o := OverrideFor(root, r, nil)
		got[r.Image] = strings.Join(o.Apply([]string{"/init"}, []string{"sshd"}), " ")
	}
	want := map[string]string{
		"x/a:1": "/init /usr/sbin/sshd -D -o PasswordAuthentication yes",
		"x/b:1": "/start.sh",
		"x/c:1": "/init sshd",
		"x/d:1": "/init -D -e",
		"x/e:1": "/usr/sbin/sshd",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
}

func TestAlpineRetag(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM python:3.9-alpine3.14\nRUN apk add openssh\n")
	opts := Options{
		Tags: func(context.Context, string) ([]string, error) {
			return []string{"3.9-alpine3.13", "3.9-alpine3.14", "3.9-alpine3.15", "3.9-alpine3.16", "3.9-alpine3.17", "3.10-alpine3.16", "3.9-slim"}, nil
		},
		Base: func(_ context.Context, img string) (bool, string, error) {
			b := img[strings.LastIndex(img, "alpine")+len("alpine"):]
			return true, b, nil
		},
	}
	fs := scan(t, root, opts)
	if len(fs) != 1 || !fs[0].Fixable || fs[0].Props["upgrade"] != "python:3.9-alpine3.16" {
		t.Fatalf("%+v", fs)
	}
	ch, _, err := Plan(context.Background(), root, fs[0], opts)
	if err != nil || ch.Edits[0].New != "FROM python:3.9-alpine3.16" {
		t.Fatalf("%v %+v", err, ch)
	}
	// A candidate whose image is not the release its tag says is skipped.
	opts.Base = func(_ context.Context, img string) (bool, string, error) { return true, "3.14", nil }
	if fs := scan(t, root, opts); fs[0].Fixable {
		t.Fatalf("trusted a tag: %+v", fs)
	}
}

type tempErr struct{}

func (tempErr) Error() string   { return "timeout" }
func (tempErr) Temporary() bool { return true }

func TestBaseLookupsOnlyWhenNeeded(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/Dockerfile", "FROM node:22\nRUN npm ci\nFROM golang:1.27 AS build\nRUN go build\n")
	write(t, root, "b/Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2\n")
	var asked []string
	opts := Options{Base: func(_ context.Context, img string) (bool, string, error) {
		asked = append(asked, img)
		return true, "3.21", nil
	}}
	fs := scan(t, root, opts)
	if strings.Join(asked, ",") != "acme/base:1" {
		t.Fatalf("looked up %v", asked)
	}
	if len(fs) != 1 || fs[0].Rule != RulePin {
		t.Fatalf("%+v", fs)
	}
	// A temporary failure is reported to the caller, and the finding's
	// message does not carry the error.
	opts.Base = func(context.Context, string) (bool, string, error) { return false, "", tempErr{} }
	res, err := Scan(context.Background(), root, opts)
	if err != nil || len(res.Transient) != 1 || strings.Contains(res.Findings[0].Message, "timeout") {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestWriteNewFilesSafety(t *testing.T) {
	root := t.TempDir()
	files := map[string][]byte{"ext/patches/openssh/9.9p2/x.patch": []byte("p"), "ext/patches/openssh/10.0p1/x.patch": []byte("p")}
	// Parallel writers of the same files all succeed.
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { errs <- WriteNewFiles(root, files) }()
	}
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	// Other content, .git, and a symlinked directory are refused before
	// anything is written.
	if err := WriteNewFiles(root, map[string][]byte{"ext/patches/openssh/9.9p2/x.patch": []byte("q")}); err == nil {
		t.Error("replaced a file")
	}
	if err := WriteNewFiles(root, map[string][]byte{"a/new.txt": []byte("x"), ".git/hooks/x": []byte("x")}); err == nil {
		t.Error("wrote into .git")
	}
	if _, err := os.Stat(filepath.Join(root, "a")); err == nil {
		t.Error("partial write before a refusal")
	}
	os.Symlink(t.TempDir(), filepath.Join(root, "link"))
	if err := WriteNewFiles(root, map[string][]byte{"link/x": []byte("x")}); err == nil {
		t.Error("wrote through a symlink")
	}
}

func TestBuildrootGitPatchDir(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Config.in", "")
	write(t, root, "configs/a_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_GLOBAL_PATCH_DIR=\".git/hooks\"\nBR2_PACKAGE_OPENSSH=y\n")
	fs := scan(t, root, Options{})
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	if _, _, err := Plan(context.Background(), root, fs[0], Options{}); err == nil || !strings.Contains(err.Error(), ".git") {
		t.Fatalf("%v", err)
	}
}

func TestFindMovedLine(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN usermod -p '*' bob\n")
	fs := scan(t, root, Options{})
	write(t, root, "Dockerfile", "FROM alpine:3.22\n# a comment added above\nRUN usermod -p '*' bob\n")
	f, gone, err := Find(context.Background(), root, "Dockerfile", fs[0].Line, RuleStar, fs[0].Message, Options{})
	if err != nil || gone || f == nil || f.Line != 3 {
		t.Fatalf("%v %v %+v", err, gone, f)
	}
}

func TestYoctoPRMode(t *testing.T) {
	root := t.TempDir()
	write(t, root, "meta-a/conf/layer.conf", "LAYERSERIES_COMPAT_a = \"scarthgap\"\n")
	write(t, root, "meta-a/conf/distro/a.conf", "TCLIBC = \"musl\"\n")
	write(t, root, "meta-a/recipes-core/images/a.bb", "IMAGE_INSTALL:append = \" openssh\"\n")
	res, err := Scan(context.Background(), root, Options{Files: []string{"meta-a/recipes-core/images/a.bb"}})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Rule != RuleBuild {
		t.Fatalf("%v %+v", err, res)
	}
}
