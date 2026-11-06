package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
