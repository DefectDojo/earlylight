package repo

import (
	"context"
	"strings"
	"testing"
)

// Cases from the second review of the not-checked change.

// checkKey asserts that what Find reads from a message is the finding's
// own package, variable and build system; an empty key is allowed (Find
// then fails closed), a wrong one is not.
func checkKey(t *testing.T, f Finding) {
	t.Helper()
	k := keyOf(f.Message)
	if k.pkg != "" && k.pkg != f.Props["package"] || k.via != "" && k.via != f.Props["variable"] || k.system != "" && k.system != f.Props["system"] {
		t.Fatalf("key %+v from %q, props %v", k, f.Message, f.Props)
	}
}

// Every message the scanner writes gives back its own key, exactly.
func TestKeyRoundTrip(t *testing.T) {
	root := t.TempDir()
	write(t, root, "a/Dockerfile", "FROM alpine:3.21\nARG PKGS=\"openssh-server=9.9_p1-r2\"\nRUN apk add $PKGS openssh@edge 'openssh-server-pam~9.9'\n")
	write(t, root, "b/Dockerfile", "FROM alpine:3.14\nRUN apk add openssh-server\n")
	write(t, root, "c/Dockerfile", "FROM ${REGISTRY}alpine:3.21\nRUN apk add openssh-server=9.9_p1-r2\n")
	write(t, root, "d/Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server\n")
	write(t, root, "configs/a_defconfig", "BR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "configs/b_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	write(t, root, "openwrt/.config", "CONFIG_TARGET_x86=y\nCONFIG_PACKAGE_openssh-server=y\n")
	write(t, root, "meta-a/conf/layer.conf", "LAYERSERIES_COMPAT_a = \"scarthgap\"\n")
	write(t, root, "meta-a/conf/distro/a.conf", "TCLIBC = \"musl\"\n")
	write(t, root, "meta-a/recipes-core/images/a.bb", "IMAGE_INSTALL:append = \" openssh\"\n")
	seen := map[string]bool{}
	for _, f := range scan(t, root, Options{}) {
		if f.Rule == RuleStar || f.Rule == RulePassword || f.Rule == RuleAnsible {
			continue
		}
		k := keyOf(f.Message)
		if k.pkg != f.Props["package"] || k.via != f.Props["variable"] || k.system != f.Props["system"] {
			if !(f.Rule == RuleNotChecked && f.Props["package"] == "" && f.Props["system"] == "") { // a variable install names no package
				t.Errorf("%s %s:%d key %+v from %q, props %v", f.Rule, f.File, f.Line, k, f.Message, f.Props)
			}
		}
		seen[f.Rule+"/"+f.Props["system"]] = true
	}
	for _, want := range []string{RulePin + "/", RuleUnpinned + "/", RuleEOL + "/", RuleNotChecked + "/", RuleNotChecked + "/buildroot", RuleBuild + "/buildroot", RuleBuild + "/openwrt", RuleBuild + "/yocto"} {
		if !seen[want] {
			t.Errorf("no %s finding in the round trip", want)
		}
	}
}

// 1: a message Find cannot read a key from fails closed.
func TestReview2KeyFailsClosed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2\n")
	pin := findOne(t, root, alpine321, RulePin)
	m := pin.Message
	for _, msg := range []string{"", "Dockerfile:2: " + m, "apk-pin: " + m, strings.ToUpper(m[:1]) + m[1:], "**" + m + "**",
		strings.Replace(m, "openssh-server=9.9_p1-r2", "`openssh-server=9.9_p1-r2`", 1)} {
		f, gone, err := Find(ctx, root, "Dockerfile", pin.Line, RulePin, msg, baseDown)
		mustDecline(t, "pin, message "+msg, f, gone, err)
	}
	// End-of-life swapped to unpinned, no message.
	root = t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/app:alpine\nRUN apk add openssh-server\n")
	eol := findOne(t, root, alpineAt("3.14"), RuleEOL)
	f, gone, err := Find(ctx, root, "Dockerfile", eol.Line, RuleEOL, "", baseDown)
	mustDecline(t, "end-of-life, no message", f, gone, err)
	// Buildroot with the C library commented out, no message.
	root = t.TempDir()
	write(t, root, "configs/a_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	b := findOne(t, root, Options{}, RuleBuild)
	write(t, root, "configs/a_defconfig", "# BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	f, gone, err = Find(ctx, root, b.File, b.Line, RuleBuild, "", Options{})
	mustDecline(t, "buildroot, no message", f, gone, err)
}

// 2: a variable in the image keeps what the name says; ARG values expand.
func TestReview2NameWithVariable(t *testing.T) {
	for _, c := range []struct {
		from, apk, rule string
		fixable         bool
	}{
		{"ARG V\nFROM alpine:${V}", "openssh-server", RuleUnpinned, false},
		{"FROM alpine:${ALPINE_VERSION}", "openssh-server=9.9_p1-r2", RulePin, false},
		{"FROM python:${PY}-alpine", "openssh-server", RuleUnpinned, false},
		{"FROM python:${PY}-alpine3.21", "openssh-server", RuleUnpinned, true},
		{"FROM node:${NODE}-alpine3.14", "openssh-server", RuleEOL, false},
		{"ARG TAG=3.21\nARG BASE=alpine:${TAG}\nFROM ${BASE}", "openssh-server", RuleUnpinned, true},
		{"FROM python:${PY}-alpine3.1${X}", "openssh-server", RuleUnpinned, false},
	} {
		root := t.TempDir()
		write(t, root, "Dockerfile", c.from+"\nRUN apk add "+c.apk+"\n")
		f := findOne(t, root, Options{}, c.rule)
		if f.Fixable != c.fixable {
			t.Errorf("%q: fixable %v: %+v", c.from, f.Fixable, f)
		}
		if strings.Contains(f.Message, "is not known") {
			t.Errorf("%q: %q", c.from, f.Message)
		}
	}
	// The registry is never asked about an image it cannot name.
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:${V}\nRUN apk add openssh-server\n")
	o := Options{Base: func(_ context.Context, img string) (bool, string, error) {
		t.Errorf("looked up %q", img)
		return true, "3.21", nil
	}}
	findOne(t, root, o, RuleUnpinned)
}

// 3: a tag cut short by an unset variable is not a release.
func TestReview2TagCutShort(t *testing.T) {
	for _, tag := range []string{"3.${MINOR}", "3_${X}", "3-${X}"} {
		if validImage("alpine:" + strings.Split(tag, "$")[0]) {
			t.Errorf("%s: valid", tag)
		}
		root := t.TempDir()
		write(t, root, "Dockerfile", "FROM alpine:"+tag+"\nRUN apk add openssh-server\n")
		if f := findOne(t, root, Options{}, RuleUnpinned); f.Fixable {
			t.Errorf("%s: %+v", tag, f)
		}
	}
}

// Nit 4: end-of-life, lookup down and the line shifted.
func TestReview2EOLShifted(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/app:alpine\nRUN apk add openssh-server\n")
	eol := findOne(t, root, alpineAt("3.14"), RuleEOL)
	write(t, root, "Dockerfile", "# a comment\nFROM acme/app:alpine\nRUN apk add openssh-server\n")
	f, gone, err := Find(context.Background(), root, "Dockerfile", eol.Line, RuleEOL, eol.Message, baseDown)
	mustDecline(t, "shifted, lookup down", f, gone, err)
}

// Nit 7: two pins on one line, the first fixed.
func TestReview2OtherPackageOnLine(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add openssh-server=9.9_p1-r2 openssh=9.9_p1-r2\n")
	var first Finding
	for _, f := range scan(t, root, Options{}) {
		if f.Props["package"] == "openssh-server" {
			first = f
		}
	}
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add 'openssh-server=9.9_p2-r1' openssh=9.9_p1-r2\n")
	f, gone, err := Find(ctx, root, "Dockerfile", first.Line, RulePin, first.Message, Options{})
	mustBeGone(t, "first pin fixed", f, gone, err)
}

// Nit 8: the note names the image and every variable before it.
func TestReview2PrefixNote(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM ${A}/${B}/alpine:3.21 AS b\nFROM b\nRUN apk add openssh-server\n")
	f := findOne(t, root, Options{}, RuleUnpinned)
	if !strings.Contains(f.Message, "${A}/${B}") || !strings.Contains(f.Message, "judged as alpine:3.21") {
		t.Errorf("%q", f.Message)
	}
}
