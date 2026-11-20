package repo

import (
	"context"
	"testing"
)

// Cases from the third review of the not-checked change.

// Nit 4: a spec that quotes "(through $Y" is not a variable install.
func TestReview3CraftedVia(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add 'openssh-server=1 (through $Y'\n")
	pin := findOne(t, root, Options{}, RulePin)
	if k := keyOf(pin.Message); k.via != "" {
		t.Errorf("via %q from %q", k.via, pin.Message)
	}
	// A real one, with the prefix note after it, still reads.
	write(t, root, "Dockerfile", "FROM ${R}alpine:3.21\nARG PKGS=\"openssh-server=9.9_p1-r2\"\nRUN apk add $PKGS\n")
	pin = findOne(t, root, Options{}, RulePin)
	if k := keyOf(pin.Message); k.via != "PKGS" {
		t.Errorf("via %q from %q", k.via, pin.Message)
	}
}

// Nit 5: a spec with a space, the line shifted and the lookup down.
func TestReview3SpecWithSpace(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/app:alpine\nRUN apk add 'openssh-server>=9.0 x'\n")
	eol := findOne(t, root, alpineAt("3.14"), RuleEOL)
	write(t, root, "Dockerfile", "# a comment\nFROM acme/app:alpine\nRUN apk add 'openssh-server>=9.0 x'\n")
	f, gone, err := Find(context.Background(), root, "Dockerfile", eol.Line, RuleEOL, eol.Message, baseDown)
	mustDecline(t, "spaced spec", f, gone, err)
}

// Nit 7: a build finding that moved, found with no message or a reworded one.
func TestReview3BuildMoved(t *testing.T) {
	root := t.TempDir()
	write(t, root, "configs/a_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	b := findOne(t, root, Options{}, RuleBuild)
	write(t, root, "configs/a_defconfig", "# moved\nBR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	for _, msg := range []string{"", "Buildroot configuration builds the OpenSSH server against musl; worded as it was before"} {
		f, gone, err := Find(context.Background(), root, b.File, b.Line, RuleBuild, msg, Options{})
		mustDecline(t, "moved, message "+msg, f, gone, err)
	}
}

// Nit 7: an image whose name is a variable says nothing about glibc; its
// tag can still say Alpine, as on main.
func TestReview3VariableRepository(t *testing.T) {
	for _, c := range []struct{ from, rule string }{
		{"FROM ${debian_base}", RuleNotChecked},
		{"FROM ${IMG}:alpine", RuleUnpinned},
	} {
		root := t.TempDir()
		write(t, root, "Dockerfile", c.from+"\nRUN apk add openssh-server\n")
		findOne(t, root, Options{}, c.rule)
	}
}

// Nit 7: a legacy ENV value expands the variables already set.
func TestReview3LegacyEnv(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21 AS a\nENV TAG 3.14\nENV BASE alpine:${TAG}\nFROM ${BASE}\nRUN apk add openssh-server\n")
	findOne(t, root, Options{}, RuleEOL)
}
