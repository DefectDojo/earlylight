package repo

import (
	"context"
	"testing"
)

// Cases from the final review of the not-checked change.

// A message stored with a trailing full stop or newline still names its
// variable, so a removed ARG is not checked, not gone.
func TestReview4ViaTrailing(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nARG PKGS=\"openssh-server=9.9_p1-r2\"\nRUN apk add $PKGS\n")
	pin := findOne(t, root, Options{}, RulePin)
	write(t, root, "Dockerfile", "FROM alpine:3.21\n\nRUN apk add $PKGS\n")
	for _, tail := range []string{".", "\n", " ", ".\n", " .\r\n"} {
		if k := keyOf(pin.Message + tail); k.via != "PKGS" {
			t.Errorf("%q: via %q", tail, k.via)
		}
		f, gone, err := Find(ctx, root, "Dockerfile", pin.Line, RulePin, pin.Message+tail, Options{})
		mustDecline(t, "ARG removed, tail "+tail, f, gone, err)
	}
}

// With no message, Find follows no finding to another line: apk and build
// findings decline (their key is unknown), the others read as gone.
func TestReview4MovedNoMessage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add openssh-server=9.9_p1-r2 && usermod -p '*' bob\n")
	fs := scan(t, root, Options{})
	write(t, root, "Dockerfile", "# moved\nFROM alpine:3.21\nRUN apk add openssh-server=9.9_p1-r2 && usermod -p '*' bob\n")
	for _, g := range fs {
		f, gone, err := Find(ctx, root, "Dockerfile", g.Line, g.Rule, "", Options{})
		switch g.Rule {
		case RulePin:
			mustDecline(t, "pin moved, no message", f, gone, err)
		case RuleStar:
			mustBeGone(t, "star moved, no message", f, gone, err)
		default:
			t.Fatalf("unexpected %+v", g)
		}
	}
}
