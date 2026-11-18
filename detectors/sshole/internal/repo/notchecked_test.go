package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A finding that was not checked, or that cannot be checked again now, is
// never "gone": Find declines with "rescan to confirm" instead, so a fix
// does not report it as already fixed.

var (
	alpine321 = Options{Base: func(context.Context, string) (bool, string, error) { return true, "3.21", nil }}
	baseDown  = Options{Base: func(context.Context, string) (bool, string, error) { return false, "", errors.New("denied") }}
)

// mustDecline fails unless Find declined, naming what was not checked.
func mustDecline(t *testing.T, what string, f *Finding, gone bool, err error) {
	t.Helper()
	d, ok := IsDeclined(err)
	if gone || f != nil || !ok {
		t.Fatalf("%s: want a decline, got finding %+v, gone %v, err %v", what, f, gone, err)
	}
	if !strings.Contains(d.Reason, "rescan to confirm") {
		t.Errorf("%s: reason %q does not say rescan to confirm", what, d.Reason)
	}
}

func findOne(t *testing.T, root string, opts Options, rule string) Finding {
	t.Helper()
	fs := scan(t, root, opts)
	if len(fs) != 1 || fs[0].Rule != rule {
		t.Fatalf("want one %s finding, got %+v", rule, fs)
	}
	return fs[0]
}

func TestFindSkippedFile(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	big := "FROM alpine:3.22\nRUN apk add openssh-server\n" + strings.Repeat("#\n", maxFileSize/2)
	write(t, root, "Dockerfile", big)
	res, err := Scan(ctx, root, Options{})
	if err != nil || len(res.Skips) != 1 || len(res.Findings) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	// A skip reaches a report as a not-checked finding on its file. The
	// file is still too large, then gone, then readable with nothing in
	// it: none of these checked what the skip left out.
	sk := res.Skips[0]
	f, gone, err := Find(ctx, root, sk.File, 0, RuleNotChecked, sk.Reason, Options{})
	mustDecline(t, "still oversized", f, gone, err)
	os.Remove(filepath.Join(root, "Dockerfile"))
	f, gone, err = Find(ctx, root, sk.File, 0, RuleNotChecked, sk.Reason, Options{})
	mustDecline(t, "removed", f, gone, err)
	write(t, root, "Dockerfile", "FROM alpine:3.22\n")
	f, gone, err = Find(ctx, root, sk.File, 0, RuleNotChecked, sk.Reason, Options{})
	mustDecline(t, "readable now", f, gone, err)
}

func TestFindFileUnreadableNow(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN usermod -p '*' bob\n")
	star := findOne(t, root, Options{}, RuleStar)
	// Oversized this time.
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN usermod -p '*' bob\n"+strings.Repeat("#\n", maxFileSize/2))
	f, gone, err := Find(ctx, root, "Dockerfile", star.Line, RuleStar, star.Message, Options{})
	mustDecline(t, "oversized", f, gone, err)
	// Not a regular file this time.
	os.Remove(filepath.Join(root, "Dockerfile"))
	write(t, root, "real", "FROM alpine:3.22\n")
	if err := os.Symlink("real", filepath.Join(root, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	f, gone, err = Find(ctx, root, "Dockerfile", star.Line, RuleStar, star.Message, Options{})
	mustDecline(t, "symlink", f, gone, err)
}

func TestFindUnresolvedImage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2\n")
	pin := findOne(t, root, alpine321, RulePin)
	// The base image cannot be read this time.
	f, gone, err := Find(ctx, root, "Dockerfile", pin.Line, RulePin, pin.Message, baseDown)
	mustDecline(t, "lookup failed", f, gone, err)
	// The image is now an unresolved build argument.
	write(t, root, "Dockerfile", "FROM ${BASE}\nRUN apk add openssh-server=9.9_p1-r2\n")
	f, gone, err = Find(ctx, root, "Dockerfile", pin.Line, RulePin, pin.Message, alpine321)
	mustDecline(t, "${BASE}", f, gone, err)
}

func TestFindNotCheckedNowVulnerable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2\n")
	nc := findOne(t, root, baseDown, RuleNotChecked)
	// Still not checked: the same finding, not gone.
	f, gone, err := Find(ctx, root, "Dockerfile", nc.Line, RuleNotChecked, nc.Message, baseDown)
	if err != nil || gone || f == nil || f.Rule != RuleNotChecked {
		t.Fatalf("still not checked: %+v %v %v", f, gone, err)
	}
	// The base resolves now, to Alpine with a vulnerable pin.
	f, gone, err = Find(ctx, root, "Dockerfile", nc.Line, RuleNotChecked, nc.Message, alpine321)
	mustDecline(t, "resolves to a pin", f, gone, err)
	if d, _ := IsDeclined(err); !strings.Contains(d.Reason, RulePin) {
		t.Errorf("decline does not name the finding there now: %q", d.Reason)
	}
}

func TestFindStaleLine(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN true\nRUN true\nRUN usermod -p '*' bob\n")
	star := findOne(t, root, Options{}, RuleStar)
	// The file was cut short: line 4 is past its end.
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN usermod -p '*' alice\n")
	for _, msg := range []string{"", "a message that matches nothing"} {
		f, gone, err := Find(ctx, root, "Dockerfile", star.Line, RuleStar, msg, Options{})
		mustDecline(t, "past the end, message "+msg, f, gone, err)
	}
	// Plan, between the scan and the fix, does not take it as fixed.
	if ch, err := Plan(ctx, root, star, Options{}); ch != nil || err == nil {
		t.Fatalf("plan of a stale line: %+v %v", ch, err)
	} else if d, ok := IsDeclined(err); !ok || !strings.Contains(d.Reason, "rescan to confirm") {
		t.Errorf("plan of a stale line: %v", err)
	}
}

func TestFindYoctoTreeUnreadable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "meta-a/conf/layer.conf", "LAYERSERIES_COMPAT_a = \"scarthgap\"\n")
	write(t, root, "meta-a/conf/distro/a.conf", "TCLIBC = \"musl\"\n")
	write(t, root, "meta-a/recipes-core/images/a.bb", "IMAGE_INSTALL:append = \" openssh\"\n")
	b := findOne(t, root, Options{}, RuleBuild)
	// The distro configuration that sets musl cannot be read this time.
	write(t, root, "meta-a/conf/distro/a.conf", "TCLIBC = \"musl\"\n"+strings.Repeat("#\n", maxFileSize/2))
	f, gone, err := Find(ctx, root, b.File, b.Line, RuleBuild, b.Message, Options{})
	mustDecline(t, "distro conf oversized", f, gone, err)
}

// What was checked and is really gone still reads as gone.
func TestFindCheckedAndGone(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2 && usermod -p '*' bob\n")
	fs := scan(t, root, alpine321)
	if len(fs) != 2 || fs[0].Rule == fs[1].Rule {
		t.Fatalf("%+v", fs)
	}
	star := fs[0]
	if star.Rule != RuleStar {
		star = fs[1]
	}
	write(t, root, "Dockerfile", "FROM acme/base:1\nRUN apk add 'openssh-server>=9.9_p2-r1' && usermod -p '*NP*' bob\n")
	for _, g := range fs {
		f, gone, err := Find(ctx, root, g.File, g.Line, g.Rule, g.Message, alpine321)
		if err != nil || !gone || f != nil {
			t.Errorf("%s: %+v %v %v", g.Rule, f, gone, err)
		}
	}
	// The star field is checked without the base image: a failed lookup
	// does not hold it back.
	f, gone, err := Find(ctx, root, "Dockerfile", star.Line, RuleStar, star.Message, baseDown)
	if err != nil || !gone || f != nil {
		t.Errorf("star with the lookup down: %+v %v %v", f, gone, err)
	}
	// A deleted file has no findings left.
	os.Remove(filepath.Join(root, "Dockerfile"))
	if f, gone, err := Find(ctx, root, "Dockerfile", star.Line, RuleStar, star.Message, Options{}); err != nil || !gone || f != nil {
		t.Errorf("deleted: %+v %v %v", f, gone, err)
	}
}

// An image the scan cannot resolve is not checked, not scratch.
func TestUnresolvedImageIsNotChecked(t *testing.T) {
	for _, from := range []string{"ARG BASE\nFROM ${BASE}", "FROM $BASE", "FROM ${BASE:-}", "FROM {{ .Base }}"} {
		root := t.TempDir()
		write(t, root, "Dockerfile", from+"\nRUN apk add openssh-server\n")
		if fs := scan(t, root, Options{}); len(fs) != 1 || fs[0].Rule != RuleNotChecked {
			t.Errorf("%q: %+v", from, fs)
		}
	}
	// A default still decides.
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM ${BASE:-debian:12}\nRUN apk add openssh-server\n")
	if fs := scan(t, root, Options{}); len(fs) != 0 {
		t.Errorf("default: %+v", fs)
	}
}
