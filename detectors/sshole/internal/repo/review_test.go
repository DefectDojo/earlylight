package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cases from the independent review of the not-checked change (numbers
// are the review's findings).

func alpineAt(branch string) Options {
	return Options{Base: func(context.Context, string) (bool, string, error) { return true, branch, nil }}
}

func mustBeGone(t *testing.T, what string, f *Finding, gone bool, err error) {
	t.Helper()
	if err != nil || !gone || f != nil {
		t.Fatalf("%s: want gone, got finding %+v, gone %v, err %v", what, f, gone, err)
	}
}

// 1: an end-of-life finding rescans as apk-unpinned when the lookup fails,
// and the reverse.
func TestReviewEOLAndUnpinnedSwap(t *testing.T) {
	ctx := context.Background()
	for _, from := range []string{"FROM acme/app:alpine", "FROM alpine"} {
		root := t.TempDir()
		write(t, root, "Dockerfile", from+"\nRUN apk add openssh-server\n")
		eol := findOne(t, root, alpineAt("3.14"), RuleEOL)
		for name, o := range map[string]Options{"lookup down": baseDown, "no lookup": {}} {
			f, gone, err := Find(ctx, root, "Dockerfile", eol.Line, RuleEOL, eol.Message, o)
			mustDecline(t, from+", "+name, f, gone, err)
		}
	}
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/app:alpine\nRUN apk add openssh-server\n")
	un := findOne(t, root, baseDown, RuleUnpinned)
	f, gone, err := Find(ctx, root, "Dockerfile", un.Line, RuleUnpinned, un.Message, alpineAt("3.14"))
	mustDecline(t, "unpinned now end-of-life", f, gone, err)
}

// 5: a pin loosened to no floor is not fixed.
func TestReviewPinLoosened(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add openssh-server=9.9_p1-r2\n")
	pin := findOne(t, root, Options{}, RulePin)
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add openssh-server\n")
	f, gone, err := Find(context.Background(), root, "Dockerfile", pin.Line, RulePin, pin.Message, Options{})
	mustDecline(t, "loosened", f, gone, err)
}

// 2a: lookup down and the line shifted.
func TestReviewNotCheckedElsewhere(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2\n")
	pin := findOne(t, root, alpine321, RulePin)
	write(t, root, "Dockerfile", "# a comment\nFROM acme/base:1\nRUN apk add openssh-server=9.9_p1-r2\n")
	f, gone, err := Find(context.Background(), root, "Dockerfile", pin.Line, RulePin, pin.Message, baseDown)
	mustDecline(t, "shifted, lookup down", f, gone, err)
}

// 2b: Buildroot whose C library is no longer set.
func TestReviewBuildrootLibcRemoved(t *testing.T) {
	root := t.TempDir()
	write(t, root, "configs/a_defconfig", "BR2_TOOLCHAIN_BUILDROOT_MUSL=y\nBR2_PACKAGE_OPENSSH=y\n")
	b := findOne(t, root, Options{}, RuleBuild)
	write(t, root, "configs/a_defconfig", "BR2_PACKAGE_OPENSSH=y\n")
	f, gone, err := Find(context.Background(), root, b.File, b.Line, RuleBuild, b.Message, Options{})
	mustDecline(t, "libc removed", f, gone, err)
}

// 2c: a pin through a variable keeps no line number in its message, and
// a message stored with one still matches.
func TestReviewVariableMoved(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nARG PKGS=\"openssh-server=9.9_p1-r2\"\nRUN apk add $PKGS\n")
	pin := findOne(t, root, Options{}, RulePin)
	if strings.Contains(pin.Message, "line") {
		t.Errorf("line number in the message: %q", pin.Message)
	}
	write(t, root, "Dockerfile", "FROM alpine:3.21\n# a comment\nARG PKGS=\"openssh-server=9.9_p1-r2\"\nRUN apk add $PKGS\n")
	for _, msg := range []string{pin.Message, strings.TrimSuffix(pin.Message, ")") + ", set on line 2)"} {
		f, gone, err := Find(ctx, root, "Dockerfile", pin.Line, RulePin, msg, Options{})
		if err != nil || gone || f == nil || f.Line != pin.Line+1 {
			t.Errorf("%q: %+v %v %v", msg, f, gone, err)
		}
	}
	// The variable is no longer set: not checked, not gone.
	write(t, root, "Dockerfile", "FROM alpine:3.21\n# a comment\n\nRUN apk add $PKGS\n")
	f, gone, err := Find(ctx, root, "Dockerfile", pin.Line, RulePin, pin.Message, Options{})
	mustDecline(t, "variable unset", f, gone, err)
}

// 3: rules and files Find never produces.
func TestReviewForeignRules(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "docker-compose.yml", "services:\n  ssh:\n    image: acme/sshd:1\n")
	write(t, root, "Dockerfile", "FROM alpine:3.22\n")
	write(t, root, "k8s/deploy.json", "{}\n")
	for _, c := range []struct{ file, rule string }{
		{"docker-compose.yml", "image"},
		{"Dockerfile", "bogus"},
		{"k8s/deploy.json", RuleStar},
		{"k8s/missing.json", RuleStar},
	} {
		f, gone, err := Find(ctx, root, c.file, 3, c.rule, "", Options{})
		mustDecline(t, c.file+" "+c.rule, f, gone, err)
	}
}

func yoctoTree(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "meta-a/conf/layer.conf", "LAYERSERIES_COMPAT_a = \"scarthgap\"\n")
	write(t, root, "meta-a/conf/distro/a.conf", "TCLIBC = \"musl\"\n")
	write(t, root, "meta-a/recipes-core/images/a.bb", "IMAGE_INSTALL:append = \" openssh\"\n")
	return root
}

// 4: an unreadable directory holding the TCLIBC setting.
func TestReviewYoctoDirUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 000 directory")
	}
	root := yoctoTree(t)
	b := findOne(t, root, Options{}, RuleBuild)
	dir := filepath.Join(root, "meta-a/conf/distro")
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	f, gone, err := Find(context.Background(), root, b.File, b.Line, RuleBuild, b.Message, Options{})
	mustDecline(t, "distro dir unreadable", f, gone, err)
}

func TestReviewYoctoSkipRelevance(t *testing.T) {
	msg := "Yocto image installs the OpenSSH server and meta-a/conf/distro/a.conf:1 sets TCLIBC to musl; x"
	for _, c := range []struct {
		skip string
		want bool
	}{
		{"meta-a/conf/distro/a.conf", true},
		{"meta-a/conf/distro", true},
		{"meta-a", true},
		{"meta-a/conf/distro/b.conf", false},
		{"third_party/tables/data.inc", false},
		{"meta-a/conf/distro/a.conf.bak", false},
	} {
		if got := blocksYocto(Skip{File: c.skip}, msg); got != c.want {
			t.Errorf("%s: %v", c.skip, got)
		}
	}
	// Without the reference, any build file or directory counts.
	if !blocksYocto(Skip{File: "x/local.conf"}, "Yocto image") {
		t.Error("no reference: build file does not count")
	}
}

// 6: a fixed pin next to a variable install is gone.
func TestReviewFixedPinBesideVariable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.21\nRUN apk add openssh-server=9.9_p1-r2 $EXTRA\n")
	var pin Finding
	for _, f := range scan(t, root, Options{}) {
		if f.Rule == RulePin {
			pin = f
		}
	}
	ch, err := Plan(ctx, root, pin, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(root, ch); err != nil {
		t.Fatal(err)
	}
	f, gone, err := Find(ctx, root, "Dockerfile", pin.Line, RulePin, pin.Message, Options{})
	mustBeGone(t, "fixed pin", f, gone, err)
}

// 7: an unrelated oversized build file, skipped at scan time too.
func TestReviewYoctoUnrelatedSkip(t *testing.T) {
	ctx := context.Background()
	root := yoctoTree(t)
	write(t, root, "third_party/tables/data.inc", strings.Repeat("#\n", maxFileSize/2+1))
	b := findOne(t, root, Options{}, RuleBuild)
	if !b.Fixable {
		t.Fatalf("not fixable: %+v", b)
	}
	ch, err := Plan(ctx, root, b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(root, ch); err != nil {
		t.Fatal(err)
	}
	f, gone, err := Find(ctx, root, b.File, b.Line, RuleBuild, b.Message, Options{})
	mustBeGone(t, "bbappend added", f, gone, err)
}

// 8: past the end, but the whole-file rescan has nothing like it left.
func TestReviewPastEndSettled(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN true\nRUN true\nRUN usermod -p '*' bob\nRUN true\nRUN true\n")
	star := findOne(t, root, Options{}, RuleStar)
	write(t, root, "Dockerfile", "FROM alpine:3.22\nRUN true\n")
	for _, msg := range []string{star.Message, ""} {
		f, gone, err := Find(context.Background(), root, "Dockerfile", star.Line, RuleStar, msg, Options{})
		mustBeGone(t, "past the end, message "+msg, f, gone, err)
	}
}

// 11: empty and prefix variables in FROM are still judged.
func TestReviewFromVariables(t *testing.T) {
	for _, from := range []string{
		"ARG REGISTRY=\nFROM ${REGISTRY}alpine:3.21",
		"ARG REGISTRY=\"\"\nFROM ${REGISTRY}alpine:3.21",
		"FROM ${REGISTRY:-}alpine:3.21",
	} {
		root := t.TempDir()
		write(t, root, "Dockerfile", from+"\nRUN apk add openssh-server\n")
		if f := findOne(t, root, Options{}, RuleUnpinned); !f.Fixable || strings.Contains(f.Message, "REGISTRY") {
			t.Errorf("%q: %+v", from, f)
		}
	}
	// Unset: the image after it is judged, with a note.
	for _, from := range []string{"FROM ${REGISTRY}alpine:3.21", "ARG REGISTRY\nFROM ${REGISTRY}/alpine:3.21", "FROM $REGISTRY/alpine:3.21"} {
		root := t.TempDir()
		write(t, root, "Dockerfile", from+"\nRUN apk add openssh-server\n")
		if f := findOne(t, root, Options{}, RuleUnpinned); !f.Fixable || !strings.Contains(f.Message, "REGISTRY") {
			t.Errorf("%q: %+v", from, f)
		}
	}
	// An end-of-life base behind the prefix is still fixed in place.
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM ${REGISTRY}alpine:3.14\nRUN apk add openssh-server\n")
	eol := findOne(t, root, Options{}, RuleEOL)
	ch, err := Plan(context.Background(), root, eol, Options{})
	if err != nil || ch.Edits[0].New != "FROM ${REGISTRY}alpine:3.16" {
		t.Fatalf("%+v %v", ch, err)
	}
	// An optional suffix: resolved online as before.
	root = t.TempDir()
	write(t, root, "Dockerfile", "ARG PY=3.12\nFROM python:${PY}${FLAVOR}\nRUN apk add openssh-server\n")
	var asked []string
	o := Options{Base: func(_ context.Context, img string) (bool, string, error) {
		asked = append(asked, img)
		return true, "3.21", nil
	}}
	findOne(t, root, o, RuleUnpinned)
	if strings.Join(asked, ",") != "python:3.12" {
		t.Errorf("looked up %v", asked)
	}
}

// 12: a tag made only of unset variables is not known, and not fixed.
func TestReviewTagOfVariables(t *testing.T) {
	root := t.TempDir()
	write(t, root, "Dockerfile", "FROM alpine:${MAJOR}.${MINOR}\nRUN apk add openssh-server\n")
	if f := findOne(t, root, Options{}, RuleNotChecked); f.Fixable {
		t.Errorf("%+v", f)
	}
}
