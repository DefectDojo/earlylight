package fix

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/refs"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry/registrytest"
)

type fixture struct {
	s       *registrytest.Server
	r       *registry.Resolver
	old84   v1.Hash // php:8.4.20-cli index
	new84   v1.Hash // php:8.4-cli / 8.4.27-cli index now
	old84a  v1.Hash // amd64 manifest in old84
	new84a  v1.Hash // amd64 manifest in new84
	wpOld   v1.Hash
	wpNew   v1.Hash
	unrelat v1.Hash
}

// pushPHP pushes an official-style index for v on base at each tag.
func pushPHP(s *registrytest.Server, v, base string, plats []string, tags ...string) (v1.Hash, []v1.Hash) {
	return s.PHPIndexOn(v, base, plats, tags...)
}

var both = []string{"linux/amd64", "linux/arm64/v8"}

const (
	trixie   = "debian:trixie-slim"
	bookworm = "debian:bookworm-slim"
	a321     = "alpine:3.21"
	a320     = "alpine:3.20"
	a322     = "alpine:3.22"
	a324     = "alpine:3.24"
)

func newFixture(t *testing.T) *fixture {
	s := registrytest.New(t)
	f := &fixture{s: s}
	pushPHP(s, "8.3.20", a321, both, "8.3.20-fpm-alpine3.21")
	pushPHP(s, "8.3.20", a320, both, "8.3.20-fpm-alpine3.20")
	pushPHP(s, "8.3.20", trixie, both, "8.3.20-cli")
	pushPHP(s, "8.3.36", a321, both, "8.3.36-fpm-alpine3.21")
	pushPHP(s, "8.3.36", a322, both, "8.3.36-fpm-alpine3.22")
	pushPHP(s, "8.3.36", trixie, both, "8.3.36-cli")
	pushPHP(s, "8.3.35", trixie, both, "8.3.35-fpm", "8.3-fpm")
	s.EmptyIndex("library/php", "8.3.36-fpm")
	pushPHP(s, "8.2.20", trixie, both, "8.2.20-cli")
	pushPHP(s, "8.2.35", trixie, []string{"linux/amd64"}, "8.2.35-cli")
	pushPHP(s, "8.1.30", trixie, both, "8.1.30-cli")
	var ms []v1.Hash
	f.old84, ms = pushPHP(s, "8.4.20", trixie, both, "8.4.20-cli")
	f.old84a = ms[0]
	f.new84, ms = pushPHP(s, "8.4.27", trixie, both, "8.4.27-cli", "8.4-cli")
	f.new84a = ms[0]
	pushPHP(s, "8.5.12", trixie, both, "8.5.12-cli")
	wp := func(v string) v1.ImageIndex {
		return s.Index(registrytest.Spec{
			OS: "linux", Arch: "amd64", Env: append(registrytest.PHPEnv(v), "WORDPRESS_VERSION=6.8.3"),
			// wordpress's base annotation is php:..., not an OS: the
			// Debian release comes from the first history entry.
			Base: "php:8.3-apache", History: "# debian.sh --arch 'amd64' out/ 'trixie' '@1760000000'",
		})
	}
	f.wpOld = s.PushIndex("library/wordpress", "6.8.2-php8.3", wp("8.3.35"))
	f.wpNew = s.PushIndex("library/wordpress", "6-php8.3-apache", wp("8.3.36"))
	f.unrelat = s.PushIndex("library/nginx", "1.29", s.Index(registrytest.Spec{OS: "linux", Arch: "amd64", Env: []string{"NGINX_VERSION=1.29.2"}}))
	f.r = registry.NewResolver(registry.Options{
		Keychain: authn.NewMultiKeychain(), Mirrors: s.Mirrors(),
		MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
	})
	return f
}

// plan writes files into a fresh repository, scans it, and plans a fix for
// the reference at file:line.
func (f *fixture) plan(t *testing.T, files map[string]string, file string, line int) (string, *Change, error) {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, skips, err := refs.Scan(root, refs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.File != file || r.Line != line {
			continue
		}
		res, err := f.r.Resolve(context.Background(), r.Image)
		if err != nil {
			t.Fatalf("resolve %s: %v", r.Image, err)
		}
		c, err := Plan(context.Background(), root, r, res, f.r)
		return root, c, err
	}
	t.Fatalf("no ref at %s:%d in %+v (skips %+v)", file, line, rs, skips)
	return "", nil, nil
}

func TestPlanAndApply(t *testing.T) {
	f := newFixture(t)
	d := func(h v1.Hash) string { return h.String() }
	tests := []struct {
		name     string
		files    map[string]string
		file     string
		line     int
		editFile string
		editLine int
		newLine  string
		after    string
	}{
		{
			name:  "exact tag",
			files: map[string]string{"Dockerfile": "# syntax=docker/dockerfile:1\nFROM php:8.3.20-fpm-alpine3.21 AS app\nRUN echo php:8.3.20-fpm-alpine3.21\n"},
			file:  "Dockerfile", line: 2, editFile: "Dockerfile", editLine: 2,
			newLine: "FROM php:8.3.36-fpm-alpine3.21 AS app",
			after:   "php:8.3.36-fpm-alpine3.21",
		},
		{
			name:  "CRLF and fully qualified",
			files: map[string]string{"app/Containerfile": "FROM --platform=linux/amd64 docker.io/library/php:8.3.20-cli\r\nCMD [\"php\"]\r\n"},
			file:  "app/Containerfile", line: 1, editFile: "app/Containerfile", editLine: 1,
			newLine: "FROM --platform=linux/amd64 docker.io/library/php:8.3.36-cli",
			after:   "docker.io/library/php:8.3.36-cli",
		},
		{
			name:  "ARG default",
			files: map[string]string{"Dockerfile": "ARG PHP_VERSION=8.3.20 # not a comment, part of nothing\nFROM php:${PHP_VERSION}-fpm-alpine3.21\n"},
			file:  "Dockerfile", line: 2,
		},
		{
			name:  "ARG default simple",
			files: map[string]string{"Dockerfile": "ARG PHP_VERSION=8.3.20\nFROM php:${PHP_VERSION}-fpm-alpine3.21\n"},
			file:  "Dockerfile", line: 2, editFile: "Dockerfile", editLine: 1,
			newLine: "ARG PHP_VERSION=8.3.36",
			after:   "php:8.3.36-fpm-alpine3.21",
		},
		{
			name:  "quoted ARG",
			files: map[string]string{"Dockerfile": "ARG BASE=\"php:8.3.20-cli\"\nFROM $BASE\n"},
			file:  "Dockerfile", line: 2, editFile: "Dockerfile", editLine: 1,
			newLine: "ARG BASE=\"php:8.3.36-cli\"",
			after:   "php:8.3.36-cli",
		},
		{
			name:  "version split between ARG and FROM",
			files: map[string]string{"Dockerfile": "ARG MINOR=8.3\nFROM php:${MINOR}.20-cli\n"},
			file:  "Dockerfile", line: 2, editFile: "Dockerfile", editLine: 2,
			newLine: "FROM php:${MINOR}.36-cli",
			after:   "php:8.3.36-cli",
		},
		{
			name:  "shared ARG, both verify",
			files: map[string]string{"Dockerfile": "ARG V=8.3.20\nFROM php:${V}-cli AS a\nFROM php:${V}-fpm-alpine3.21\n"},
			file:  "Dockerfile", line: 2, editFile: "Dockerfile", editLine: 1,
			newLine: "ARG V=8.3.36",
			after:   "php:8.3.36-cli",
		},
		{
			name:  "digest-pinned floating tag",
			files: map[string]string{"Dockerfile": "FROM php:8.4-cli@" + d(f.old84) + "\n"},
			file:  "Dockerfile", line: 1, editFile: "Dockerfile", editLine: 1,
			newLine: "FROM php:8.4-cli@" + d(f.new84),
			after:   "php:8.4-cli@" + d(f.new84),
		},
		{
			name:  "digest-pinned exact tag",
			files: map[string]string{"Dockerfile": "FROM php:8.4.20-cli@" + d(f.old84) + " AS x\n"},
			file:  "Dockerfile", line: 1, editFile: "Dockerfile", editLine: 1,
			newLine: "FROM php:8.4.27-cli@" + d(f.new84) + " AS x",
			after:   "php:8.4.27-cli@" + d(f.new84),
		},
		{
			name:  "pinned to a platform manifest",
			files: map[string]string{"Dockerfile": "FROM php:8.4-cli@" + d(f.old84a) + "\n"},
			file:  "Dockerfile", line: 1, editFile: "Dockerfile", editLine: 1,
			newLine: "FROM php:8.4-cli@" + d(f.new84a),
			after:   "php:8.4-cli@" + d(f.new84a),
		},
		{
			name:  "derived image pinned by digest",
			files: map[string]string{"docker-compose.yml": "services:\n  wp:\n    image: \"wordpress:6-php8.3-apache@" + d(f.wpOld) + "\" # pinned\n"},
			file:  "docker-compose.yml", line: 3, editFile: "docker-compose.yml", editLine: 3,
			newLine: "    image: \"wordpress:6-php8.3-apache@" + d(f.wpNew) + "\" # pinned",
			after:   "wordpress:6-php8.3-apache@" + d(f.wpNew),
		},
		{
			name:  "helm values tag line",
			files: map[string]string{"chart/values.yaml": "image:\n  repository: php\n  tag: '8.3.20-fpm-alpine3.21'  # app\n  pullPolicy: Always\n"},
			file:  "chart/values.yaml", line: 2, editFile: "chart/values.yaml", editLine: 3,
			newLine: "  tag: '8.3.36-fpm-alpine3.21'  # app",
			after:   "php:8.3.36-fpm-alpine3.21",
		},
		{
			name:  "compose default",
			files: map[string]string{"compose.yaml": "services:\n  app:\n    image: php:${PHP_TAG:-8.3.20-cli}\n"},
			file:  "compose.yaml", line: 3, editFile: "compose.yaml", editLine: 3,
			newLine: "    image: php:${PHP_TAG:-8.3.36-cli}",
			after:   "php:8.3.36-cli",
		},
		{
			name: "compose .env value",
			files: map[string]string{
				"deploy/compose.yaml":           "services:\n  app:\n    image: php:${PHP_TAG:-8.2.20-cli}\n",
				"deploy/docker-compose.dev.yml": "services:\n  dev:\n    image: php:${PHP_TAG}\n",
				"deploy/.env":                   "# versions\r\nPHP_TAG=8.3.20-cli\r\n",
			},
			file: "deploy/compose.yaml", line: 3, editFile: "deploy/.env", editLine: 2,
			newLine: "PHP_TAG=8.3.36-cli",
			after:   "php:8.3.36-cli",
		},
		{
			name:  "kubernetes",
			files: map[string]string{"k8s/deploy.yaml": "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - {name: a, image: php:8.3.20-cli}   # x\n"},
			file:  "k8s/deploy.yaml", line: 5, editFile: "k8s/deploy.yaml", editLine: 5,
			newLine: "    - {name: a, image: php:8.3.36-cli}   # x",
			after:   "php:8.3.36-cli",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, c, err := f.plan(t, tc.files, tc.file, tc.line)
			if tc.newLine == "" {
				// "ARG PHP_VERSION=8.3.20 # ..." is three ARGs; the "#" and
				// the words after it are ARG names without values.
				if err != nil {
					t.Fatalf("plan: %v", err)
				}
				if c.Line != 1 || !strings.HasPrefix(c.New, "ARG PHP_VERSION=8.3.36 #") {
					t.Fatalf("change %+v", c)
				}
				return
			}
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if c.File != tc.editFile || c.Line != tc.editLine || c.New != tc.newLine || c.After != tc.after {
				t.Fatalf("change = %s:%d %q -> %q (after %s), want %s:%d %q (%s)\nreason: %s", c.File, c.Line, c.Old, c.New, c.After, tc.editFile, tc.editLine, tc.newLine, tc.after, c.Reason)
			}
			t.Logf("reason: %s", c.Reason)
			if len(c.Verified) == 0 || c.Reason == "" {
				t.Errorf("change %+v", c)
			}
			p := filepath.Join(root, filepath.FromSlash(c.File))
			before, _ := os.ReadFile(p)
			if err := os.Chmod(p, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := Apply(root, []Change{*c, *c}); err != nil {
				t.Fatal(err)
			}
			after, _ := os.ReadFile(p)
			assertOneLine(t, before, after, c)
			if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o750 {
				t.Errorf("mode %v", fi.Mode())
			}
			// Applying again refuses: the line no longer reads Old.
			if err := Apply(root, []Change{*c}); err == nil {
				t.Error("second Apply succeeded")
			}
			// Re-scan from disk: the reference is now the fixed one.
			rs, _, _ := refs.Scan(root, refs.Options{})
			found := false
			for _, r := range rs {
				if r.File == tc.file && r.Line == tc.line && r.Image == tc.after {
					found = true
				}
			}
			if !found {
				t.Errorf("after apply refs %+v", rs)
			}
		})
	}
}

// assertOneLine checks that after differs from before only in the changed
// line.
func assertOneLine(t *testing.T, before, after []byte, c *Change) {
	t.Helper()
	bl, al := splitKeep(before), splitKeep(after)
	if len(bl) != len(al) {
		t.Fatalf("line count %d -> %d", len(bl), len(al))
	}
	for i := range bl {
		if bl[i].term != al[i].term {
			t.Errorf("line %d terminator changed", i+1)
		}
		if i == c.Line-1 {
			if bl[i].text != c.Old || al[i].text != c.New {
				t.Errorf("line %d: %q -> %q", i+1, bl[i].text, al[i].text)
			}
			continue
		}
		if bl[i].text != al[i].text {
			t.Errorf("line %d changed: %q -> %q", i+1, bl[i].text, al[i].text)
		}
	}
	if len(after)-len(before) != len(c.New)-len(c.Old) {
		t.Errorf("size changed by %d", len(after)-len(before))
	}
}

func TestDeclines(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name  string
		files map[string]string
		file  string
		line  int
		code  DeclineCode
		says  string
	}{
		{"floating tag", map[string]string{"Dockerfile": "FROM php:8.3-fpm\n"}, "Dockerfile", 1, DeclineFloatingTag, "the tag will move to the fixed release"},
		{"empty index", map[string]string{"Dockerfile": "FROM php:8.3.35-fpm\n"}, "Dockerfile", 1, DeclineNotPublished, "exists but has no images yet"},
		{"suffix not published", map[string]string{"Dockerfile": "FROM php:8.3.20-fpm-alpine3.20\n"}, "Dockerfile", 1, DeclineSuffixNotPublished, "-fpm-alpine3.21, -fpm-alpine3.22"},
		{"platform missing", map[string]string{"Dockerfile": "FROM php:8.2.20-cli\n"}, "Dockerfile", 1, DeclinePlatformsMissing, "not yet published for linux/arm64/v8"},
		{"end of life", map[string]string{"Dockerfile": "FROM php:8.1.30-cli\n"}, "Dockerfile", 1, DeclineEndOfLife, "changes the PHP minor version"},
		{"bare digest", map[string]string{"Dockerfile": "FROM php@" + f.old84.String() + "\n"}, "Dockerfile", 1, DeclineBareDigest, "variant"},
		{"derived", map[string]string{"Dockerfile": "FROM wordpress:6.8.2-php8.3\n"}, "Dockerfile", 1, DeclineDerivedImage, "publisher rebuilds"},
		{"not vulnerable", map[string]string{"Dockerfile": "FROM php:8.5.12-cli\n"}, "Dockerfile", 1, DeclineNotVulnerable, "carries the fix"},
		{
			"shared ARG whose other fix differs",
			map[string]string{"Dockerfile": "ARG V=8.3.20\nFROM php:${V}-fpm-alpine3.21 AS a\nFROM php:${V}-fpm-alpine3.20\n"},
			"Dockerfile", 2, DeclineSharedEdit, "php:8.3.36-fpm-alpine3.20",
		},
		{
			"shared ARG feeding an unrelated image",
			map[string]string{"Dockerfile": "ARG V=8.3.20\nFROM php:${V}-cli AS a\nFROM nginx:1.29@sha256:" + strings.Repeat("0", 64) + "\nFROM acme/tool:${V}\n"},
			"Dockerfile", 2, DeclineSharedEdit, "acme/tool:8.3.36",
		},
		{
			"helm tag and digest on two lines",
			map[string]string{"values.yaml": "image:\n  repository: php\n  tag: 8.4.20-cli\n  digest: " + f.old84.String() + "\n"},
			"values.yaml", 2, DeclineMultipleLines, "single-line",
		},
		{
			"escaped in YAML",
			map[string]string{"compose.yaml": "services:\n  a:\n    image: \"php:8.3.20\\x2dcli\"\n"},
			"compose.yaml", 3, DeclineNotEditable, "verbatim",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, c, err := f.plan(t, tc.files, tc.file, tc.line)
			d, ok := IsDecline(err)
			if !ok {
				t.Fatalf("got change %+v err %v, want decline %s", c, err, tc.code)
			}
			t.Logf("decline: %s", d.Reason)
			if d.Code != tc.code || !strings.Contains(d.Reason, tc.says) {
				t.Errorf("decline %s %q, want %s containing %q", d.Code, d.Reason, tc.code, tc.says)
			}
		})
	}
}

func TestApplyRefusesStaleAndSymlinks(t *testing.T) {
	f := newFixture(t)
	root, c, err := f.plan(t, map[string]string{"Dockerfile": "FROM php:8.3.20-cli\n"}, "Dockerfile", 1)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "Dockerfile")
	if err := os.WriteFile(p, []byte("FROM php:8.3.20-cli AS changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Apply(root, []Change{*c}); err == nil {
		t.Error("applied to a changed line")
	}
	if b, _ := os.ReadFile(p); string(b) != "FROM php:8.3.20-cli AS changed\n" {
		t.Errorf("file written: %q", b)
	}
	// Conflicting changes to one line.
	c2 := *c
	c2.New = "FROM php:8.3.36-zts"
	if err := Apply(root, []Change{*c, c2}); err == nil {
		t.Error("conflicting changes applied")
	}
	// A symlinked directory on the way is refused.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "Dockerfile"), []byte(c.Old+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	c3 := *c
	c3.File = "link/Dockerfile"
	if err := Apply(root, []Change{c3}); err == nil {
		t.Error("wrote through a symlink")
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "Dockerfile")); !bytes.Equal(b, []byte(c.Old+"\n")) {
		t.Error("outside file changed")
	}
}
