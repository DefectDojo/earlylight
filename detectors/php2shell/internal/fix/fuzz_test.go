package fix

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/refs"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/registry"
)

// fakeResolver answers for docker.io/library/php exact tags only: the tag's
// version on linux/amd64 and linux/arm64/v8.
type fakeResolver struct{}

var fakeExact = regexp.MustCompile(`^([0-9]+\.[0-9]+\.[0-9]+)(-[a-z0-9.-]+)?$`)

var fakeTags = []string{"8.3.36", "8.3.36-cli", "8.3.36-fpm", "8.3.36-fpm-alpine3.21", "8.2.35-cli", "8.4.27-cli", "8.5.12-cli"}

func (fakeResolver) Resolve(_ context.Context, s string) (*registry.Resolution, error) {
	ref, err := registry.ParseReference(s)
	if err != nil {
		return nil, &registry.Error{Kind: registry.KindInvalid, Ref: s, Err: err}
	}
	m := fakeExact.FindStringSubmatch(ref.Tag)
	if !ref.IsOfficialPHP() || ref.Digest != "" || m == nil {
		return nil, &registry.Error{Kind: registry.KindNotFound, Ref: s, Err: fmt.Errorf("not found")}
	}
	d := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(ref.String())))
	return &registry.Resolution{
		Ref: s, Reference: ref, Index: true, Digest: d,
		Platforms: []registry.Platform{
			{Platform: "linux/amd64", Digest: d, PHPVersion: m[1], BaseOS: "debian:trixie"},
			{Platform: "linux/arm64/v8", Digest: d, PHPVersion: m[1], BaseOS: "debian:trixie"},
		},
	}, nil
}

func (fakeResolver) Tags(context.Context, string) ([]string, error) { return fakeTags, nil }

var planTemplates = []struct{ file, body string }{
	{"Dockerfile", "FROM php:8.3.20-cli\n"},
	{"Dockerfile", "ARG V=8.3.20\nFROM php:${V}-fpm\n"},
	{"chart/values.yaml", "image:\n  repository: php\n  tag: \"8.4.1-cli\"\n"},
	{"compose.yaml", "services:\n  a:\n    image: php:${T:-8.2.1-cli}\n"},
	{"k8s/pod.yaml", "apiVersion: v1\nkind: Pod\nspec:\n  containers: [{image: 'php:8.5.0-cli'}]\n"},
}

// FuzzPlanEdit surrounds known-vulnerable references with arbitrary text and
// checks that every proposed fix edits only its own line, keeps every other
// byte, and leaves the reference resolving to the fixed image.
func FuzzPlanEdit(f *testing.F) {
	f.Add(uint8(0), []byte(""), []byte(""))
	f.Add(uint8(1), []byte("# syntax=x\r\n"), []byte("FROM php:8.3.20-cli\r\n"))
	f.Add(uint8(1), []byte("ARG V=8.3.20 W=8.3.20\n"), []byte("FROM php:${V}-cli\n"))
	f.Add(uint8(2), []byte("x: 1\n"), []byte("other:\n  image: php:8.3.20-cli\n"))
	f.Add(uint8(3), []byte(""), []byte("  b:\n    image: php:${T:-8.2.1-cli}\n"))
	f.Add(uint8(4), []byte("---\n"), []byte("---\napiVersion: v1\nkind: Pod\n"))
	f.Fuzz(func(t *testing.T, which uint8, prefix, suffix []byte) {
		tpl := planTemplates[int(which)%len(planTemplates)]
		content := append(append(append([]byte{}, prefix...), tpl.body...), suffix...)
		root := t.TempDir()
		p := filepath.Join(root, filepath.FromSlash(tpl.file))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
		rs, _, err := refs.ScanFiles(root, []string{tpl.file}, refs.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var r fakeResolver
		ctx := context.Background()
		for _, ref := range rs {
			res, err := r.Resolve(ctx, ref.Image)
			if err != nil {
				continue
			}
			c, err := Plan(ctx, root, ref, res, r)
			if d, ok := IsDecline(err); ok && d.Code == DeclineBaseOSUnknown {
				t.Fatalf("fake images carry a base: %v", d)
			}
			if err != nil {
				if _, ok := IsDecline(err); !ok {
					t.Fatalf("plan %s: %v", ref.Image, err)
				}
				continue
			}
			ep := filepath.Join(root, filepath.FromSlash(c.File))
			before, err := os.ReadFile(ep)
			if err != nil {
				t.Fatal(err)
			}
			if err := Apply(root, []Change{*c}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			after, _ := os.ReadFile(ep)
			assertOneLine(t, before, after, c)
			rs2, _, _ := refs.ScanFiles(root, []string{tpl.file}, refs.Options{})
			found := false
			for _, r2 := range rs2 {
				if sameRef(r2, ref) && r2.Image == c.After {
					found = true
				}
			}
			if !found {
				t.Fatalf("after applying %+v the reference is not %s: %+v", c, c.After, rs2)
			}
			if a := registry.Assess(mustFake(t, c.After)); a.Verdict != registry.Fixed {
				t.Fatalf("after %s: %s", c.After, a.Reason)
			}
			return // the file changed; later refs were planned against the old content
		}
	})
}

func mustFake(t *testing.T, s string) *registry.Resolution {
	res, err := fakeResolver{}.Resolve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
