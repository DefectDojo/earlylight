package pins_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
)

// A finding that was not checked, or that cannot be checked again now, is
// never "already fixed": Plan declines with "rescan to confirm" instead.

// mustDecline fails unless Plan declined with "rescan to confirm".
func mustDecline(t *testing.T, what string, ch *pins.Change, already bool, err error) {
	t.Helper()
	d, ok := pins.IsDeclined(err)
	if already || ch != nil || !ok {
		t.Errorf("%s: want a decline, got change %+v, already %v, err %v", what, ch, already, err)
		return
	}
	if !strings.Contains(d.Reason, "rescan to confirm") {
		t.Errorf("%s: reason %q does not say rescan to confirm", what, d.Reason)
	}
}

// mustBeGone fails unless Plan reported the finding already fixed.
func mustBeGone(t *testing.T, what string, ch *pins.Change, already bool, err error) {
	t.Helper()
	if !already || ch != nil || err != nil {
		t.Errorf("%s: want already fixed, got change %+v, already %v, err %v", what, ch, already, err)
	}
}

// only scans root and returns its one finding of rule.
func only(t *testing.T, root, rule string) pins.Finding {
	t.Helper()
	res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out []pins.Finding
	for _, f := range res.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	if len(out) != 1 {
		t.Fatalf("want one %s finding, got %+v (skips %+v)", rule, res.Findings, res.Skips)
	}
	return out[0]
}

func plan(root string, f pins.Finding) (*pins.Change, bool, error) {
	return pins.Plan(context.Background(), root, f.File, f.Line, f.Rule, f.Props)
}

const oversized = 5 << 20 // past the 4 MiB the pin finder reads

func big(head string) string { return head + strings.Repeat("#\n", oversized/2) }

// A skip reaches a report as a not-checked finding. Whatever the file holds
// now, Plan did not check what the skip left out.
func TestPlanNotCheckedFinding(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "FROM node@sha256:" + strings.Repeat("a", 64) + "\n"})
	res, err := pins.Scan(ctx, root, nil, pins.Options{})
	if err != nil || len(res.Skips) != 1 || len(res.Findings) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	sk := res.Skips[0]
	try := func(what string) {
		t.Helper()
		ch, already, err := pins.Plan(ctx, root, sk.File, sk.Line, pins.RuleNotChecked, nil)
		mustDecline(t, what, ch, already, err)
	}
	try("still digest only")
	write(t, root, map[string]string{"Dockerfile": "FROM node:24.22.0\n"})
	try("now a vulnerable tag")
	write(t, root, map[string]string{"Dockerfile": "FROM node:24-slim\n"})
	try("now a floating tag")
	os.Remove(filepath.Join(root, "Dockerfile"))
	try("removed")

	// A file-level skip: package.json that was not valid JSON.
	write(t, root, map[string]string{"package.json": "{\"volta\": {\"node\": \"24.22.0\"}"})
	res, err = pins.Scan(ctx, root, nil, pins.Options{})
	if err != nil || len(res.Skips) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	write(t, root, map[string]string{"package.json": "{\"volta\": {\"node\": \"24.22.1\"}}"})
	ch, already, err := pins.Plan(ctx, root, "package.json", res.Skips[0].Line, pins.RuleNotChecked, nil)
	mustDecline(t, "package.json valid now", ch, already, err)

	// Rules this package does not plan for are not checked here either.
	for _, rule := range []string{pins.RuleImage, pins.RuleImageUnknown, "", "brotli/other"} {
		ch, already, err := pins.Plan(ctx, root, "package.json", 1, rule, nil)
		mustDecline(t, "rule "+rule, ch, already, err)
	}
}

// A file the rescan cannot read this time says nothing about the pin. A
// text candidate (a shell script, a Makefile) used to be read without
// recording why it was not.
func TestPlanFileUnreadableNow(t *testing.T) {
	for _, c := range []struct{ file, body, rule string }{
		{"install.sh", "export NODE_VERSION=24.22.0\n", pins.RuleNode},
		{"Makefile", "build:\n\tnvm install 24.22.0\n", pins.RuleNode},
		{".nvmrc", "24.22.0\n", pins.RuleNode},
		{"Dockerfile", "FROM node:24.22.0\n", pins.RuleNode},
		{"requirements.txt", "pycurl==7.48.0\n", pins.RuleDependency},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		f := only(t, root, c.rule)
		p := filepath.Join(root, c.file)

		os.WriteFile(p, []byte(big(c.body)), 0o644)
		ch, already, err := plan(root, f)
		mustDecline(t, c.file+" oversized", ch, already, err)

		os.Remove(p)
		write(t, root, map[string]string{"real/" + c.file: c.body})
		if err := os.Symlink(filepath.Join("real", c.file), p); err != nil {
			t.Fatal(err)
		}
		ch, already, err = plan(root, f)
		mustDecline(t, c.file+" now a symbolic link", ch, already, err)
	}
}

// A lockfile, project or global.json that does not parse this time was
// not checked, and the scan says so.
func TestPlanUnparseableJSON(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ file, body, rule string }{
		{"web/package-lock.json", "{\n  \"packages\": {\n    \"node_modules/iltorb\": {\n      \"version\": \"2.4.5\"\n    }\n  }\n}\n", pins.RuleDependency},
		{"npm-shrinkwrap.json", "{\n  \"packages\": {\n    \"node_modules/iltorb\": {\n      \"version\": \"2.4.5\"\n    }\n  }\n}\n", pins.RuleDependency},
		{"svc/packages.lock.json", depsRepo["svc/packages.lock.json"], pins.RuleDotnet},
		{"global.json", "{\n  \"sdk\": {\n    \"version\": \"8.0.415\"\n  }\n}\n", pins.RuleDotnet},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		f := only(t, root, c.rule)
		write(t, root, map[string]string{c.file: c.body[:len(c.body)/2]})
		ch, already, err := plan(root, f)
		mustDecline(t, c.file+" not valid JSON", ch, already, err)
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Skips) != 1 || res.Skips[0].File != c.file || !strings.Contains(res.Skips[0].Reason, "not valid JSON") {
			t.Errorf("%s: the scan does not report it as not checked: %v %+v", c.file, err, res.Skips)
		}
	}
}

// A finding whose line is past the end of the file, or whose line now pins
// another release without the fix, is not fixed: the file changed since
// the scan.
func TestPlanStaleLine(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22 AS a\nRUN true\nFROM node:24.22.0 AS b\n"})
	f := only(t, root, pins.RuleNode)
	// Cut short, and the pin moved to line 1 at another vulnerable release.
	write(t, root, map[string]string{"Dockerfile": "FROM node:24.21.0\n"})
	ch, already, err := plan(root, f)
	mustDecline(t, "past the end", ch, already, err)
	// Cut short, nothing left to pin: the line still is not there to check.
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22\n"})
	ch, already, err = plan(root, f)
	mustDecline(t, "past the end, no pin", ch, already, err)

	write(t, root, map[string]string{".nvmrc": "22.23.1\n"})
	only(t, root, pins.RuleNode)
	write(t, root, map[string]string{".nvmrc": "22.23.2\n"})
	n := pins.Finding{File: ".nvmrc", Line: 1, Rule: pins.RuleNode, Props: map[string]string{"current": "22.23.1", "source": "nvmrc"}}
	ch, already, err = plan(root, n)
	mustDecline(t, "another vulnerable release on the line", ch, already, err)
}

// A cancelled plan read nothing to the end.
func TestPlanCancelled(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"install.sh": "export NODE_VERSION=24.22.0\n"})
	f := only(t, root, pins.RuleNode)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, already, err := pins.Plan(ctx, root, f.File, f.Line, f.Rule, f.Props)
	if already || ch != nil || err == nil {
		t.Fatalf("cancelled: change %+v, already %v, err %v", ch, already, err)
	}
}

// A root that is not there is not a repository with nothing in it.
func TestPlanMissingRoot(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{".nvmrc": "22.23.1\n"})
	f := only(t, root, pins.RuleNode)
	ch, already, err := plan(filepath.Join(root, "nope"), f)
	if already || ch != nil || err == nil {
		t.Fatalf("missing root: change %+v, already %v, err %v", ch, already, err)
	}
}

// What was checked and is really gone still reads as already fixed.
func TestPlanCheckedAndGone(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"install.sh": "export NODE_VERSION=24.22.0\n",
		"Dockerfile": "FROM node:24.22.0 AS a\nFROM node:22.23.1 AS b\n",
		".nvmrc":     "22.23.1\n",
	})
	res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
	if err != nil || len(res.Findings) != 4 || len(res.Skips) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	write(t, root, map[string]string{
		"install.sh": "export NODE_VERSION=24.22.1\n",
		"Dockerfile": "FROM node:24.22.1 AS a\nFROM node:22.23.1 AS b\n",
		".nvmrc":     "lts/*\n",
	})
	at := map[string]pins.Finding{}
	for _, f := range res.Findings {
		at[f.File+":"+itoa(f.Line)] = f
	}
	for _, k := range []string{".nvmrc:1", "Dockerfile:1", "install.sh:1"} {
		ch, already, err := plan(root, at[k])
		mustBeGone(t, k, ch, already, err)
	}
	// The pin left in place is still found.
	if _, already, err := plan(root, at["Dockerfile:2"]); already {
		t.Fatalf("Dockerfile:2: already %v, err %v", already, err)
	}
	// A deleted file has no pins left.
	os.Remove(filepath.Join(root, "install.sh"))
	ch, already, err := plan(root, at["install.sh:1"])
	mustBeGone(t, "install.sh deleted", ch, already, err)
	os.Remove(filepath.Join(root, "Dockerfile"))
	ch, already, err = plan(root, at["Dockerfile:2"])
	mustBeGone(t, "Dockerfile deleted", ch, already, err)
	// A line 0 finding (the scan did not know the line) is checked by the
	// whole file.
	f := at[".nvmrc:1"]
	f.Line = 0
	ch, already, err = plan(root, f)
	mustBeGone(t, ".nvmrc line 0", ch, already, err)
}
