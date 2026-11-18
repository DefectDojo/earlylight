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

// A finding whose line is past the end of a file that still pins another
// release without the fix, or whose line now pins one, is not fixed: the
// file changed since the scan.
func TestPlanStaleLine(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22 AS a\nRUN true\nFROM node:24.22.0 AS b\n"})
	f := only(t, root, pins.RuleNode)
	// Cut short, and the pin moved to line 1 at another vulnerable release.
	write(t, root, map[string]string{"Dockerfile": "FROM node:24.21.0\n"})
	ch, already, err := plan(root, f)
	mustDecline(t, "past the end", ch, already, err)
	// Cut short, nothing left to pin: read in full, the pin is gone.
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22\n"})
	ch, already, err = plan(root, f)
	mustBeGone(t, "past the end, no pin", ch, already, err)

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

// Removing the pin's line is a fix wherever the line sat, the last line
// included, as long as nothing of that rule is left in the file.
func TestPlanRemovedLastLine(t *testing.T) {
	for _, c := range []struct{ file, body, now, rule string }{
		{"tools/.tool-versions", "python 3.13.1\nnodejs 22.23.1\n", "python 3.13.1\n", pins.RuleNode},
		{"requirements.txt", "requests==2.32.3\npycurl==7.48.0\n", "requests==2.32.3\n", pins.RuleDependency},
		{".nvmrc", "22.23.1\n", "", pins.RuleNode},
		{"Dockerfile", "FROM alpine:3.22 AS a\nRUN true\nFROM node:24.22.0 AS b\n", "FROM alpine:3.22 AS a\nRUN true\n", pins.RuleNode},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		f := only(t, root, c.rule)
		write(t, root, map[string]string{c.file: c.now})
		ch, already, err := plan(root, f)
		mustBeGone(t, c.file+" last line removed", ch, already, err)
	}
}

// A line 0 finding (the scan did not know the line) is not gone while the
// file pins any release of that rule without the fix.
func TestPlanLineZeroStillPinned(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{".nvmrc": "22.23.2\n"})
	f := pins.Finding{File: ".nvmrc", Line: 0, Rule: pins.RuleNode, Props: map[string]string{"current": "22.23.1", "source": "nvmrc"}}
	ch, already, err := plan(root, f)
	mustDecline(t, "line 0, another vulnerable release", ch, already, err)
}

// Plan reads a path in any form the scan would have cleaned to the same file.
func TestPlanPathForms(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{
		"Dockerfile":       "FROM node:24.22.0\n",
		"svc/compose.yaml": "services:\n  web:\n    image: node:24.22.0\n",
		".nvmrc":           "22.23.1\n",
	})
	for _, c := range []struct {
		file string
		line int
	}{{"./Dockerfile", 1}, {"svc/../Dockerfile", 1}, {"svc//compose.yaml", 3}, {"./svc/compose.yaml", 3}, {"./.nvmrc", 1}} {
		ch, already, err := pins.Plan(context.Background(), root, c.file, c.line, pins.RuleNode, nil)
		if already {
			t.Errorf("%s: an untouched vulnerable pin reads as already fixed (change %+v, err %v)", c.file, ch, err)
		}
	}
	ch, _, err := pins.Plan(context.Background(), root, "./.nvmrc", 1, pins.RuleNode, nil)
	if err != nil || ch == nil || ch.File != ".nvmrc" {
		t.Errorf("./.nvmrc: change %+v, err %v", ch, err)
	}
}

// A file whose directory was deleted is deleted. What cannot be read never
// names the checkout's absolute path.
func TestPlanDirectoryDeleted(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"svc/.nvmrc": "22.23.1\n"})
	f := only(t, root, pins.RuleNode)
	os.RemoveAll(filepath.Join(root, "svc"))
	ch, already, err := plan(root, f)
	mustBeGone(t, "directory removed", ch, already, err)

	long := strings.Repeat("a", 300) + "/.nvmrc" // the directory name is too long to look up
	ch, already, err = pins.Plan(context.Background(), root, long, 1, pins.RuleNode, nil)
	mustDecline(t, "name too long", ch, already, err)
	if err != nil && strings.Contains(err.Error(), root) {
		t.Errorf("the message names the absolute path: %v", err)
	}
	_, _, err = pins.Plan(context.Background(), filepath.Join(root, "nope"), ".nvmrc", 1, pins.RuleNode, nil)
	if err == nil || strings.Contains(err.Error(), root) {
		t.Errorf("missing root: %v", err)
	}
}

// Which skips hold back "already fixed": one on the whole file, or one on
// the finding's own line. A skip on another line of the file is about
// another pin, and is reported on its own.
func TestPlanSkipScope(t *testing.T) {
	digest := "FROM node@sha256:" + strings.Repeat("a", 64)
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": digest + " AS a\nFROM node:24.22.0 AS b\n"})
	f := only(t, root, pins.RuleNode)
	if f.Line != 2 {
		t.Fatalf("%+v", f)
	}
	// Fixed; the digest-only stage on line 1 is still not checked.
	write(t, root, map[string]string{"Dockerfile": digest + " AS a\nFROM node:24.22.1 AS b\n"})
	ch, already, err := plan(root, f)
	mustBeGone(t, "skip on another line", ch, already, err)
	// Line 2 itself is digest only now.
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22 AS a\n" + digest + " AS b\n"})
	ch, already, err = plan(root, f)
	mustDecline(t, "skip on the finding's line", ch, already, err)
	if d, ok := pins.IsDeclined(err); ok && !strings.Contains(d.Reason, "line 2") {
		t.Errorf("the decline does not name the line: %q", d.Reason)
	}
	// A line 0 finding is held back by a skip on any line.
	g := f
	g.Line = 0
	ch, already, err = plan(root, g)
	mustDecline(t, "line 0 with a skip in the file", ch, already, err)
	// The finding's line is past the end now: a skip on any line of the
	// file may be where its pin went.
	write(t, root, map[string]string{"Dockerfile": digest + " AS b\n"})
	ch, already, err = plan(root, f)
	mustDecline(t, "past the end with a skip in the file", ch, already, err)
	// A skip on the whole file holds back every finding in it.
	write(t, root, map[string]string{"package.json": "{\n  \"volta\": {\n    \"node\": \"24.22.0\"\n  }\n}\n"})
	v := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{"package.json": "{\n  \"volta\": {\n    \"node\": \"24.22.1\"\n  }\n}\n,"})
	ch, already, err = plan(root, v)
	mustDecline(t, "skip on the whole file", ch, already, err)
}

// global.json may carry comments and a byte-order mark, which the .NET SDK
// accepts; package.json and packages.lock.json may start with a byte-order
// mark. They are read, not reported as not checked.
func TestJSONCommentsAndBOM(t *testing.T) {
	ctx := context.Background()
	bom := "\ufeff"
	for _, c := range []struct {
		file, body string
		line       int
		rule, want string
	}{
		{"global.json", bom + "{\n  // pinned for the build agents, see https://example.com/x\n  \"sdk\": {\n    /* \"version\": \"8.0.100\" */ \"version\": \"8.0.415\",\n    \"rollForward\": \"disable\"\n  }\n}\n",
			4, pins.RuleDotnet, `    /* "version": "8.0.100" */ "version": "8.0.427",`},
		{"app/package.json", bom + "{\n  \"volta\": {\n    \"node\": \"24.22.0\"\n  }\n}\n", 3, pins.RuleNode, `    "node": "24.22.1"`},
		{"svc/packages.lock.json", bom + depsRepo["svc/packages.lock.json"], 0, pins.RuleDotnet, ""},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Skips) != 0 || len(res.Findings) != 1 || res.Findings[0].Rule != c.rule {
			t.Errorf("%s: %v findings %+v skips %+v", c.file, err, res.Findings, res.Skips)
			continue
		}
		f := res.Findings[0]
		if c.line != 0 && f.Line != c.line {
			t.Errorf("%s: line %d, want %d", c.file, f.Line, c.line)
		}
		if c.want == "" {
			continue
		}
		ch, _, err := plan(root, f)
		if err != nil || ch == nil || ch.Edits[0].New[0] != c.want {
			t.Errorf("%s: change %+v, err %v", c.file, ch, err)
		}
	}
	// Fixed, or without an sdk key, a commented global.json is clean.
	for _, body := range []string{"{\n  // fixed\n  \"sdk\": { \"version\": \"8.0.427\" }\n}\n", "/* tools only */ { \"msbuild-sdks\": {} }\n"} {
		root := t.TempDir()
		write(t, root, map[string]string{"global.json": body})
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Skips) != 0 || len(res.Findings) != 0 {
			t.Errorf("%q: %v %+v", body, err, res)
		}
	}
}

// A lockfile that is not read says why: not JSON, JSON of another shape, or
// a lockfile version the scan does not read.
func TestLockfileSkipReasons(t *testing.T) {
	for _, c := range []struct{ file, body, want string }{
		{"package-lock.json", "{\"packages\": {", "not valid JSON: unexpected end"},
		{"package-lock.json", "{\"packages\": []}", "not the expected shape"},
		{"package-lock.json", "{\"lockfileVersion\": 1, \"dependencies\": {\"iltorb\": {\"version\": \"2.4.5\"}}}", "lockfileVersion 1"},
		{"packages.lock.json", "{\"dependencies\": []}", "not the expected shape"},
		{"Pipfile.lock", "{\"default\": [", "not valid JSON: unexpected end"},
		{"Pipfile.lock", "{\"default\": []}", "not the expected shape"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
		if err != nil || len(res.Skips) != 1 || !strings.Contains(res.Skips[0].Reason, c.want) {
			t.Errorf("%s %q: %v skips %+v, want a reason with %q", c.file, c.body, err, res.Skips, c.want)
		}
	}
	// A lockfile with nothing in it is read, not skipped.
	root := t.TempDir()
	write(t, root, map[string]string{"package-lock.json": "{\"name\": \"x\", \"lockfileVersion\": 3, \"packages\": {}}"})
	if res, err := pins.Scan(context.Background(), root, nil, pins.Options{}); err != nil || len(res.Skips) != 0 {
		t.Errorf("empty lockfile: %v %+v", err, res.Skips)
	}
}

// An image pin that moved off its line and became a reference the scan
// cannot judge (an ARG with no default, an image pinned by digest only)
// is not fixed: the skip on its new line holds back "already fixed"
// unless a resolved image still sits on the finding's own line.
func TestPlanImageMovedAndUnresolved(t *testing.T) {
	digest := "node@sha256:" + strings.Repeat("a", 64)
	for _, c := range []struct{ what, now string }{
		{"an ARG with no default", "ARG NODE_VERSION\nFROM node:${NODE_VERSION}\n"},
		{"a syntax line above a digest-only FROM", "# syntax=docker/dockerfile:1\nFROM " + digest + "\n"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{"Dockerfile": "FROM node:24.22.0\n"})
		f := only(t, root, pins.RuleNode)
		write(t, root, map[string]string{"Dockerfile": c.now})
		ch, already, err := plan(root, f)
		mustDecline(t, c.what, ch, already, err)
		// Without the finding's props the plan cannot tell an image pin
		// from another: it holds back too.
		ch, already, err = pins.Plan(context.Background(), root, f.File, f.Line, f.Rule, nil)
		mustDecline(t, c.what+", no props", ch, already, err)
	}
	// Fixed in place, with an unresolved stage elsewhere: fixed.
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "FROM node:24.22.0 AS a\nARG BASE\nFROM ${BASE} AS b\n"})
	f := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{"Dockerfile": "FROM node:24.22.1 AS a\nARG BASE\nFROM ${BASE} AS b\n"})
	ch, already, err := plan(root, f)
	mustBeGone(t, "fixed in place", ch, already, err)
	// A text pin is not an image: a skip on another line does not hold it.
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22\nENV NODE_VERSION=24.22.0\nFROM " + digest + "\n"})
	g := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{"Dockerfile": "FROM alpine:3.22\nENV NODE_VERSION=24.22.1\nFROM " + digest + "\n"})
	ch, already, err = plan(root, g)
	mustBeGone(t, "a text pin fixed in place", ch, already, err)
}

// The comment reader leaves strings alone and keeps every line break, and
// the text patterns read what it leaves: a URL in a JSON string is not a
// comment, and a pin inside a comment is not a pin.
func TestJSONTextKeepsStringsAndLines(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	write(t, root, map[string]string{
		"app/package.json": "{\n  \"homepage\": \"https://example.com/a//b\",\n  \"repository\": \"git://x/*not a comment*/\",\n  \"volta\": {\n    \"node\": \"24.22.0\"\n  }\n}\n",
		"global.json":      "{\n  /* the SDK\n     for the build\n     agents */\n  \"sdk\": {\n    \"version\": \"8.0.415\"\n  }\n}\n",
		"tools.json":       "{\n  // was \"https://nodejs.org/dist/v24.21.0/node.tar.gz\"\n  \"url\": \"https://nodejs.org/dist/v24.22.0/node.tar.gz\"\n}\n",
	})
	res, err := pins.Scan(ctx, root, nil, pins.Options{})
	if err != nil || len(res.Skips) != 0 {
		t.Fatalf("%v %+v", err, res.Skips)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.File+":"+itoa(f.Line)] = f.Props["current"]
	}
	want := map[string]string{"app/package.json:5": "24.22.0", "global.json:6": "8.0.415", "tools.json:3": "24.22.0"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	for _, f := range res.Findings {
		if f.File == "tools.json" {
			continue
		}
		ch, _, err := plan(root, f)
		if err != nil || ch == nil || ch.Edits[0].Line != f.Line {
			t.Errorf("%s:%d: change %+v, err %v", f.File, f.Line, ch, err)
		}
	}
}

// A byte-order mark is not part of line 1: the column does not count it.
func TestBOMColumn(t *testing.T) {
	body := `{"volta":{"node":"24.22.0"}}`
	root := t.TempDir()
	write(t, root, map[string]string{"package.json": "\ufeff" + body})
	f := only(t, root, pins.RuleNode)
	if want := itoa(strings.Index(body, "24.22.0") + 1); f.Props["column"] != want {
		t.Errorf("column %q, want %q", f.Props["column"], want)
	}
	ch, _, err := plan(root, f)
	if err != nil || ch == nil || ch.Edits[0].New[0] != "\ufeff"+`{"volta":{"node":"24.22.1"}}` {
		t.Errorf("change %+v, err %v", ch, err)
	}
}

// A lockfileVersion 1 package-lock.json with no dependencies has nothing
// to read: it is not reported as not checked.
func TestLockfileV1Empty(t *testing.T) {
	for _, body := range []string{`{"lockfileVersion": 1, "dependencies": {}}`, `{"lockfileVersion": 1}`} {
		root := t.TempDir()
		write(t, root, map[string]string{"package-lock.json": body})
		if res, err := pins.Scan(context.Background(), root, nil, pins.Options{}); err != nil || len(res.Skips) != 0 {
			t.Errorf("%s: %v %+v", body, err, res.Skips)
		}
	}
}

func TestScrub(t *testing.T) {
	for _, c := range []struct{ root, in, want string }{
		{"/w/repo", "lstat /w/repo/svc: no such file or directory", "lstat svc: no such file or directory"},
		{"/w/repo/", "open /w/repo/a.json: denied", "open a.json: denied"},
		{"/w/repo", "the root /w/repo is gone", "the root . is gone"},
		{".", "lstat svc: x", "lstat svc: x"},
	} {
		if got := pins.Scrub(c.root, c.in); got != c.want {
			t.Errorf("Scrub(%q, %q) = %q, want %q", c.root, c.in, got, c.want)
		}
	}
}
