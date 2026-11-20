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

// A pin that moved to another line and became a value the scan cannot
// judge is not fixed, even when another value lands on its old line: only
// a value of the finding's own rule judged on its line clears it.
func TestPlanMovedOntoAnotherValue(t *testing.T) {
	digest := "node@sha256:" + strings.Repeat("a", 64)
	k8s := func(first, second string) string {
		return "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n  - name: " + first + "\n  - name: " + second + "\n"
	}
	wf := "on: push\njobs:\n  test:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 24.22.0\n"
	for _, c := range []struct{ what, file, was, now string }{
		{"an ARG with no default, another image on the old line", "Dockerfile",
			"FROM golang:1.25 AS build\nFROM node:24.22.0\n", "ARG NODE_VERSION\nFROM golang:1.25 AS build\nFROM node:${NODE_VERSION}\n"},
		{"a digest-only FROM pushed down two lines", "Dockerfile",
			"FROM golang:1.25 AS build\nFROM node:24.22.0\n", "FROM alpine:3.22 AS a\nFROM golang:1.25 AS build\nRUN true\nFROM " + digest + "\n"},
		{"Compose services reordered, the tag now unset", "compose.yaml",
			"services:\n  web:\n    image: node:24.22.0\n  db:\n    image: postgres:16\n", "services:\n  db:\n    image: postgres:16\n  web:\n    image: node:${NODE_TAG}\n"},
		{"Kubernetes containers reordered, the tag now $(TAG)", "pod.yaml",
			k8s("a\n    image: node:24.22.0", "b\n    image: redis:7"), k8s("b\n    image: redis:7", "a\n    image: node:$(TAG)")},
		{"GitLab jobs reordered, the tag now $NODE_TAG", ".gitlab-ci.yml",
			"build:\n  image: node:24.22.0\n  script: [x]\nlint:\n  image: python:3.13\n  script: [y]\n", "lint:\n  image: python:3.13\n  script: [y]\nbuild:\n  image: node:$NODE_TAG\n  script: [x]\n"},
		{"a distroless line image now built from a variable", "Dockerfile",
			"FROM golang:1.25 AS b\nFROM gcr.io/distroless/nodejs20-debian12\n", "ARG V\nFROM golang:1.25 AS b\nFROM gcr.io/distroless/nodejs${V}-debian12\n"},
		{"setup-node under a matrix the scan cannot resolve", ".github/workflows/ci.yml",
			wf, "on: push\njobs:\n  test:\n    strategy:\n      matrix: ${{ fromJSON(needs.x.outputs.m) }}\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.node }}\n"},
		{"setup-node from an env value that is not set", ".github/workflows/ci.yml",
			wf, "on: push\njobs:\n  test:\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ env.NODE_VERSION }}\n"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.was})
		f := only(t, root, pins.RuleNode)
		write(t, root, map[string]string{c.file: c.now})
		res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
		if err != nil || len(res.Skips) == 0 {
			t.Errorf("%s: the rewrite is not a skip: %v %+v", c.what, err, res)
			continue
		}
		ch, already, err := plan(root, f)
		mustDecline(t, c.what, ch, already, err)
	}
}

// In a JSON file that is not strict JSON (single quotes, an unterminated
// comment), the text patterns read the file as written: what the comment
// reader cannot follow is not taken as a comment.
func TestTextPatternsInLooseJSON(t *testing.T) {
	for _, c := range []struct{ file, body, current string }{
		{"tools.json", "{'url': 'https://nodejs.org/dist/v24.22.0/node.tar.gz'}\n", "24.22.0"},
		{"tasks.json", "{ files: ['src/*.ts'], \"setup\": \"nvm install 24.22.0\" }\n", "24.22.0"},
		{"cdk.json", "{\n  'context': {\n    'install': 'curl -fsSL https://deb.nodesource.com/setup_20.x | bash'\n  }\n}\n", "20"},
		{"loose.json", "{ /* open\n\"setup\": \"nvm install 24.22.0\" }\n", "24.22.0"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		f := only(t, root, pins.RuleNode)
		if f.Props["current"] != c.current {
			t.Errorf("%s: %+v", c.file, f)
		}
	}
}

// The column counts no byte-order mark, and only on line 1: a file without
// one keeps every column, and a later line of a file with one too. A
// Dockerfile-prod is read only as an image file, and is no exception.
func TestColumnsAndBOM(t *testing.T) {
	for _, c := range []struct{ file, body, value string }{
		{"package.json", `{"volta":{"node":"24.22.0"}}`, `{"volta":{"node":"24.22.0"}}`},
		{"Dockerfile-prod", "\ufeffFROM node:24.22.0\n", "FROM node:24.22.0"},
		{"Dockerfile_prod", "\ufeffFROM node:24.22.0\n", "FROM node:24.22.0"},
		{"svc/package.json", "\ufeff{\n  \"volta\": {\n    \"node\": \"24.22.0\"\n  }\n}\n", `    "node": "24.22.0"`},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		f := only(t, root, pins.RuleNode)
		if want := itoa(strings.Index(c.value, "24.22.0") + 1); f.Props["column"] != want {
			t.Errorf("%s line %d: column %q, want %q", c.file, f.Line, f.Props["column"], want)
		}
	}
}

// A lockfileVersion 1 "dependencies" of another shape is not checked, and
// says so.
func TestLockfileV1DependenciesShape(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{"package-lock.json": `{"lockfileVersion": 1, "dependencies": [1]}`})
	res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
	if err != nil || len(res.Skips) != 1 || !strings.Contains(res.Skips[0].Reason, "dependencies: not the expected shape") {
		t.Errorf("%v %+v", err, res.Skips)
	}
}

// scrub removes only an absolute checkout path, and only where it is a
// whole path: a relative root, or the root's name inside another path or
// word, is left alone.
func TestScrubBoundaries(t *testing.T) {
	for _, c := range []struct{ root, in, want string }{
		{"/", "open /a.json: denied", "open /a.json: denied"},
		{".", "open ./a.json: denied", "open ./a.json: denied"},
		{"repo", "open repo/a.json: the repository is gone", "open repo/a.json: the repository is gone"},
		{"/app", "gcr.io/app/web is pinned by digest only", "gcr.io/app/web is pinned by digest only"},
		{"/app", "lstat /app/svc: x; /application is not /app", "lstat svc: x; /application is not ."},
		{"/app", `"/app/a.json" is not read`, `"a.json" is not read`},
	} {
		if got := pins.Scrub(c.root, c.in); got != c.want {
			t.Errorf("Scrub(%q, %q) = %q, want %q", c.root, c.in, got, c.want)
		}
	}
}

// A value of the same rule but another source on the pin's old line (a
// .NET SDK image where the aspnet image was, an ARG NODE_VERSION where
// the node image was) is not the pin: a skip elsewhere still holds it.
func TestPlanSameRuleOtherSource(t *testing.T) {
	for _, c := range []struct{ what, was, now string }{
		{"an SDK image on the aspnet image's line",
			"FROM mcr.microsoft.com/dotnet/sdk:8.0.415 AS build\nFROM mcr.microsoft.com/dotnet/aspnet:8.0.32\n",
			"ARG V\nFROM mcr.microsoft.com/dotnet/sdk:8.0.427 AS build\nFROM mcr.microsoft.com/dotnet/aspnet:${V}\n"},
		{"an ARG NODE_VERSION on the node image's line",
			"FROM golang:1.25 AS b\nFROM node:24.22.0\n",
			"FROM golang:1.25 AS b\nARG NODE_VERSION=24.22.1\nFROM ${BASE}\n"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{"Dockerfile": c.was})
		res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var f *pins.Finding
		for i := range res.Findings {
			if res.Findings[i].Line == 2 {
				f = &res.Findings[i]
			}
		}
		if f == nil {
			t.Fatalf("%s: %+v", c.what, res.Findings)
		}
		write(t, root, map[string]string{"Dockerfile": c.now})
		ch, already, err := plan(root, *f)
		mustDecline(t, c.what, ch, already, err)
	}
}

// A value the scan could not judge (a range, an expression) on the pin's
// line is not a judged value there.
func TestPlanUnjudgedValueOnTheLine(t *testing.T) {
	root := t.TempDir()
	job := func(name, version string) string {
		return "  " + name + ":\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: " + version + "\n"
	}
	write(t, root, map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n" + job("a", "24.22.0") + job("b", "'>=22 <25'")})
	f := only(t, root, pins.RuleNode)
	if f.Line != 8 {
		t.Fatalf("%+v", f)
	}
	write(t, root, map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n" + job("b", "'>=22 <25'") + job("a", "${{ env.NODE_VERSION }}")})
	ch, already, err := plan(root, f)
	mustDecline(t, "a range on the line, the pin now an unset env value", ch, already, err)
}

// A pin changed in place to an expression the scan does not resolve is
// not checked, and is reported so: it never reads as fixed.
func TestExpressionInPlace(t *testing.T) {
	setup := func(v string) string {
		return "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: " + v + "\n"
	}
	envWF := func(v string) string {
		return "on: push\nenv:\n  NODE_VERSION: " + v + "\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ env.NODE_VERSION }}\n"
	}
	matrix := func(v string) string {
		return "on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix:\n        n: " + v + "\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.n }}\n"
	}
	circle := func(v string) string {
		return "version: 2.1\njobs:\n  build:\n    docker:\n      - image: cimg/node:" + v + "\n    steps: [checkout]\n"
	}
	azure := func(v string) string {
		return "steps:\n- task: NodeTool@0\n  inputs:\n    versionSpec: '" + v + "'\n"
	}
	for _, c := range []struct{ what, file, was, now string }{
		{"node-version from vars", ".github/workflows/ci.yml", setup("24.22.0"), setup("${{ vars.NODE }}")},
		{"node-version from inputs", ".github/workflows/ci.yml", setup("24.22.0"), setup("${{ inputs.node }}")},
		{"workflow env from vars", ".github/workflows/ci.yml", envWF("24.22.0"), envWF("${{ vars.X }}")},
		{"matrix from fromJSON", ".github/workflows/ci.yml", matrix("[24.22.0]"), matrix("${{ fromJSON(needs.x.outputs.m) }}")},
		{"CircleCI image parameter", ".circleci/config.yml", circle("24.22.0"), circle("<< parameters.tag >>")},
		{"Azure versionSpec variable", "azure-pipelines.yml", azure("24.22.0"), azure("$(nodeVersion)")},
		{".nvmrc variable", ".nvmrc", "24.22.0\n", "${NODE_VERSION}\n"},
		{"ENV from a build variable", "Dockerfile", "FROM debian:12\nENV NODE_VERSION=24.22.0\n", "FROM debian:12\nENV NODE_VERSION=$BUILD_NODE\n"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.was})
		f := only(t, root, pins.RuleNode)
		write(t, root, map[string]string{c.file: c.now})
		res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
		if err != nil || len(res.Skips) != 1 || res.Skips[0].Line != f.Line {
			t.Errorf("%s: want one not-checked item on line %d: %v %+v", c.what, f.Line, err, res.Skips)
		}
		ch, already, err := plan(root, f)
		mustDecline(t, c.what, ch, already, err)
	}
	// A variable the file sets to a release is read where it is set: the
	// reference to it is no gap.
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "ARG NODE_VERSION=24.22.1\nFROM debian:12\nARG NODE_VERSION\nENV NODE_VERSION=$NODE_VERSION\n"})
	if res, err := pins.Scan(context.Background(), root, nil, pins.Options{}); err != nil || len(res.Skips) != 0 || len(res.Findings) != 0 {
		t.Errorf("a set variable: %v %+v", err, res)
	}
}

// The judged record covers line images, line text patterns and every
// rule, keyed by the rule and the line it was found on.
func TestPlanJudgedRecord(t *testing.T) {
	digest := "FROM node@sha256:" + strings.Repeat("a", 64)
	for _, c := range []struct {
		what, was, now string
		line           int
		rule           string
		gone           bool
	}{
		{"a line image fixed in place", "FROM gcr.io/distroless/nodejs20-debian12 AS a\n" + digest + " AS b\n",
			"FROM gcr.io/distroless/nodejs22-debian12 AS a\n" + digest + " AS b\n", 1, pins.RuleNode, true},
		{"a NodeSource line fixed in place", digest + "\nRUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash\n",
			digest + "\nRUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash\n", 2, pins.RuleNode, true},
		{"a .NET image fixed in place", "FROM mcr.microsoft.com/dotnet/aspnet:8.0.32 AS a\n" + digest + " AS b\n",
			"FROM mcr.microsoft.com/dotnet/aspnet:8.0.33 AS a\n" + digest + " AS b\n", 1, pins.RuleDotnet, true},
		{"a node pin whose line now holds a .NET image", "FROM node:24.22.0 AS a\n",
			"FROM mcr.microsoft.com/dotnet/aspnet:8.0.33 AS a\nARG V\nFROM node:${V}\n", 1, pins.RuleNode, false},
		{"a judged value on the next line, not on the pin's", digest + " AS a\nFROM node:24.22.0 AS b\n",
			digest + " AS a\nRUN true\nFROM node:24.22.1 AS b\n", 2, pins.RuleNode, false},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{"Dockerfile": c.was})
		f := only(t, root, c.rule)
		if f.Line != c.line {
			t.Fatalf("%s: %+v", c.what, f)
		}
		write(t, root, map[string]string{"Dockerfile": c.now})
		// With the finding's props and without them.
		for _, props := range []map[string]string{f.Props, nil} {
			ch, already, err := pins.Plan(context.Background(), root, f.File, f.Line, f.Rule, props)
			if c.gone {
				mustBeGone(t, c.what, ch, already, err)
			} else {
				mustDecline(t, c.what, ch, already, err)
			}
		}
	}
	// A skip on the pin's own line holds it even beside a judged value of
	// its rule on that line.
	root := t.TempDir()
	pod := func(a, b string) string {
		return "apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec:\n  containers: [{name: a, image: " + a + "}, {name: b, image: " + b + "}]\n"
	}
	write(t, root, map[string]string{"pod.yaml": pod("node:24.22.0", "redis:7")})
	f := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{"pod.yaml": pod("node:24.22.1", "node:$(TAG)")})
	ch, already, err := plan(root, f)
	mustDecline(t, "a skip beside a judged value on the line", ch, already, err)
}

// A pin changed in place to a value the scan does not resolve never reads
// as fixed, whether or not an ordinary scan lists it as not checked: a
// shell variable in a command or a URL is left to the plan, a version
// variable set from a build argument nobody sets is listed.
func TestInPlaceExpressionNeverFixed(t *testing.T) {
	ctx := context.Background()
	wf := func(v string) string {
		return "on: push\nenv:\n  NODE_VERSION: " + v + "\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo hi\n"
	}
	for _, c := range []struct {
		what, file, was, now string
		skips                int
	}{
		{"ENV from an ARG that holds a vulnerable release", "Dockerfile", "FROM debian:12\nENV NODE_VERSION=24.22.0\n", "ARG OTHER=24.22.0\nENV NODE_VERSION=$OTHER\n", 0},
		{"ENV from an unset ARG, another ARG holding a release", "Dockerfile", "FROM debian:12\nENV NODE_VERSION=24.22.0\n", "ARG NODE_VERSION=24.22.1\nENV NODE_VERSION=$OTHER\n", 1},
		{"nvm install $V", "install.sh", "nvm install 24.22.0\n", "nvm install $V\n", 0},
		{"a download URL with ${V}", "install.sh", "curl -fsSL https://nodejs.org/dist/v24.22.0/SHASUMS256.txt\n", "curl -fsSL https://nodejs.org/dist/v${V}/SHASUMS256.txt\n", 0},
		{"nvm install $(cat .nvmrc)", "install.sh", "nvm install 24.22.0\n", "nvm install $(cat .nvmrc)\n", 0},
		{"a workflow env value no setup step reads", ".github/workflows/ci.yml", wf("24.22.0"), wf("${{ vars.N }}"), 0},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.was})
		f := only(t, root, pins.RuleNode)
		write(t, root, map[string]string{c.file: c.now})
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Skips) != c.skips {
			t.Errorf("%s: want %d not-checked items, got %v %+v", c.what, c.skips, err, res.Skips)
		}
		// Declined, or planned where the pin still is: never already fixed.
		if _, already, err := plan(root, f); already {
			t.Errorf("%s: already fixed (err %v)", c.what, err)
		} else if _, ok := pins.IsDeclined(err); err != nil && !ok {
			t.Errorf("%s: %v", c.what, err)
		}
	}
}

// An ordinary scan reads what it can: an ENV set from an ARG in the same
// Dockerfile is judged by the ARG's value (and fixed there), a ${X:-d}
// default is judged, and a commented-out line is not read.
func TestVersionVariablesResolved(t *testing.T) {
	ctx := context.Background()
	scan := func(files map[string]string) pins.Result {
		t.Helper()
		root := t.TempDir()
		write(t, root, files)
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	type want struct {
		line    int
		current string
	}
	for _, c := range []struct {
		what, file, body string
		want             []want
	}{
		{"ENV from a fixed ARG", "Dockerfile", "ARG NODE_VERSION=24.22.1\nFROM debian:12\nARG NODE_VERSION\nENV NODE_VERSION=$NODE_VERSION\n", nil},
		{"ENV from a vulnerable ARG of another name", "Dockerfile", "ARG BUILD_NODE=24.22.0\nFROM debian:12\nARG BUILD_NODE\nENV NODE_VERSION=$BUILD_NODE\n", []want{{4, "24.22.0"}}},
		{"ENV from a vulnerable ARG of its name: one finding", "Dockerfile", "ARG NODE_VERSION=24.22.0\nFROM debian:12\nARG NODE_VERSION\nENV NODE_VERSION=${NODE_VERSION}\n", []want{{1, "24.22.0"}}},
		{"ENV from the ARG the FROM reads: the image finding", "Dockerfile", "ARG NODE_VERSION=24.22.0\nFROM node:${NODE_VERSION}\nARG NODE_VERSION\nENV NODE_VERSION=$NODE_VERSION\n", []want{{2, "24.22.0"}}},
		{"a fixed default", "Dockerfile", "FROM debian:12\nENV NODE_VERSION=${NODE_VERSION:-24.22.1}\n", nil},
		{"a vulnerable default", "Dockerfile", "FROM debian:12\nENV NODE_VERSION=${NODE_VERSION:-24.22.0}\n", []want{{2, "24.22.0"}}},
		{"commented-out lines", "Dockerfile", "# ENV NODE_VERSION=24.22.0\n# ENV NODE_VERSION=$UNSET\nFROM debian:12\n  # RUN nvm install 18\n", nil},
		{"a commented-out CDK runtime", "stack.ts", "// runtime: Runtime.NODEJS_16_X,\nconst ok = 1\n", nil},
		{"a live CDK runtime", "stack.ts", "new Function(this, 'f', { runtime: Runtime.NODEJS_16_X })\n", []want{{1, "16"}}},
	} {
		res := scan(map[string]string{c.file: c.body})
		if len(res.Skips) != 0 || len(res.Findings) != len(c.want) {
			t.Errorf("%s: findings %+v skips %+v", c.what, res.Findings, res.Skips)
			continue
		}
		for k, w := range c.want {
			if f := res.Findings[k]; f.Line != w.line || f.Props["current"] != w.current {
				t.Errorf("%s: %+v, want line %d current %s", c.what, f, w.line, w.current)
			}
		}
	}
	// The fix of an ENV that reads an ARG moves the ARG; of a default, the
	// default.
	for _, c := range []struct{ body, want string }{
		{"ARG BUILD_NODE=24.22.0\nFROM debian:12\nARG BUILD_NODE\nENV NODE_VERSION=$BUILD_NODE\n", "ARG BUILD_NODE=24.22.1"},
		{"FROM debian:12\nENV NODE_VERSION=${NODE_VERSION:-24.22.0}\n", "ENV NODE_VERSION=${NODE_VERSION:-24.22.1}"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{"Dockerfile": c.body})
		f := only(t, root, pins.RuleNode)
		ch, _, err := plan(root, f)
		if err != nil || ch == nil || ch.Edits[0].New[0] != c.want {
			t.Errorf("%q: change %+v, err %v", c.body, ch, err)
		}
	}
}

// What a fixed value records, and where an unreadable value is listed.
func TestJudgedAndListed(t *testing.T) {
	ctx := context.Background()
	// A fixed .tool-versions line is judged (add records every verdict),
	// and the variable on the next line is listed.
	root := t.TempDir()
	write(t, root, map[string]string{".tool-versions": "nodejs 24.22.0\nbun ${BUN}\n"})
	f := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{".tool-versions": "nodejs 24.22.1\nbun ${BUN}\n"})
	if res, err := pins.Scan(ctx, root, nil, pins.Options{}); err != nil || len(res.Skips) != 1 || res.Skips[0].Line != 2 {
		t.Errorf(".tool-versions: %v %+v", err, res.Skips)
	}
	ch, already, err := plan(root, f)
	mustBeGone(t, ".tool-versions fixed beside a variable", ch, already, err)

	// netlify.toml NODE_VERSION set from a variable is listed.
	root = t.TempDir()
	write(t, root, map[string]string{"netlify.toml": "[build.environment]\n  NODE_VERSION = \"24.22.0\"\n"})
	f = only(t, root, pins.RuleNode)
	write(t, root, map[string]string{"netlify.toml": "[build.environment]\n  NODE_VERSION = \"$NODE\"\n"})
	if res, err := pins.Scan(ctx, root, nil, pins.Options{}); err != nil || len(res.Skips) != 1 || res.Skips[0].Line != 2 {
		t.Errorf("netlify.toml: %v %+v", err, res.Skips)
	}
	ch, already, err = plan(root, f)
	mustDecline(t, "netlify.toml from a variable", ch, already, err)

	// A range or a floating value is a value, not an expression.
	for _, v := range []string{"'>=22 <25'", "'^24'", "lts/*", "24.x", "'~24.22'"} {
		root := t.TempDir()
		write(t, root, map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: " + v + "\n"})
		if res, err := pins.Scan(ctx, root, nil, pins.Options{}); err != nil || len(res.Skips) != 0 {
			t.Errorf("%s: %v %+v", v, err, res.Skips)
		}
	}
}

// Every reader records a fixed value under the source its findings carry,
// so a plan with the finding's props finds it there.
func TestJudgedSourceStrings(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct{ file, was, now string }{
		{"Dockerfile", "FROM node:24.22.0\n", "FROM node:24.22.1\n"},
		{"Dockerfile", "FROM mcr.microsoft.com/dotnet/aspnet:8.0.32\n", "FROM mcr.microsoft.com/dotnet/aspnet:8.0.33\n"},
		{"Dockerfile", "FROM mcr.microsoft.com/dotnet/sdk:8.0.415\n", "FROM mcr.microsoft.com/dotnet/sdk:8.0.427\n"},
		{"Dockerfile", "FROM oven/bun:1.4.3\n", "FROM oven/bun:1.4.4\n"},
		{"Dockerfile", "FROM gcr.io/distroless/nodejs20-debian12\n", "FROM gcr.io/distroless/nodejs22-debian12\n"},
		{"Dockerfile", "FROM debian:12\nRUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash\n", "FROM debian:12\nRUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash\n"},
		{"Dockerfile", "FROM debian:12\nENV NODE_VERSION=24.22.0\n", "FROM debian:12\nENV NODE_VERSION=24.22.1\n"},
		{"requirements.txt", "pycurl==7.48.0\n", "pycurl==7.49.0\n"},
		{"app.csproj", "<Project>\n  <PropertyGroup>\n    <TargetFramework>net6.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n", "<Project>\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n"},
		{"svc/packages.lock.json", depsRepo["svc/packages.lock.json"], strings.Replace(depsRepo["svc/packages.lock.json"], "8.0.32", "8.0.33", 1)},
		{".nvmrc", "22.23.1\n", "22.23.4\n"},
		{".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 24.22.0\n",
			"on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 24.22.1\n"},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.was})
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Findings) != 1 {
			t.Errorf("%s %q: %v %+v", c.file, c.was, err, res.Findings)
			continue
		}
		f := res.Findings[0]
		write(t, root, map[string]string{c.file: c.now})
		got := pins.JudgedSources(root, f.File, f.Line, f.Rule)
		found := false
		for _, s := range got {
			found = found || s == f.Props["source"]
		}
		if !found {
			t.Errorf("%s %q: the fixed value is recorded under %v, the finding's source is %q", c.file, c.now, got, f.Props["source"])
		}
	}
}

// The class: a release slot whose value is not a literal release after
// what the scan resolves (a $, a backtick, $( ), ${{ }}, << >>, or a
// parameter expansion it does not evaluate) is never judged fixed. It
// declines "rescan to confirm" at fix time, and is listed as not checked
// only where the value cannot be resolved (a version variable, a
// structured slot), not for a shell command or URL.
func TestUnresolvedSlotNeverFixed(t *testing.T) {
	ctx := context.Background()
	env := func(v string) string { return "FROM debian:12\nENV NODE_VERSION=" + v + "\n" }
	for _, c := range []struct {
		what, file, was, now string
		listed               bool
	}{
		{"${V:?err}", "Dockerfile", env("24.22.0"), env("${V:?set V}"), true},
		{"${V%.*}", "Dockerfile", env("24.22.0"), env("${V%.*}"), true},
		{"${V:+alt}", "Dockerfile", env("24.22.0"), env("${V:+24.22.1}"), true},
		{"a quoted default", "Dockerfile", env("24.22.0"), env(`${V:-"24.22.1"}`), true},
		{"a default with a suffix", "Dockerfile", env("24.22.0"), env("${V:-24.22.1}-$X"), true},
		{"export from $(cat ..)", "install.sh", "export NODE_VERSION=24.22.0\n", "export NODE_VERSION=$(cat .nvmrc)\n", true},
		{"export from backticks", "install.sh", "export NODE_VERSION=24.22.0\n", "export NODE_VERSION=`cat .nvmrc`\n", true},
		{"nvm install v$V", "install.sh", "nvm install 24.22.0\n", "nvm install v$V\n", false},
		{"nvm install 24$SUFFIX", "install.sh", "nvm install 24.22.0\n", "nvm install 24$SUFFIX\n", false},
		{"nvm install `cat .nvmrc`", "install.sh", "nvm install 24.22.0\n", "nvm install `cat .nvmrc`\n", false},
		{"a quoted asdf value", "install.sh", "asdf install nodejs 24.22.0\n", "asdf install nodejs \"$V\"\n", false},
		{"a quoted volta value", "install.sh", "volta install node@24.22.0\n", "volta install node@\"$V\"\n", false},
		{"a quoted dotnet-install version", "install.sh", "./dotnet-install.sh --runtime dotnet --version 8.0.32\n", "./dotnet-install.sh --runtime dotnet --version \"$V\"\n", false},
		{"a managed runtime from a variable", "serverless.yml", "provider:\n  runtime: nodejs18.x\n", "provider:\n  runtime: ${self:custom.runtime}\n", false},
		{"a managed runtime with a variable major", "serverless.yml", "provider:\n  runtime: nodejs18.x\n", "provider:\n  runtime: nodejs${NODE}.x\n", false},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.was})
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Findings) != 1 {
			t.Fatalf("%s: %v %+v", c.what, err, res.Findings)
		}
		f := res.Findings[0]
		write(t, root, map[string]string{c.file: c.now})
		res, err = pins.Scan(ctx, root, nil, pins.Options{})
		listed := err == nil && len(res.Skips) == 1 && res.Skips[0].Line == f.Line
		if err != nil || listed != c.listed || len(res.Findings) != 0 || (!c.listed && len(res.Skips) != 0) {
			t.Errorf("%s: want listed %v and no finding: %v findings %+v skips %+v", c.what, c.listed, err, res.Findings, res.Skips)
		}
		ch, already, err := plan(root, f)
		mustDecline(t, c.what, ch, already, err)
	}
}

// In JavaScript and TypeScript a leading # is a private field, not a
// comment; in Python it is a comment.
func TestHashLines(t *testing.T) {
	for _, c := range []struct {
		file, body string
		n          int
	}{
		{"stack.ts", "class S {\n  #runtime = Runtime.NODEJS_16_X;\n}\n", 1},
		{"stack.js", "class S {\n  #runtime = lambda.Runtime.NODEJS_16_X\n}\n", 1},
		{"stack.py", "# runtime=Runtime.NODEJS_16_X\n", 0},
		{"stack.ts", "  // runtime: Runtime.NODEJS_16_X\n", 0},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{c.file: c.body})
		res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
		if err != nil || len(res.Findings) != c.n {
			t.Errorf("%s %q: %v %+v", c.file, c.body, err, res.Findings)
		}
	}
}

// ARG scope across Dockerfile stages: an ENV reads the ARG its own stage
// declares (a global ARG only through an ARG line in the stage), and a
// variable-fed edit is made by hand when the ARG is set in more than one
// place or a FROM reads it.
func TestARGStageScope(t *testing.T) {
	ctx := context.Background()
	type want struct {
		line    int
		current string
		fixable bool
	}
	for _, c := range []struct {
		what, body string
		want       []want
		skips      int
	}{
		{"a global ARG not declared in the stage", "ARG B=24.22.0\nFROM debian:12 AS a\nENV NODE_VERSION=$B\n", nil, 1},
		{"a global ARG declared in the stage", "ARG B=24.22.0\nFROM debian:12 AS a\nARG B\nENV NODE_VERSION=$B\n", []want{{4, "24.22.0", true}}, 0},
		{"an ARG of another stage", "FROM debian:12 AS a\nARG B=24.22.1\nFROM debian:12 AS b\nENV NODE_VERSION=$B\n", nil, 1},
		{"each stage its own ARG", "FROM debian:12 AS a\nARG B=24.22.0\nENV NODE_VERSION=$B\nFROM debian:12 AS b\nARG B=24.21.0\nENV NODE_VERSION=$B\n",
			[]want{{3, "24.22.0", false}, {6, "24.21.0", false}}, 0},
		{"an ARG a FROM reads", "ARG B=24.22.0\nFROM debian:${B} AS a\nARG B\nENV NODE_VERSION=$B\n", []want{{4, "24.22.0", false}}, 0},
	} {
		root := t.TempDir()
		write(t, root, map[string]string{"Dockerfile": c.body})
		res, err := pins.Scan(ctx, root, nil, pins.Options{})
		if err != nil || len(res.Findings) != len(c.want) || len(res.Skips) != c.skips {
			t.Errorf("%s: %v findings %+v skips %+v", c.what, err, res.Findings, res.Skips)
			continue
		}
		for k, w := range c.want {
			f := res.Findings[k]
			if f.Line != w.line || f.Props["current"] != w.current || f.Fixable != w.fixable {
				t.Errorf("%s: %+v, want %+v", c.what, f, w)
			}
			if !w.fixable {
				if ch, already, err := plan(root, f); ch != nil || already || err == nil {
					t.Errorf("%s: a by-hand edit planned: %+v %v %v", c.what, ch, already, err)
				}
			}
		}
	}
	// A pin whose stage now reads an ARG set only in another stage is not
	// fixed.
	root := t.TempDir()
	write(t, root, map[string]string{"Dockerfile": "FROM debian:12 AS a\nARG B=24.22.1\nFROM debian:12 AS b\nENV NODE_VERSION=24.22.0\n"})
	f := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{"Dockerfile": "FROM debian:12 AS a\nARG B=24.22.1\nFROM debian:12 AS b\nENV NODE_VERSION=$B\n"})
	ch, already, err := plan(root, f)
	mustDecline(t, "an ARG of another stage", ch, already, err)
}

// A version file value that starts like a release but goes on as a
// variable is listed, not judged.
func TestVersionFileValueWithVariable(t *testing.T) {
	root := t.TempDir()
	write(t, root, map[string]string{".nvmrc": "24.22.0\n"})
	f := only(t, root, pins.RuleNode)
	write(t, root, map[string]string{".nvmrc": "24.22.1$SUFFIX\n"})
	res, err := pins.Scan(context.Background(), root, nil, pins.Options{})
	if err != nil || len(res.Findings) != 0 || len(res.Skips) != 1 {
		t.Errorf("%v %+v", err, res)
	}
	ch, already, err := plan(root, f)
	mustDecline(t, ".nvmrc 24.22.1$SUFFIX", ch, already, err)
}
