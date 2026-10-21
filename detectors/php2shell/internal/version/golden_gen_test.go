//go:build golden

package version

// Regenerates testdata/*.golden.gz from the real tools, in Docker:
//
//	go test -tags golden -run TestRegenerateGolden -timeout 60m ./version
//
// dpkg: debian:12 (dpkg --compare-versions), apk-tools 2: alpine:3.22,
// apk-tools 3: alpine:3.23 (apk version -c / -t), rpm: fedora:41 (Lua
// rpm.vercmp, which is rpmverParse + rpmverCmp).

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func docker(t *testing.T, dir, image, script string) string {
	t.Helper()
	cmd := exec.Command("docker", "run", "--rm", "-v", dir+":/w", image, "sh", "-c", script)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", image, err, errb.String())
	}
	return out.String()
}

func writeNul(t *testing.T, path string, fields ...[]string) {
	var b bytes.Buffer
	for _, f := range fields {
		for _, s := range f {
			b.WriteString(s)
			b.WriteByte(0)
		}
	}
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// classify runs script once per version (args: index, version) and returns
// the first output field after the index for each version.
func classify(t *testing.T, dir, image, perVersion string, vs []string) []string {
	var args []string
	for i, v := range vs {
		args = append(args, strconv.Itoa(i), v)
	}
	writeNul(t, filepath.Join(dir, "valid.bin"), args)
	script := `xargs -0 -n 200 sh -c 'while [ $# -gt 0 ]; do ` + perVersion + `; shift 2; done' _ < /w/valid.bin > /w/valid.txt`
	docker(t, dir, image, script)
	b, err := os.ReadFile(filepath.Join(dir, "valid.txt"))
	if err != nil {
		t.Fatal(err)
	}
	res := make([]string, len(vs))
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		f := strings.SplitN(line, " ", 2)
		i, err := strconv.Atoi(f[0])
		if err != nil || len(f) != 2 || res[i] != "" {
			t.Fatalf("bad line %q", line)
		}
		res[i] = f[1]
	}
	for i, r := range res {
		if r == "" {
			t.Fatalf("no class for %q", vs[i])
		}
	}
	return res
}

// pairs runs cmp (args $3 $4 = versions, sets r to <, = or >) on every pair
// i <= j of ok and returns the upper triangle rows.
func pairs(t *testing.T, dir, image, cmp string, ok []string) []string {
	var args []string
	for i := range ok {
		for j := i; j < len(ok); j++ {
			args = append(args, strconv.Itoa(i), strconv.Itoa(j), ok[i], ok[j])
		}
	}
	writeNul(t, filepath.Join(dir, "pairs.bin"), args)
	script := `xargs -0 -n 400 -P 8 sh -c 'while [ $# -gt 0 ]; do ` + cmp + `; echo "$1 $2 $r"; shift 4; done' _ < /w/pairs.bin > /w/pairs.txt`
	docker(t, dir, image, script)
	f, err := os.Open(filepath.Join(dir, "pairs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows := make([][]byte, len(ok))
	for i := range rows {
		rows[i] = bytes.Repeat([]byte{'?'}, len(ok)-i)
	}
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 3 {
			t.Fatalf("bad pair line %q", sc.Text())
		}
		i, _ := strconv.Atoi(fs[0])
		j, _ := strconv.Atoi(fs[1])
		if fs[2] != "<" && fs[2] != "=" && fs[2] != ">" {
			t.Fatalf("pair %q %q: tool said %q", ok[i], ok[j], fs[2])
		}
		if rows[i][j-i] != '?' {
			t.Fatalf("duplicate pair %d %d", i, j)
		}
		rows[i][j-i] = fs[2][0]
		n++
	}
	if want := len(ok) * (len(ok) + 1) / 2; n != want {
		t.Fatalf("%s: %d pair results, want %d", image, n, want)
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = string(r)
	}
	return out
}

func TestRegenerateGolden(t *testing.T) {
	only := os.Getenv("GOLDEN_ONLY") // "dpkg", "apk", "rpm" or empty for all
	dir, err := os.MkdirTemp("", "vergolden")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// dpkg: bookworm (1.21) and trixie (1.22)
	for _, x := range []struct{ name, image string }{{"dpkg", "debian:12"}, {"dpkg13", "debian:trixie-slim"}} {
		if only != "" && only != "dpkg" {
			break
		}
		vs := dpkgCorpus()
		tool := strings.TrimSpace(strings.SplitN(docker(t, dir, x.image, "dpkg --version"), "\n", 2)[0])
		cls := classify(t, dir, x.image,
			`e=$(dpkg --compare-versions -- "$2" eq "$2" 2>&1); c=$?; k=ok; case "$e" in *warning*) k=warn;; esac; [ $c -ne 0 ] && k=error; echo "$1 $k"`, vs)
		var ok []string
		for i, c := range cls {
			if c == "ok" {
				ok = append(ok, vs[i])
			}
		}
		rows := pairs(t, dir, x.image,
			`if dpkg --compare-versions -- "$3" lt "$4"; then r="<"; elif dpkg --compare-versions -- "$3" eq "$4"; then r="="; else r=">"; fi`, ok)
		writeGolden(t, x.name, x.image+" "+tool, vs, cls, rows)
	}
	// apk-tools 2 and 3
	for _, x := range []struct{ name, image string }{{"apk2", "alpine:3.22"}, {"apk3", "alpine:3.23"}} {
		if only != "" && only != "apk" {
			break
		}
		vs := apkCorpus()
		tool := strings.TrimSpace(docker(t, dir, x.image, "apk --version"))
		cls := classify(t, dir, x.image,
			`if apk version -c "$2" >/dev/null 2>&1; then echo "$1 ok"; else echo "$1 invalid"; fi`, vs)
		var ok []string
		for i, c := range cls {
			if c == "ok" {
				ok = append(ok, vs[i])
			}
		}
		rows := pairs(t, dir, x.image, `r=$(apk version -t "$3" "$4")`, ok)
		writeGolden(t, x.name, x.image+" "+tool, vs, cls, rows)
	}
	// rpm: one Lua run over the full ordered matrix.
	if only == "" || only == "rpm" {
		vs := rpmCorpus()
		writeNul(t, filepath.Join(dir, "rpm.bin"), vs)
		lua := `local f = io.open("/w/rpm.bin", "rb"); local s = f:read("a"); f:close()
local v = {}
for x in string.gmatch(s, "([^\0]*)\0") do v[#v+1] = x end
local o = io.open("/w/rpm.txt", "w")
for i = 1, #v do
  local row = {}
  for j = 1, #v do
    local ok, r = pcall(rpm.vercmp, v[i], v[j])
    if not ok then row[j] = "E" elseif r < 0 then row[j] = "<" elseif r > 0 then row[j] = ">" else row[j] = "=" end
  end
  o:write(table.concat(row), "\n")
end
o:close()
`
		if err := os.WriteFile(filepath.Join(dir, "gen.lua"), []byte(lua), 0o644); err != nil {
			t.Fatal(err)
		}
		tool := strings.TrimSpace(docker(t, dir, "fedora:41", "rpm --version"))
		docker(t, dir, "fedora:41", `rpm --eval "%{lua: dofile('/w/gen.lua')}" >/dev/null`)
		b, err := os.ReadFile(filepath.Join(dir, "rpm.txt"))
		if err != nil {
			t.Fatal(err)
		}
		rows := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if len(rows) != len(vs) {
			t.Fatalf("rpm: %d rows for %d versions", len(rows), len(vs))
		}
		cls := make([]string, len(vs))
		for i := range cls {
			cls[i] = "ok"
			if len(rows[i]) != len(vs) {
				t.Fatalf("rpm row %d has %d results", i, len(rows[i]))
			}
		}
		writeGolden(t, "rpm", "fedora:41 "+tool+" (lua rpm.vercmp, full ordered matrix)", vs, cls, rows)
	}
}

func writeGolden(t *testing.T, name, tool string, vs, cls, rows []string) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n# tool: %s\n", name, tool)
	for i, v := range vs {
		fmt.Fprintf(&b, "V %s %s\n", cls[i], strconv.Quote(v))
	}
	for _, r := range rows {
		fmt.Fprintf(&b, "R %s\n", r)
	}
	if err := writeGz(filepath.Join("testdata", name+".golden.gz"), b.Bytes()); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %d versions, %d rows (%s)", name, len(vs), len(rows), tool)
}
