package version

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// golden is a recorded run of a real tool (see golden_gen_test.go).
type golden struct {
	tool     string
	versions []string
	class    []string // "ok", "warn", "error", "invalid"
	ok       []string // versions with class "ok", in order
	rows     []string // results over ok: upper triangle, or full matrix for rpm
}

func writeGz(path string, data []byte) error {
	var b bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	zw.Write(data)
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func loadGolden(t *testing.T, name string) *golden {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name+".golden.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	g := &golden{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# tool: "):
			g.tool = strings.TrimPrefix(line, "# tool: ")
		case strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "V "):
			f := strings.SplitN(line, " ", 3)
			v, err := strconv.Unquote(f[2])
			if err != nil {
				t.Fatalf("%s: %q: %v", name, line, err)
			}
			g.versions = append(g.versions, v)
			g.class = append(g.class, f[1])
			if f[1] == "ok" {
				g.ok = append(g.ok, v)
			}
		case strings.HasPrefix(line, "R "):
			g.rows = append(g.rows, strings.TrimPrefix(line, "R "))
		default:
			t.Fatalf("%s: bad line %q", name, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(g.rows) != len(g.ok) {
		t.Fatalf("%s: %d rows for %d ok versions", name, len(g.rows), len(g.ok))
	}
	return g
}

func sym(c byte) int {
	switch c {
	case '<':
		return -1
	case '=':
		return 0
	case '>':
		return 1
	}
	panic("bad result " + string(c))
}

// forUpper calls f for every recorded pair i <= j with the tool's result.
func (g *golden) forUpper(t *testing.T, f func(a, b string, want int)) int {
	n := 0
	for i, row := range g.rows {
		if len(row) != len(g.ok)-i {
			t.Fatalf("row %d: %d results, want %d", i, len(row), len(g.ok)-i)
		}
		for k := 0; k < len(row); k++ {
			f(g.ok[i], g.ok[i+k], sym(row[k]))
			n++
		}
	}
	return n
}

func TestDpkgDifferential(t *testing.T) {
	for _, name := range []string{"dpkg", "dpkg13"} {
		t.Run(name, func(t *testing.T) { dpkgDifferential(t, loadGolden(t, name)) })
	}
}

func dpkgDifferential(t *testing.T, g *golden) {
	for i, v := range g.versions {
		_, err := ParseDpkg(v)
		if (err == nil) != (g.class[i] == "ok") {
			t.Errorf("ParseDpkg(%q) err=%v, dpkg says %s", v, err, g.class[i])
		}
	}
	bad := 0
	n := g.forUpper(t, func(a, b string, want int) {
		got, err := CompareDpkg(a, b)
		rev, err2 := CompareDpkg(b, a)
		if err != nil || err2 != nil || got != want || rev != -want {
			if bad++; bad < 20 {
				t.Errorf("CompareDpkg(%q, %q) = %d (reverse %d) %v %v, dpkg says %d", a, b, got, rev, err, err2, want)
			}
		}
	})
	t.Logf("%s: %d versions (%d valid), %d pairs x2 orders, %d mismatches", g.tool, len(g.versions), len(g.ok), n, bad)
}

func TestAPKDifferential(t *testing.T) {
	g2, g3 := loadGolden(t, "apk2"), loadGolden(t, "apk3")
	for _, x := range []struct {
		g        *golden
		validate func(string) bool
		cmp      func(a, b string) int
	}{{g2, apk2Validate, apk2Compare}, {g3, apk3Validate, apk3Compare}} {
		for i, v := range x.g.versions {
			if x.validate(v) != (x.g.class[i] == "ok") {
				t.Errorf("%s: validate(%q) = %v, tool says %s", x.g.tool, v, x.validate(v), x.g.class[i])
			}
		}
		bad := 0
		n := x.g.forUpper(t, func(a, b string, want int) {
			if got, rev := x.cmp(a, b), x.cmp(b, a); got != want || rev != -want {
				if bad++; bad < 20 {
					t.Errorf("%s: compare(%q, %q) = %d (reverse %d), tool says %d", x.g.tool, a, b, got, rev, want)
				}
			}
		})
		t.Logf("%s: %d versions (%d valid), %d pairs x2 orders, %d mismatches", x.g.tool, len(x.g.versions), len(x.g.ok), n, bad)
	}

	// CompareAPK: defined exactly where both tools accept both versions and
	// agree; an error everywhere else.
	res2 := map[[2]string]int{}
	g2.forUpper(t, func(a, b string, want int) { res2[[2]string{a, b}] = want })
	valid2 := map[string]bool{}
	for _, v := range g2.ok {
		valid2[v] = true
	}
	agree, disagree, bad := 0, 0, 0
	g3.forUpper(t, func(a, b string, want3 int) {
		got, err := CompareAPK(a, b)
		want2, both := res2[[2]string{a, b}]
		if !both {
			if w, ok := res2[[2]string{b, a}]; ok {
				want2, both = -w, true
			}
		}
		switch {
		case !valid2[a] || !valid2[b]:
			if err == nil {
				bad++
				t.Errorf("CompareAPK(%q, %q) = %d, want error (invalid for apk-tools 2)", a, b, got)
			}
		case !both:
			t.Fatalf("pair %q %q missing from apk2 golden", a, b)
		case want2 == want3:
			agree++
			if err != nil || got != want3 {
				bad++
				t.Errorf("CompareAPK(%q, %q) = %d, %v; both tools say %d", a, b, got, err, want3)
			}
		default:
			disagree++
			if err == nil {
				bad++
				t.Errorf("CompareAPK(%q, %q) = %d; apk2 says %d, apk3 %d: want error", a, b, got, want2, want3)
			}
		}
	})
	t.Logf("CompareAPK: %d pairs where apk-tools 2 and 3 agree, %d where they differ (error), %d mismatches", agree, disagree, bad)
	for i, v := range g3.versions {
		err := ValidateAPK(v)
		if want := g3.class[i] == "ok" && valid2[v]; (err == nil) != want {
			t.Errorf("ValidateAPK(%q) = %v, want valid=%v", v, err, want)
		}
	}
}

func TestRPMDifferential(t *testing.T) {
	g := loadGolden(t, "rpm")
	bad, n := 0, 0
	for i, row := range g.rows {
		if len(row) != len(g.ok) {
			t.Fatalf("row %d: %d results", i, len(row))
		}
		for j := range row {
			want := sym(row[j])
			n++
			if got := CompareRPM(g.ok[i], g.ok[j]); got != want {
				if bad++; bad < 20 {
					t.Errorf("CompareRPM(%q, %q) = %d, rpm says %d", g.ok[i], g.ok[j], got, want)
				}
			}
		}
	}
	t.Logf("%s: %d versions, %d ordered pairs, %d mismatches", g.tool, len(g.ok), n, bad)
}
