package engine

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/internal/source"
)

// limited is a detector that sets its own size limit on some files.
type limited struct {
	*fake
	max func(p string) int64
}

func (l limited) Limit(p string, _ []byte, _ bool) int64 { return l.max(p) }

// limitedReader is a limited detector that also filters what it reads.
type limitedReader struct {
	limited
	fakeReader
}

func (l limitedReader) Manifest() Manifest                    { return l.limited.Manifest() }
func (l limitedReader) Load() error                           { return nil }
func (l limitedReader) NewScan(k TargetKind) Scan             { return l.limited.NewScan(k) }
func (l limitedReader) Wants(p string, h []byte, e bool) bool { return l.fakeReader.Wants(p, h, e) }

func capped(id string, wants func(string) bool, max func(string) int64) (*fake, Detector) {
	f := &fake{id: id, wants: wants, seen: &[]string{}}
	l := limited{f, max}
	if wants == nil {
		return f, l
	}
	return f, limitedReader{l, fakeReader{f}}
}

func osRelease(p string) bool { return p == "/etc/os-release" }

func limit64K(p string) int64 {
	if osRelease(p) {
		return 64 << 10
	}
	return 0
}

func ownSkips(t *Target) []source.Skip {
	var out []source.Skip
	for _, s := range t.Skipped {
		if strings.Contains(s.Reason, "-byte limit of") {
			out = append(out, s)
		}
	}
	return out
}

// A file over a detector's own limit is not read for it: it is recorded as a
// deliberate exclusion naming the detector and the size, and is no coverage gap.
func TestLimiterSkipsAFileOverItsLimit(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10), "etc/small": []byte("x")})
	f, d := capped("t-cap", func(p string) bool { return strings.HasPrefix(p, "/etc/") }, limit64K)
	tg := ScanFS([]Detector{d}, root, Options{AsRoot: true, MaxFileSize: 256 << 20})
	if got := strings.Join(*f.seen, ","); got != "/etc/small" {
		t.Errorf("the capped detector saw %q", got)
	}
	sk := ownSkips(tg)
	if len(sk) != 1 || sk[0].Path != "/etc/os-release" || !sk[0].Excluded ||
		!strings.Contains(sk[0].Reason, "t-cap") || !strings.Contains(sk[0].Reason, "102400 bytes") || !strings.Contains(sk[0].Reason, "65536") {
		t.Fatalf("skips %+v", tg.Skipped)
	}
	if tg.Gaps() != 0 || tg.Read != 1 {
		t.Errorf("gaps %d read %d", tg.Gaps(), tg.Read)
	}
	// At or under the limit it is read as before.
	root = tree(t, map[string][]byte{"etc/os-release": make([]byte, 64<<10)})
	f, d = capped("t-cap2", func(p string) bool { return true }, limit64K)
	if tg := ScanFS([]Detector{d}, root, Options{AsRoot: true}); len(*f.seen) != 1 || len(tg.Skipped) != 0 {
		t.Errorf("a file at the limit: seen %v skipped %+v", *f.seen, tg.Skipped)
	}
}

// The limit holds in an image too, where the size comes from the tar header.
func TestLimiterInAnImage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rootfs.tar")
	if err := os.WriteFile(p, tarFile(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10), "etc/small": []byte("x")}), 0o600); err != nil {
		t.Fatal(err)
	}
	f, d := capped("t-capimg", func(p string) bool { return true }, limit64K)
	tg := ScanImage([]Detector{d}, "rootfs:"+p, Options{MaxFileSize: 256 << 20})
	if tg.Error != "" || strings.Join(*f.seen, ",") != "/etc/small" || len(ownSkips(tg)) != 1 || tg.Gaps() != 0 {
		t.Fatalf("error %q seen %v skipped %+v", tg.Error, *f.seen, tg.Skipped)
	}
}

// Another detector that wants the file without a limit still gets it; the
// capped detector does not, and the file is recorded as not checked by it.
func TestLimiterWithAnotherReader(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10)})
	f, d := capped("t-capu", osRelease, limit64K)
	other := &fake{id: "t-uncapped", wants: osRelease}
	tg := ScanFS([]Detector{d, detector(other)}, root, Options{AsRoot: true})
	if len(*f.seen) != 0 || len(*other.seen) != 1 {
		t.Errorf("capped saw %v, other saw %v", *f.seen, *other.seen)
	}
	if sk := ownSkips(tg); len(sk) != 1 || !strings.Contains(sk[0].Reason, "t-capu") || strings.Contains(sk[0].Reason, "t-uncapped") || tg.Gaps() != 0 {
		t.Errorf("skips %+v", tg.Skipped)
	}

	// The largest limit decides how far the file is read; each detector
	// still sees only what fits its own.
	root = tree(t, map[string][]byte{"etc/os-release": make([]byte, 10<<10)})
	small, ds := capped("t-cap1k", osRelease, func(string) int64 { return 1 << 10 })
	big, db := capped("t-cap64k", osRelease, limit64K)
	tg = ScanFS([]Detector{ds, db}, root, Options{AsRoot: true})
	if len(*small.seen) != 0 || len(*big.seen) != 1 || len(ownSkips(tg)) != 1 || !strings.Contains(ownSkips(tg)[0].Reason, "t-cap1k") {
		t.Errorf("small saw %v, big saw %v, skipped %+v", *small.seen, *big.seen, tg.Skipped)
	}
}

// A file over the limits of two detectors has one record naming each
// (final review finding 6).
func TestLimiterTwoLimits(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10)})
	_, ds := capped("t-two1k", osRelease, func(string) int64 { return 1 << 10 })
	_, db := capped("t-two64k", osRelease, limit64K)
	tg := ScanFS([]Detector{ds, db}, root, Options{AsRoot: true})
	var got []string
	for _, s := range tg.Skipped {
		got = append(got, s.Reason)
	}
	// One record for the path, naming both.
	want := "excluded: larger than the 1024-byte limit of t-two1k for this file (102400 bytes); " +
		"larger than the 65536-byte limit of t-two64k for this file (102400 bytes)"
	if strings.Join(got, "|") != want {
		t.Errorf("skipped %q", got)
	}
}

// With a detector that reads every file, a capped detector is still not
// shown a file over its limit.
func TestLimiterWithAnAllReader(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10), "etc/x": []byte("x")})
	f, d := capped("t-capall", nil, limit64K)
	all := &fake{id: "t-all3"}
	tg := ScanFS([]Detector{d, detector(all)}, root, Options{AsRoot: true})
	if strings.Join(*f.seen, ",") != "/etc/x" || len(*all.seen) != 2 || len(ownSkips(tg)) != 1 {
		t.Errorf("capped saw %v, all saw %v, skipped %+v", *f.seen, *all.seen, tg.Skipped)
	}
}

// A limit does not apply where the detector sets none, and --max-file-size
// still bounds a file under a detector's limit.
func TestLimiterLeavesOtherFiles(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100), "bin/big": make([]byte, 200<<10)})
	f, d := capped("t-capo", func(string) bool { return true }, limit64K)
	tg := ScanFS([]Detector{d}, root, Options{AsRoot: true, MaxFileSize: 50})
	if len(*f.seen) != 0 || len(tg.Skipped) != 2 || len(ownSkips(tg)) != 0 || tg.Gaps() != 2 {
		t.Errorf("seen %v skipped %+v", *f.seen, tg.Skipped)
	}
	tg = ScanFS([]Detector{d}, root, Options{AsRoot: true})
	if len(*f.seen) != 2 || len(tg.Skipped) != 0 {
		t.Errorf("without --max-file-size: seen %v skipped %+v", *f.seen, tg.Skipped)
	}
}

// A file over a detector's limit is never read past its head: scanning a
// huge one allocates about nothing.
func TestLimiterNeverReadsAHugeFile(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	fh, err := os.Create(filepath.Join(root, "etc/os-release"))
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(128 << 20); err != nil { // sparse: no disk used
		t.Fatal(err)
	}
	fh.Close()
	_, d := capped("t-caphuge", osRelease, limit64K)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	tg := ScanFS([]Detector{d}, root, Options{AsRoot: true, MaxFileSize: 256 << 20})
	runtime.ReadMemStats(&after)
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
		t.Errorf("scanning a 128 MiB file over a 64 KiB limit allocated %d bytes", alloc)
	}
	if len(ownSkips(tg)) != 1 {
		t.Errorf("skipped %+v", tg.Skipped)
	}
}

func tarFile(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	tw.Close()
	return buf.Bytes()
}

// gapScan is a capped detector whose scan says an over-limit file is a gap.
type gapScan struct {
	limitedReader
	gap   bool
	sizes *[]int64
}

func (g gapScan) NewScan(TargetKind) Scan { return g }
func (g gapScan) Visit(f File) []Skip     { return g.limited.fake.Visit(f) }
func (g gapScan) Finish(ctx TargetContext) []Finding {
	return g.limited.fake.Finish(ctx)
}
func (g gapScan) VisitOverLimit(p string, size int64) []Skip {
	*g.sizes = append(*g.sizes, size)
	if !g.gap {
		return nil
	}
	return []Skip{{Path: p, Reason: "an include over the limit; not cleared"}}
}

func gapDetector(id string, gap bool) (*fake, gapScan) {
	f := &fake{id: id, wants: osRelease, seen: &[]string{}}
	return f, gapScan{limitedReader{limited{f, limit64K}, fakeReader{f}}, gap, &[]int64{}}
}

// A scan that implements LimitVisitor turns an over-limit file into a
// coverage gap, whether the file was left unread or read for another
// detector; returning nothing leaves it a deliberate exclusion.
func TestLimitVisitor(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10)})
	f, g := gapDetector("t-gap", true)
	tg := ScanFS([]Detector{g}, root, Options{AsRoot: true})
	if len(*f.seen) != 0 || len(tg.Skipped) != 1 || tg.Skipped[0].Excluded || tg.Gaps() != 1 || strings.Join(fmtSizes(*g.sizes), ",") != "102400" {
		t.Errorf("unread: seen %v skipped %+v sizes %v", *f.seen, tg.Skipped, *g.sizes)
	}
	f, g = gapDetector("t-gap2", true)
	other := &fake{id: "t-reads", wants: osRelease}
	tg = ScanFS([]Detector{g, detector(other)}, root, Options{AsRoot: true})
	if len(*f.seen) != 0 || len(*other.seen) != 1 || len(tg.Skipped) != 1 || tg.Gaps() != 1 {
		t.Errorf("read for another: seen %v skipped %+v", *f.seen, tg.Skipped)
	}
	f, g = gapDetector("t-nogap", false)
	tg = ScanFS([]Detector{g}, root, Options{AsRoot: true})
	if len(tg.Skipped) != 1 || !tg.Skipped[0].Excluded || tg.Gaps() != 0 || len(*g.sizes) != 1 {
		t.Errorf("no gap: skipped %+v sizes %v", tg.Skipped, *g.sizes)
	}
}

func fmtSizes(s []int64) []string {
	var out []string
	for _, n := range s {
		out = append(out, strconv.FormatInt(n, 10))
	}
	return out
}

// Exists is true for every regular file the walk met: one over a
// detector's limit, one over --max-file-size and one no detector wants.
// It does not depend on which detectors ran.
func TestExistsWithLimits(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10), "bin/big": make([]byte, 2000), "etc/x": []byte("x")})
	for _, extra := range [][]Detector{nil, {detector(&fake{id: "t-ex-all"})}} {
		var got []bool
		f := &fake{id: "t-ex", wants: osRelease, seen: &[]string{}, finish: func(ctx TargetContext) []Finding {
			got = []bool{ctx.Exists("/etc/os-release"), ctx.Exists("/bin/big"), ctx.Exists("/etc/x"), ctx.Exists("/etc/none")}
			return nil
		}}
		d := limitedReader{limited{f, limit64K}, fakeReader{f}}
		ScanFS(append([]Detector{d}, extra...), root, Options{AsRoot: true, MaxFileSize: 1000})
		if fmt.Sprint(got) != "[true true true false]" {
			t.Errorf("with %d other detectors: exists %v", len(extra), got)
		}
	}
}

// The limit decision, checked against a model for any file size, limits and
// wants: who sees the file, what is recorded, and that Exists holds.
func FuzzLimits(f *testing.F) {
	for _, s := range [][5]uint16{{100, 100, 0, 3, 0}, {101, 100, 0, 3, 0}, {4096, 4096, 4097, 3, 1}, {4097, 4096, 0, 1, 2}, {5000, 4096, 5000, 2, 3}, {0, 1, 1, 3, 3}, {1, 0, 0, 0, 0}, {115, 100, 0, 2, 0}} {
		f.Add(s[0], s[1], s[2], uint8(s[3]), uint8(s[4]))
	}
	f.Fuzz(func(t *testing.T, size, limA, limB uint16, wants, maxSel uint8) {
		size %= 9000
		maxSize := []int64{0, 4096, 5000, 100}[maxSel%4]
		lims := []int64{int64(limA % 9000), int64(limB % 9000)}
		want := []bool{wants&1 != 0, wants&2 != 0}
		root := tree(t, map[string][]byte{"etc/os-release": make([]byte, size)})
		var fakes []*fake
		var dets []Detector
		for i := range lims {
			i := i
			fk := &fake{id: fmt.Sprintf("t-fz%d", i), wants: func(string) bool { return want[i] }, seen: &[]string{}}
			fakes = append(fakes, fk)
			dets = append(dets, limitedReader{limited{fk, func(string) int64 { return lims[i] }}, fakeReader{fk}})
		}
		var exists bool
		fakes[0].finish = func(ctx TargetContext) []Finding { exists = ctx.Exists("/etc/os-release"); return nil }
		tg := ScanFS(dets, root, Options{AsRoot: true, MaxFileSize: maxSize})

		over := func(i int) bool { return lims[i] > 0 && int64(size) > lims[i] }
		// The read limit: the largest limit of those who want it, or
		// --max-file-size when one of them has none; a limit at or above
		// --max-file-size is --max-file-size.
		read := false
		var bound int64
		unlimited := false
		for i := range lims {
			if !want[i] {
				continue
			}
			read = true
			if lims[i] <= 0 {
				unlimited = true
			}
			bound = max(bound, lims[i])
		}
		if unlimited || maxSize > 0 && bound >= maxSize {
			bound = maxSize
		}
		readIt := read && (bound <= 0 || int64(size) <= bound)
		ownSkip := read && !unlimited && bound != maxSize && int64(size) > bound
		for i := range lims {
			sees := readIt && !over(i)
			if (len(*fakes[i].seen) == 1) != sees {
				t.Fatalf("size %d lims %v want %v max %d: detector %d saw %v, want %v (skipped %+v)", size, lims, want, maxSize, i, *fakes[i].seen, sees, tg.Skipped)
			}
		}
		// One record for the path names each detector whose own limit kept
		// it out (and that wanted it).
		if len(tg.Skipped) > 1 {
			t.Fatalf("more than one record for one path: %+v", tg.Skipped)
		}
		for i := range lims {
			named := len(tg.Skipped) == 1 && tg.Skipped[0].Excluded &&
				strings.Contains(tg.Skipped[0].Reason, fmt.Sprintf("limit of t-fz%d ", i))
			if wantNamed := want[i] && over(i) && (readIt || ownSkip); named != wantNamed {
				t.Fatalf("size %d lims %v want %v max %d: detector %d named %v, want %v: %+v", size, lims, want, maxSize, i, named, wantNamed, tg.Skipped)
			}
		}
		if !exists {
			t.Fatalf("Exists false for a file the walk met")
		}
	})
}

// panicOver panics in VisitOverLimit.
type panicOver struct{ gapScan }

func (p panicOver) NewScan(TargetKind) Scan { return p }
func (p panicOver) VisitOverLimit(string, int64) []Skip {
	panic("hostile size")
}

// A panic in VisitOverLimit loses that file, recorded as a detector
// failure (a gap), and the scan goes on: over its own limit and over
// --max-file-size alike.
func TestVisitOverLimitPanic(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10), "etc/b": []byte("b")})
	for _, max := range []int64{0, 1000} {
		_, g := gapDetector(fmt.Sprintf("t-overpanic%d", max), true)
		other := &fake{id: fmt.Sprintf("t-overother%d", max), wants: func(string) bool { return true }}
		tg := ScanFS([]Detector{panicOver{g}, detector(other)}, root, Options{AsRoot: true, MaxFileSize: max})
		failed := false
		for _, s := range tg.Skipped {
			failed = failed || s.Path == "/etc/os-release" && s.DetectorFailed
		}
		if tg.Error != "" || !failed || tg.Gaps() != 1 || len(*other.seen) == 0 {
			t.Errorf("--max-file-size %d: error %q skipped %+v other saw %v", max, tg.Error, tg.Skipped, *other.seen)
		}
	}
}

// Files over --max-file-size are told to each scan that asked for them
// (size known, or -1), and the record stays the --max-file-size gap.
func TestVisitOverLimitMaxFileSize(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 2000)})
	_, g := gapDetector("t-overmax", true)
	tg := ScanFS([]Detector{g}, root, Options{AsRoot: true, MaxFileSize: 1000})
	if len(*g.sizes) != 1 || (*g.sizes)[0] != 2000 || len(tg.Skipped) != 1 || !strings.Contains(tg.Skipped[0].Reason, "--max-file-size") || tg.Gaps() != 1 {
		t.Errorf("sizes %v skipped %+v", *g.sizes, tg.Skipped)
	}
	// A detector that did not ask for it is not told.
	notWanting := &fake{id: "t-overmax-no", wants: func(string) bool { return false }, seen: &[]string{}}
	sizes := &[]int64{}
	ng := gapScan{limitedReader{limited{notWanting, limit64K}, fakeReader{notWanting}}, true, sizes}
	ScanFS([]Detector{ng, detector(&fake{id: "t-overmax-all"})}, root, Options{AsRoot: true, MaxFileSize: 1000})
	if len(*sizes) != 0 {
		t.Errorf("told a detector that did not want it: %v", *sizes)
	}
}

// Over-limit records carry the path inside the system root when a
// directory below it is scanned (--root).
func TestLimiterBelowSystemRoot(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10)})
	_, d := capped("t-caproot", osRelease, limit64K)
	tg := ScanFS([]Detector{d}, filepath.Join(root, "etc"), Options{SystemRoot: root})
	if tg.Error != "" || len(tg.Skipped) != 1 || tg.Skipped[0].Path != "/etc/os-release" {
		t.Errorf("error %q skipped %+v", tg.Error, tg.Skipped)
	}
}

// finishSkipper reports a gap only at the end.
type finishSkipper struct {
	gapScan
	found bool
}

func (f finishSkipper) NewScan(TargetKind) Scan { return f }
func (f finishSkipper) FinishSkips() []Skip {
	if !f.found {
		return nil
	}
	return []Skip{{Path: "/etc/os-release", Reason: "needed after all"}}
}

// FinishSkips adds coverage gaps after Finish; a path with several records
// is counted once.
func TestFinishSkipper(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 100<<10)})
	for _, found := range []bool{false, true} {
		_, g := gapDetector(fmt.Sprintf("t-finskip%v", found), false)
		tg := ScanFS([]Detector{finishSkipper{g, found}}, root, Options{AsRoot: true})
		want := 0
		if found {
			want = 1
		}
		if tg.Gaps() != want || tg.SkippedPaths() != 1 {
			t.Errorf("found %v: gaps %d paths %d skipped %+v", found, tg.Gaps(), tg.SkippedPaths(), tg.Skipped)
		}
		// A gap reported at the end replaces the scan's exclusion record.
		if found && (len(tg.Skipped) != 1 || tg.Skipped[0].Excluded) {
			t.Errorf("records contradict each other: %+v", tg.Skipped)
		}
	}
}

// unreadable makes p unreadable, or skips the test when that cannot be
// done (running as root).
func unreadable(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o755) })
	if f, err := os.Open(p); err == nil {
		f.Close()
		t.Skip("running as root: permissions do not keep a file unread")
	}
}

// unreadScan records what it is told about files it could not read and
// what it is told to forget.
type unreadScan struct {
	*fake
	unread, forgot *[]string
	panicOn        string
}

func (u unreadScan) NewScan(TargetKind) Scan { return u }
func (u unreadScan) VisitUnread(p string, dir bool) {
	if p == u.panicOn {
		panic("hostile")
	}
	*u.unread = append(*u.unread, fmt.Sprintf("%s %v", p, dir))
}
func (u unreadScan) Forget(p string) {
	if p == u.panicOn {
		panic("hostile")
	}
	*u.forgot = append(*u.forgot, p)
}

func newUnreadScan(id string) unreadScan {
	return unreadScan{&fake{id: id, seen: &[]string{}}, &[]string{}, &[]string{}, ""}
}

// Round-3 review finding 1: a file or directory the walk met and could
// not read is told to every scan that asks, exists, and is a gap.
func TestUnreadFilesAndDirs(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/ssh/sshd_config.d/50.conf": []byte("UsePAM no\n"), "etc/locked/x": []byte("x"), "etc/ok": []byte("ok")})
	unreadable(t, filepath.Join(root, "etc/ssh/sshd_config.d/50.conf"))
	unreadable(t, filepath.Join(root, "etc/locked"))
	u := newUnreadScan("t-unread")
	var exists []bool
	u.finish = func(ctx TargetContext) []Finding {
		exists = []bool{ctx.Exists("/etc/ssh/sshd_config.d/50.conf"), ctx.Exists("/etc/ok")}
		return nil
	}
	tg := ScanFS([]Detector{u}, root, Options{AsRoot: true})
	sort.Strings(*u.unread)
	if strings.Join(*u.unread, ",") != "/etc/locked true,/etc/ssh/sshd_config.d/50.conf false" {
		t.Errorf("told %v", *u.unread)
	}
	if fmt.Sprint(exists) != "[true true]" || tg.Gaps() != 2 {
		t.Errorf("exists %v gaps %d skipped %+v", exists, tg.Gaps(), tg.Skipped)
	}
	// A panic there is the detector failing on that file.
	u = newUnreadScan("t-unread-panic")
	u.panicOn = "/etc/ssh/sshd_config.d/50.conf"
	tg = ScanFS([]Detector{u}, root, Options{AsRoot: true})
	failed := false
	for _, s := range tg.Skipped {
		failed = failed || s.Path == u.panicOn && s.DetectorFailed
	}
	if tg.Error != "" || !failed {
		t.Errorf("error %q skipped %+v", tg.Error, tg.Skipped)
	}
}

// Round-3 review finding 2: when an image names a path twice, every scan
// forgets the first entry before it is shown the second.
func TestForgetDuplicateEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, body := range []string{"first", "second"} {
		tw.WriteHeader(&tar.Header{Name: "etc/a", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.WriteHeader(&tar.Header{Name: "etc/b", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("b"))
	tw.Close()
	p := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	u := newUnreadScan("t-forget")
	ScanImage([]Detector{u}, "rootfs:"+p, Options{})
	if strings.Join(*u.forgot, ",") != "/etc/a" || strings.Join(*u.seen, ",") != "/etc/a,/etc/a,/etc/b" {
		t.Errorf("forgot %v seen %v", *u.forgot, *u.seen)
	}
	u = newUnreadScan("t-forget-panic")
	u.panicOn = "/etc/a"
	tg := ScanImage([]Detector{u}, "rootfs:"+p, Options{})
	if tg.Error != "" || len(tg.Skipped) != 1 || !tg.Skipped[0].DetectorFailed {
		t.Errorf("error %q skipped %+v", tg.Error, tg.Skipped)
	}
}

// A detector's limit equal to --max-file-size is --max-file-size: a larger
// file is a gap. One byte under, it is the detector's own: an exclusion.
func TestLimitAtMaxFileSize(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 2000)})
	for _, c := range []struct {
		limit    int64
		excluded bool
	}{{1000, false}, {999, true}} {
		limit := c.limit
		_, d := capped(fmt.Sprintf("t-atmax%d", limit), osRelease, func(string) int64 { return limit })
		tg := ScanFS([]Detector{d}, root, Options{AsRoot: true, MaxFileSize: 1000})
		if len(tg.Skipped) != 1 || tg.Skipped[0].Excluded != c.excluded {
			t.Errorf("limit %d: skipped %+v", limit, tg.Skipped)
		}
	}
}

// panicFinishSkips panics in FinishSkips.
type panicFinishSkips struct{ finishSkipper }

func (p panicFinishSkips) NewScan(TargetKind) Scan { return p }
func (p panicFinishSkips) FinishSkips() []Skip     { panic("late") }

// A panic in FinishSkips fails the target, as one in Finish does.
func TestFinishSkipsPanic(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": []byte("x")})
	_, g := gapDetector("t-finpanic", false)
	tg := ScanFS([]Detector{panicFinishSkips{finishSkipper{g, true}}}, root, Options{AsRoot: true})
	if !strings.Contains(tg.Error, "t-finpanic failed") {
		t.Errorf("error %q", tg.Error)
	}
}

// visitorOnly is told about files over --max-file-size without having a
// limit of its own.
type visitorOnly struct {
	*fake
	fakeReader
	sizes *[]int64
}

func (v visitorOnly) Manifest() Manifest                    { return v.fake.Manifest() }
func (v visitorOnly) Load() error                           { return nil }
func (v visitorOnly) NewScan(TargetKind) Scan               { return v }
func (v visitorOnly) Visit(f File) []Skip                   { return v.fake.Visit(f) }
func (v visitorOnly) Finish(ctx TargetContext) []Finding    { return nil }
func (v visitorOnly) Wants(p string, h []byte, e bool) bool { return v.fakeReader.Wants(p, h, e) }
func (v visitorOnly) VisitOverLimit(_ string, size int64) []Skip {
	*v.sizes = append(*v.sizes, size)
	return nil
}

// A LimitVisitor that is not a Limiter is told about a file it wanted over
// --max-file-size, and reads every other file as before.
func TestLimitVisitorWithoutLimiter(t *testing.T) {
	root := tree(t, map[string][]byte{"etc/os-release": make([]byte, 2000), "etc/small": []byte("x")})
	f := &fake{id: "t-visitor-only", wants: func(string) bool { return true }, seen: &[]string{}}
	v := visitorOnly{f, fakeReader{f}, &[]int64{}}
	tg := ScanFS([]Detector{v}, root, Options{AsRoot: true, MaxFileSize: 1000})
	if fmt.Sprint(*v.sizes) != "[2000]" || strings.Join(*f.seen, ",") != "/etc/small" || tg.Gaps() != 1 {
		t.Errorf("sizes %v seen %v skipped %+v", *v.sizes, *f.seen, tg.Skipped)
	}
}

// Final review finding 3: in a docker export, a file a later entry
// replaces with a link or directory is forgotten; one a hard link names
// is not, as the link keeps its content.
func TestReplacedInDockerExport(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	reg := func(n, body string) {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	reg("etc/a", "1")
	tw.WriteHeader(&tar.Header{Name: "etc/a", Typeflag: tar.TypeSymlink, Linkname: "b"})
	reg("etc/d", "1")
	tw.WriteHeader(&tar.Header{Name: "etc/d", Typeflag: tar.TypeDir, Mode: 0o755})
	reg("x", "real")
	tw.WriteHeader(&tar.Header{Name: "y", Typeflag: tar.TypeLink, Linkname: "x"})
	reg("x", "")
	tw.Close()
	p := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	u := newUnreadScan("t-replaced")
	var exists []bool
	u.finish = func(ctx TargetContext) []Finding {
		exists = []bool{ctx.Exists("/etc/a"), ctx.Exists("/etc/d"), ctx.Exists("/x")}
		return nil
	}
	ScanImage([]Detector{u}, "rootfs:"+p, Options{})
	sort.Strings(*u.forgot)
	if strings.Join(*u.forgot, ",") != "/etc/a,/etc/d" || fmt.Sprint(exists) != "[false false true]" {
		t.Errorf("forgot %v exists %v", *u.forgot, exists)
	}
}

// A gap and an exclusion for one path are one record: a gap, with both
// reasons.
func TestOneRecordPerPath(t *testing.T) {
	got := oneRecordPerPath([]source.Skip{
		{Path: "/a", Reason: "excluded: larger than the 10-byte limit of x for this file (20 bytes)", Excluded: true},
		{Path: "/b", Reason: "permission denied"},
		{Path: "/a", Reason: "not read, and y's verdict depends on it"},
		{Path: "/a", Reason: "detector z failed on this file", DetectorFailed: true},
	})
	if len(got) != 2 || got[0].Path != "/a" || got[0].Excluded || !got[0].DetectorFailed ||
		got[0].Reason != "not read, and y's verdict depends on it; larger than the 10-byte limit of x for this file (20 bytes); detector z failed on this file" {
		t.Errorf("%+v", got)
	}
}
