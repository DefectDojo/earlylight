package engine

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
