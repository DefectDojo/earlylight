package java4shell

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/repo"
	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// pushImage pushes a one-layer linux/amd64 image holding files.
func pushImage(t *testing.T, ref string, files map[string][]byte) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for p, b := range files {
		if err := tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(p, "/"), Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(b)
	}
	tw.Close()
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil })
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	img, err = mutate.ConfigFile(img, &v1.ConfigFile{OS: "linux", Architecture: "amd64", Config: v1.Config{Env: []string{"PATH=/usr/bin"}}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
}

func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func runtimeFiles(version string) map[string][]byte {
	return map[string][]byte{
		"/opt/java/openjdk/lib/server/libjvm.so": testlib.Build(testlib.Lib{Version: version, VBMI: true}),
		"/etc/os-release":                        []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"),
	}
}

// Review finding 16: tagLister, the verifier and pulled images, against an
// in-memory registry.
func TestRegistryPaths(t *testing.T) {
	host := testRegistry(t)
	cur := host + "/acme/java:21.0.13_9-jre"
	fixed := host + "/acme/java:21.0.13.1_2-jre"
	bad := host + "/acme/java:21.0.13.1_1-jre"
	none := host + "/acme/java:no-runtime"
	pushImage(t, cur, runtimeFiles("21.0.13+9-LTS"))
	pushImage(t, fixed, runtimeFiles("21.0.13.1+2-LTS"))
	pushImage(t, bad, runtimeFiles("21.0.13.1+1-LTS"))
	pushImage(t, none, map[string][]byte{"/etc/os-release": []byte("ID=ubuntu\n")})

	o := engine.Options{}
	tags, err := tagLister(o)(context.Background(), host+"/acme/java")
	if err != nil || len(tags) != 4 {
		t.Fatalf("tags %v %v", tags, err)
	}

	d := &Detector{}
	verify := d.verifier(o)
	if dg, err := verify(context.Background(), cur, fixed); err != nil || !strings.HasPrefix(dg, "sha256:") {
		t.Errorf("fixed target: %q %v", dg, err)
	}
	for _, target := range []string{bad, none} {
		_, err := verify(context.Background(), cur, target)
		var dec *repo.Declined
		if err == nil || !errorsAs(err, &dec) {
			t.Errorf("%s accepted: %v", target, err)
		}
	}

	// A tree that deploys a product-like image: pulled and judged.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  app:\n    image: "+host+"/acme/jira:9\n"), 0o644)
	pushImage(t, host+"/acme/jira:9", map[string][]byte{"/opt/atlassian/jira/jre/lib/server/libjvm.so": testlib.Build(testlib.Lib{Version: "17.0.21+9", VBMI: true})})
	tg := d.ScanRepo(context.Background(), dir, o)
	if len(tg.Findings) != 1 || tg.Findings[0].Kind != KindImage || tg.Findings[0].Verdict != engine.Vulnerable || tg.Findings[0].Facts["product"] != "Atlassian Jira" {
		t.Errorf("pulled: %+v", tg.Findings)
	}
}

func errorsAs(err error, d **repo.Declined) bool {
	x, ok := err.(*repo.Declined)
	if ok {
		*d = x
	}
	return ok
}

// Round-2 finding 7: the verifier compares the base OS for every move,
// and the os-release strings it reads are bounded.
func TestVerifierBaseOS(t *testing.T) {
	host := testRegistry(t)
	cur := host + "/acme/java:21.0.13_9-jre-noble"
	same := host + "/acme/java:21.0.13.1_2-jre-noble"
	other := host + "/acme/java:21.0.13.1_3-jre-noble"
	files := func(v, osr string) map[string][]byte {
		m := runtimeFiles(v)
		m["/etc/os-release"] = []byte(osr)
		return m
	}
	pushImage(t, cur, files("21.0.13+9-LTS", "ID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	pushImage(t, same, files("21.0.13.1+2-LTS", "ID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	pushImage(t, other, files("21.0.13.1+3-LTS", "ID=ubuntu\nVERSION_ID=\"26.04\"\n"))
	v := (&Detector{}).verifier(engine.Options{})
	if _, err := v(context.Background(), cur, same); err != nil {
		t.Errorf("same base declined: %v", err)
	}
	if _, err := v(context.Background(), cur, other); err == nil {
		t.Error("a move from Ubuntu 24.04 to 26.04 accepted under a variant that names the OS")
	}
	// A deleted current tag that names its OS is tolerated.
	if _, err := v(context.Background(), host+"/acme/java:21.0.12_7-jre-noble", same); err != nil {
		t.Errorf("deleted current tag: %v", err)
	}
	if got := osRelease([]byte("ID=" + strings.Repeat("a", 60000) + "\nVERSION_ID=1\n")); len(got) > 80 {
		t.Errorf("unbounded os-release: %d bytes", len(got))
	}
}

// Round-3 finding 3: the os-release probe keeps to --max-file-size.
func TestOSProbeMaxFileSize(t *testing.T) {
	host := testRegistry(t)
	ref := host + "/acme/big:1"
	pushImage(t, ref, map[string][]byte{"/etc/os-release": append([]byte("ID=ubuntu\n"), bytes.Repeat([]byte("#"), 2<<20)...)})
	tg := osOf(ref, engine.Options{MaxFileSize: 1 << 20})
	skipped := false
	for _, s := range tg.Skipped {
		if s.Path == "/etc/os-release" {
			skipped = true
		}
	}
	if !skipped {
		t.Errorf("a 2 MiB os-release was read past a 1 MiB limit: %+v", tg.Skipped)
	}
}
