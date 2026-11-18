package emudhra_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/internal/cli"
)

// Round-2 review finding 1: botocore's bundle is cleared only on a certifi
// bundle that was read and checked, not one too large to read.
func TestBotocoreNotClearedByUnreadCertifi(t *testing.T) {
	g3, err := os.ReadFile(filepath.Join(g3Bundle(t), "cacert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	site := "usr/lib/python3/site-packages"
	for _, c := range []struct {
		name    string
		certifi []byte
		want    int
	}{
		{"read certifi", []byte("# empty bundle\n"), 0},
		{"unread certifi", bytes.Repeat([]byte("#"), 5000), 1},
		{"unread certifi holding the CA", append(g3, bytes.Repeat([]byte("#"), 5000)...), 1},
	} {
		root := t.TempDir()
		for rel, b := range map[string][]byte{site + "/botocore/cacert.pem": g3, site + "/certifi/cacert.pem": c.certifi} {
			p := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var out, errb bytes.Buffer
		code := cli.Run(engine, []string{"scan", "fs", "--detector", "emudhra", "--as-root", "--max-file-size", "4096", root}, &out, &errb)
		if code != c.want {
			t.Errorf("%s: exit %d, want %d\n%s%s", c.name, code, c.want, out.String(), errb.String())
		}
	}
}

// Round-3 review finding 2: of two image entries for certifi's bundle, the
// last is the file: one over --max-file-size after a read one does not
// clear botocore's bundle.
func TestCertifiNamedTwice(t *testing.T) {
	g3, err := os.ReadFile(filepath.Join(g3Bundle(t), "cacert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	site := "usr/lib/python3/site-packages/"
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct {
		name string
		body []byte
	}{
		{site + "botocore/cacert.pem", g3},
		{site + "certifi/cacert.pem", []byte("# empty bundle\n")},
		{site + "certifi/cacert.pem", append(g3, bytes.Repeat([]byte("#"), 5000)...)},
	} {
		tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg})
		tw.Write(e.body)
	}
	tw.Close()
	img := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(img, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := cli.Run(engine, []string{"scan", "image", "--detector", "emudhra", "--max-file-size", "4096", "rootfs:" + img}, &out, &errb); code != 1 {
		t.Errorf("exit %d, want 1\n%s%s", code, out.String(), errb.String())
	}
}

// Final review finding 5: forgetting a path costs what the path held, not
// every finding kept: an image that repeats paths stays linear.
func TestForgetIsCheap(t *testing.T) {
	g3, err := os.ReadFile(filepath.Join(g3Bundle(t), "cacert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, body []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write(body)
	}
	for i := 0; i < 2000; i++ {
		add(fmt.Sprintf("certs/%d.pem", i), g3)
	}
	for i := 0; i < 20000; i++ {
		add("certs/0.pem", []byte("x"))
	}
	tw.Close()
	img := filepath.Join(t.TempDir(), "rootfs.tar")
	if err := os.WriteFile(img, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	var out, errb bytes.Buffer
	if code := cli.Run(engine, []string{"scan", "image", "--detector", "emudhra", "--format", "json", "rootfs:" + img}, &out, &errb); code != 1 {
		t.Fatalf("exit %d %s", code, errb.String())
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("2,000 findings and 20,000 repeats took %s", d)
	}
	var r struct {
		Targets []struct {
			Findings []struct {
				Path string `json:"path"`
			} `json:"findings"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Targets) != 1 {
		t.Fatalf("%v", err)
	}
	for _, f := range r.Targets[0].Findings {
		if f.Path == "/certs/0.pem" {
			t.Errorf("a finding in the replaced entry survived")
		}
	}
	if n := len(r.Targets[0].Findings); n != 1999 {
		t.Errorf("%d findings, want 1999", n)
	}
}
