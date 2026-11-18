package emudhra_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

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
