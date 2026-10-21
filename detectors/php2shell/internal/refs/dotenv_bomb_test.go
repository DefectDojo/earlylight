package refs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The doubling chain tried through a Compose .env file and Compose's own
// ${VAR:-default} interpolation: .env refuses variables inside values, so the
// chain never forms, and the scan stays fast.
func TestComposeExpansionBomb(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("A0=" + strings.Repeat("x", 64) + "\n")
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&b, "A%d=${A%d}${A%d}\n", i, i-1, i-1)
	}
	os.WriteFile(filepath.Join(dir, ".env"), []byte(b.String()), 0o600)
	nested := "${A0}"
	for i := 0; i < 15; i++ {
		nested = "${B:-" + nested + nested + "}"
	}
	os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: php:${A40}\n  deep:\n    image: php:"+nested+"\n  ok:\n    image: php:8.3.35-fpm\n"), 0o600)
	start := time.Now()
	refs, _, err := Scan(dir, Options{})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, r := range refs {
		if len(r.Image) > maxExpansion {
			t.Fatalf("an expanded reference of %d bytes got through", len(r.Image))
		}
		ok = ok || strings.Contains(r.Image, "8.3.35-fpm")
	}
	if !ok {
		t.Errorf("the plain reference was lost")
	}
}
