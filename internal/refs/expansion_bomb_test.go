package refs

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A chain of ARGs that each double the last must not exhaust memory or time:
// the expansion stops at maxExpansion and the FROM is reported, not resolved.
func TestARGExpansionBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("ARG A0=" + strings.Repeat("x", 64) + "\n")
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&b, "ARG A%d=${A%d}${A%d}\"$A%d$A%d\"\n", i, i-1, i-1, i-1, i-1)
	}
	b.WriteString("FROM php:${A40}\nFROM php:8.3.35-fpm\n")
	s := &scanner{root: t.TempDir()}
	start := time.Now()
	s.dockerfile("Dockerfile", []byte(b.String()))
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
	found := false
	for _, r := range s.refs {
		if strings.Contains(r.Image, "8.3.35-fpm") {
			found = true
		}
		if len(r.Image) > maxExpansion {
			t.Fatalf("an expanded reference of %d bytes got through", len(r.Image))
		}
	}
	if !found {
		t.Errorf("the plain FROM after the bomb was lost: %+v", s.refs)
	}
}
