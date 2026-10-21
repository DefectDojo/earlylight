package archive

import (
	"bytes"
	"testing"
)

// A lying size hint may cost one allocation while reading, but the returned
// slice must not keep that allocation alive.
func TestLyingHintIsNotRetained(t *testing.T) {
	w := &walker{lim: DefaultLimits, budget: DefaultLimits.MaxArchiveSize}
	b, err := w.read(bytes.NewReader([]byte("tiny")), 16<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "tiny" || cap(b) > 1<<10 {
		t.Fatalf("len %d cap %d", len(b), cap(b))
	}
}
