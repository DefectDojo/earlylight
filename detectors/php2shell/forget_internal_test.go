package php2shell

import (
	"fmt"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/detect"
)

// When an image names a path again, what was kept of the first entry is
// dropped.
func TestForget(t *testing.T) {
	c := &collector{dbFiles: map[string][]byte{"/var/lib/dpkg/status": []byte("x")}}
	c.keep(&detect.Binary{Path: "/usr/bin/php"})
	c.keep(&detect.Binary{Path: "/usr/bin/php8"})
	c.Forget("/var/lib/dpkg/status")
	c.Forget("/usr/bin/php")
	if bs := c.kept(); len(c.dbFiles) != 0 || len(bs) != 1 || bs[0].Path != "/usr/bin/php8" {
		t.Errorf("db %v binaries %+v", c.dbFiles, bs)
	}
	c.keep(&detect.Binary{Path: "/usr/bin/php"})
	if bs := c.kept(); len(bs) != 2 || bs[1].Path != "/usr/bin/php" {
		t.Errorf("binaries %+v", bs)
	}
}

// Final review A6: forgetting a path costs what the path held, not every
// binary kept.
func TestForgetIsCheap(t *testing.T) {
	c := &collector{dbFiles: map[string][]byte{}}
	for i := 0; i < 20000; i++ {
		c.keep(&detect.Binary{Path: fmt.Sprintf("/usr/bin/php%d", i)})
	}
	start := time.Now()
	for i := 0; i < 100000; i++ {
		c.Forget("/x")
		c.keep(&detect.Binary{Path: "/x"})
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("100,000 repeats over 20,000 binaries took %s", d)
	}
	if n := len(c.kept()); n != 20001 {
		t.Errorf("%d binaries, want 20001", n)
	}
}
