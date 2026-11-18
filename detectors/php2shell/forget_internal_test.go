package php2shell

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/detect"
)

// When an image names a path again, what was kept of the first entry is
// dropped.
func TestForget(t *testing.T) {
	c := &collector{dbFiles: map[string][]byte{"/var/lib/dpkg/status": []byte("x")},
		binaries: []*detect.Binary{{Path: "/usr/bin/php"}, {Path: "/usr/bin/php8"}}}
	c.Forget("/var/lib/dpkg/status")
	c.Forget("/usr/bin/php")
	if len(c.dbFiles) != 0 || len(c.binaries) != 1 || c.binaries[0].Path != "/usr/bin/php8" {
		t.Errorf("db %v binaries %+v", c.dbFiles, c.binaries)
	}
}
