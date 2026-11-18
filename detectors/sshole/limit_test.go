package sshole_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/DefectDojo/earlylight/detectors/emudhra" // a detector that reads every file
	"github.com/DefectDojo/earlylight/detectors/sshole/internal/testelf"
	"github.com/DefectDojo/earlylight/internal/cli"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// maxKept is the most sshole reads of a file its verdict depends on.
const maxKept = 4 << 20

// padded writes data followed by zeros up to size bytes (sparse).
func padded(t *testing.T, root, rel string, data []byte, size int64) {
	t.Helper()
	write(t, root, rel, data, 0o644)
	if err := os.Truncate(filepath.Join(root, rel), size); err != nil {
		t.Fatal(err)
	}
}

// scanExit runs a JSON scan and returns its findings, skips and exit status.
func scanExit(t *testing.T, args ...string) ([]engine.Finding, []struct {
	Path     string `json:"path"`
	Excluded bool   `json:"excluded"`
}, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Run(cfg, append([]string{"scan", "fs", "--format", "json"}, args...), &out, &errb)
	var r struct {
		Targets []struct {
			Findings []engine.Finding `json:"findings"`
			Skipped  []struct {
				Path     string `json:"path"`
				Excluded bool   `json:"excluded"`
			} `json:"skipped"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Targets) != 1 {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errb.String())
	}
	return r.Targets[0].Findings, r.Targets[0].Skipped, code
}

// pamRoot is alpineRoot with sshd built with PAM and UsePAM yes after an
// Include of sshd_config.d.
func pamRoot(t *testing.T) string {
	root := alpineRoot(t, "10.0_p1-r10")
	write(t, root, "usr/sbin/sshd", testelf.ELF("/lib/ld-musl-x86_64.so.1", []string{"libc.musl-x86_64.so.1", "libpam.so.0"},
		testelf.SSHDStrings("10.0p2", "/usr/lib/ssh/sshd-session", "/usr/lib/ssh/sshd-auth")...), 0o755)
	write(t, root, "etc/ssh/sshd_config", []byte("Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"), 0o644)
	return root
}

// Review finding 1: an included file over the limit that may turn PAM off
// keeps the server from being cleared, and is a coverage gap.
func TestIncludeOverLimitNeverClears(t *testing.T) {
	root := pamRoot(t)
	fs, _, _ := scanExit(t, "--detector", "sshole", "--as-root", root)
	if len(fs) != 1 || fs[0].Verdict != engine.Inactive {
		t.Fatalf("PAM on, nothing included: %+v", fs)
	}
	write(t, root, "etc/ssh/sshd_config.d/50-site.conf", []byte("UsePAM no\n"), 0o644)
	fs, _, _ = scanExit(t, "--detector", "sshole", "--as-root", root)
	if len(fs) != 1 || fs[0].Verdict != engine.Vulnerable || fs[0].Severity != "critical" {
		t.Fatalf("a small include turning PAM off: %+v", fs)
	}
	padded(t, root, "etc/ssh/sshd_config.d/50-site.conf", []byte("UsePAM no\n"), maxKept+1)
	for _, extra := range [][]string{nil, {"--detector", "emudhra"}} {
		args := append(append([]string{"--detector", "sshole"}, extra...), "--as-root", "--fail-on-skip", root)
		fs, skipped, code := scanExit(t, args...)
		var got []engine.Finding
		for _, f := range fs {
			if f.Detector == "sshole" {
				got = append(got, f)
			}
		}
		if len(got) != 1 || got[0].Verdict.Cleared() || got[0].Verdict != engine.Unknown || !strings.Contains(got[0].Reason, "50-site.conf") {
			t.Errorf("with %v, an include over the limit: %+v", extra, got)
		}
		gap := false
		for _, s := range skipped {
			gap = gap || s.Path == "/etc/ssh/sshd_config.d/50-site.conf" && !s.Excluded
		}
		if !gap || code != 3 {
			t.Errorf("with %v: exit %d, skipped %+v", extra, code, skipped)
		}
	}
}

// Review finding 2: a login shell over the script limit still exists, so
// the verdict is the same as for a small one, with or without other
// detectors.
func TestShellOverLimitExists(t *testing.T) {
	verdict := func(script []byte, size int64, extra ...string) string {
		root := alpineRoot(t, "10.0_p1-r10")
		write(t, root, "etc/passwd", []byte("root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/usr/local/bin/menu\n"), 0o644)
		padded(t, root, "usr/local/bin/menu", script, size)
		fs, _, _ := scanExit(t, append(append([]string{"--detector", "sshole"}, extra...), "--as-root", root)...)
		for _, f := range fs {
			if f.Detector == "sshole" {
				return string(f.Verdict) + "/" + f.Severity
			}
		}
		return "none"
	}
	script := []byte("#!/bin/sh\nexec /bin/sh\n")
	small := verdict(script, int64(len(script)))
	if small != "vulnerable/critical" {
		t.Fatalf("small shell: %s", small)
	}
	if big := verdict(script, 300<<10); big != small {
		t.Errorf("a 300 KiB shell: %s, a small one: %s", big, small)
	}
	if big := verdict(script, 300<<10, "--detector", "emudhra"); big != small {
		t.Errorf("a 300 KiB shell with emudhra: %s, a small one: %s", big, small)
	}
}

// --fail-on-skip: a start script over the limit is a deliberate exclusion
// (the startup analysis never clears a server), an account file over it a
// gap.
func TestFailOnSkipWithLimits(t *testing.T) {
	root := alpineRoot(t, "10.0_p1-r11") // fixed: exit 0 when nothing is a gap
	padded(t, root, "opt/install.sh", []byte("#!/bin/sh\n"), 300<<10)
	_, skipped, code := scanExit(t, "--detector", "sshole", "--as-root", "--fail-on-skip", root)
	if code != 0 || len(skipped) != 1 || !skipped[0].Excluded {
		t.Errorf("a large script: exit %d skipped %+v", code, skipped)
	}
	padded(t, root, "etc/shadow", []byte("root:*::0:::::\n"), maxKept+1)
	_, skipped, code = scanExit(t, "--detector", "sshole", "--as-root", "--fail-on-skip", root)
	if code != 3 || len(skipped) != 2 {
		t.Errorf("a large /etc/shadow: exit %d skipped %+v", code, skipped)
	}
}
