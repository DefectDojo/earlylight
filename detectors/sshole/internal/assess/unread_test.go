package assess

import (
	"fmt"
	"strings"
	"testing"
)

// unreadFiles lists some files that Read cannot give (over the limit).
type unreadFiles struct {
	memFiles
	unread []string
}

func (u unreadFiles) Glob(pattern string) []string {
	out := u.memFiles.Glob(pattern)
	for _, p := range u.unread {
		if strings.HasPrefix(p, strings.TrimSuffix(pattern, "*.conf")) {
			out = append(out, p)
		}
	}
	return out
}

// What the configuration names but was not read is listed as unread: an
// included file Read cannot give, and anything past the parser's limits.
func TestConfigUnread(t *testing.T) {
	fs := unreadFiles{memFiles{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n"}, []string{"/etc/ssh/sshd_config.d/50-site.conf"}}
	c := ParseConfig(fs, "/etc/ssh/sshd_config")
	if strings.Join(c.Unread, ",") != "/etc/ssh/sshd_config.d/50-site.conf" || c.Global("usepam", "no") != "yes" {
		t.Errorf("unread %v", c.Unread)
	}
	m := memFiles{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n"}
	for i := 0; i <= maxIncludes; i++ {
		m[fmt.Sprintf("/etc/ssh/sshd_config.d/%03d.conf", i)] = "Port 22\n"
	}
	if c := ParseConfig(m, "/etc/ssh/sshd_config"); len(c.Unread) != 1 || !strings.Contains(c.Unread[0], "more than 256") {
		t.Errorf("past the include limit: unread %v", c.Unread)
	}
	// Includes nested past the parser's depth.
	m = memFiles{}
	for i := 0; i <= 17; i++ {
		m[fmt.Sprintf("/etc/ssh/%d.conf", i)] = fmt.Sprintf("Include /etc/ssh/%d.conf\n", i+1)
	}
	m["/etc/ssh/sshd_config"] = "Include /etc/ssh/0.conf\n"
	if c := ParseConfig(m, "/etc/ssh/sshd_config"); len(c.Unread) != 1 || !strings.Contains(c.Unread[0], "nested too deeply") {
		t.Errorf("nested too deeply: unread %v", c.Unread)
	}
	// Directives past the parser's limit.
	if c := ParseConfig(memFiles{"/etc/ssh/sshd_config": strings.Repeat("Port 22\n", maxDirectives+1) + "UsePAM no\n"}, "/etc/ssh/sshd_config"); len(c.Unread) != 1 || !strings.Contains(c.Unread[0], "directives") {
		t.Errorf("past the directive limit: unread %v", c.Unread)
	}
	if c := ParseConfig(memFiles{"/etc/ssh/sshd_config": "UsePAM yes\n"}, "/etc/ssh/sshd_config"); len(c.Unread) != 0 {
		t.Errorf("all read: unread %v", c.Unread)
	}
}
