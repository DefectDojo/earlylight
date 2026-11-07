package sshole

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/DefectDojo/earlylight/detectors/sshole/internal/assess"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// probeUser is the user name the probe asks about. sshd lists the same
// methods for any name, and the probe never sends a password.
const probeUser = "earlylight-probe"

// errStop ends authentication once the server has offered password logins.
var errStop = errors.New("stop")

// glibcVendors are banner comments of distributions that build OpenSSH on
// glibc or a BSD libc: their servers are not affected.
var glibcVendors = []string{"Debian", "Ubuntu", "Raspbian", "FreeBSD", "NetBSD", "OpenBSD", "Fedora", "RHEL", "SUSE"}

// Probe connects to an SSH server (default port 22), reads its banner and
// asks which authentication methods it offers. It sends no password: when
// the server offers password logins, the client stops there.
func (d *Detector) Probe(ctx context.Context, addr string, timeout time.Duration) (string, int, []engine.Finding, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	host, port, err := net.SplitHostPort(addr)
	portGiven := err == nil
	if !portGiven {
		host, port = addr, "22"
	}
	target := net.JoinHostPort(host, port)
	dl := net.Dialer{Timeout: timeout}
	conn, err := dl.DialContext(ctx, "tcp", target)
	if err != nil {
		if !portGiven {
			return target, 0, nil, fmt.Errorf("%w: no SSH server answered on %s (%v)", engine.ErrNotApplicable, target, err)
		}
		return target, 0, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	rec := &bannerConn{Conn: conn}
	banner, err := rec.peekBanner()
	if err != nil || !strings.HasPrefix(banner, "SSH-") {
		return target, 0, nil, fmt.Errorf("%w: %s does not speak SSH", engine.ErrNotApplicable, target)
	}

	offered := false
	cfg := &ssh.ClientConfig{
		User: probeUser,
		Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
			offered = true
			return "", errStop
		})},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // inspection only: no secret is sent
		Timeout:         timeout,
	}
	_, _, _, herr := ssh.NewClientConn(rec, target, cfg)
	methodsKnown := offered || herr != nil && strings.Contains(herr.Error(), "unable to authenticate")

	f, ok := judgeBanner(target, banner, offered, methodsKnown)
	if !ok {
		return target, 1, nil, nil
	}
	return target, 1, []engine.Finding{f}, nil
}

// judgeBanner decides what a banner and the offered methods can tell. ok
// is false when the server is not an affected build (not OpenSSH, or a
// glibc distribution's).
func judgeBanner(target, banner string, offered, methodsKnown bool) (engine.Finding, bool) {
	soft := strings.TrimPrefix(strings.TrimPrefix(banner, "SSH-2.0-"), "SSH-1.99-")
	name, comment, _ := strings.Cut(soft, " ")
	if !strings.HasPrefix(name, "OpenSSH_") || strings.HasPrefix(name, "OpenSSH_for_Windows") {
		return engine.Finding{}, false
	}
	for _, v := range glibcVendors {
		if strings.Contains(comment, v) {
			return engine.Finding{}, false
		}
	}
	v, ok := assess.ParseRelease(name)
	f := engine.Finding{Kind: KindHost, Path: target, Method: "ssh-banner",
		Facts: map[string]string{"banner": banner, "password_offered": yes(offered)}}
	switch {
	case !ok:
		f.Verdict, f.Reason = engine.Unknown, "the banner's OpenSSH release could not be read"
		f.Message = "SSH server " + name
		return f, true
	case !v.Less(assess.FixedRelease):
		f.Verdict, f.Reason = engine.Fixed, "the banner reports OpenSSH "+v.String()+", which has the fix"
		f.Message = "OpenSSH " + v.String() + " has the *sshole fix"
		return f, true
	case v.Less(assess.FirstAffected):
		f.Verdict, f.Reason = engine.Fixed, "OpenSSH "+v.String()+" predates 7.3p1 and never borrows another account's salt"
		f.Message = "OpenSSH " + v.String() + " is not affected by *sshole"
		return f, true
	case methodsKnown && !offered:
		f.Verdict = engine.Inactive
		f.Reason = "the server does not offer password logins to this address (a Match block can still offer them to others)"
		f.Message = "OpenSSH " + v.String() + " does not offer password logins"
		return f, true
	}
	f.Verdict = engine.Unknown
	f.Reason = "a banner does not show the C library or a vendor backport: scan the host's filesystem (earlylight fs /) to decide"
	f.Message = fmt.Sprintf("OpenSSH %s reports a release before 10.6p2", v.String())
	if offered {
		f.Message += " and offers password logins"
	}
	f.Fix = "Scan the host with earlylight fs / --detector sshole. If sshd runs on musl, update OpenSSH to 10.6p2 or a vendor package with the fix, or set PasswordAuthentication no."
	f.Severity = "medium"
	return f, true
}

// bannerConn reads the server's identification line before the SSH client
// does, then replays it.
type bannerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bannerConn) peekBanner() (string, error) {
	c.r = bufio.NewReaderSize(c.Conn, 4096)
	// RFC 4253 allows other lines before the identification string.
	for i := 0; i < 16; i++ {
		b, err := c.r.Peek(c.r.Buffered() + 1)
		if err != nil && len(b) == 0 {
			return "", err
		}
		all, _ := c.r.Peek(c.r.Buffered())
		for _, line := range strings.Split(string(all), "\n") {
			if strings.HasPrefix(line, "SSH-") && strings.Contains(string(all), line+"\n") {
				return strings.TrimRight(line, "\r"), nil
			}
		}
		if err != nil {
			return "", err
		}
		if c.r.Buffered() >= 4096 {
			break
		}
	}
	return "", errors.New("no SSH identification line")
}

func (c *bannerConn) Read(p []byte) (int, error) {
	if c.r != nil {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}
