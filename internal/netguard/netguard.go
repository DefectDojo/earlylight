// Package netguard is the HTTP transport for registry lookups. Image references
// come from the repository being scanned, which may not be yours (a pull request
// from a fork, a third-party project), so a reference must not be able to make
// the scanner call an address that is not a registry.
//
// Link-local addresses, which include every cloud metadata service
// (169.254.169.254, fd00:ec2::254), are always refused: no registry lives there.
// With PublicOnly, loopback, private (RFC 1918), carrier-grade NAT, IPv6
// unique-local and unspecified addresses are refused too, which is the setting
// for untrusted repositories. Addresses are checked after DNS on every
// connection, including redirects. With PublicOnly no proxy is used, so every
// connection is a checked direct dial: a proxy resolves names itself, and a name
// that resolves differently there (DNS rebinding) would escape the check.
// Without PublicOnly the environment's proxy is honoured and the target's
// addresses are checked before the request is handed to it.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"
)

var (
	cgnat = mustCIDR("100.64.0.0/10")
	nat64 = mustCIDR("64:ff9b::/96")
	// Prefixes that carry or translate to an IPv4 address this check cannot
	// see reliably: local-use NAT64 (RFC 8215), 6to4, Teredo. No registry is
	// reached through them, so they are refused.
	tunnels = []*net.IPNet{mustCIDR("64:ff9b:1::/48"), mustCIDR("2002::/16"), mustCIDR("2001::/32")}
	global6 = mustCIDR("2000::/3")
	ec2v6   = net.ParseIP("fd00:ec2::254")
	alibab  = net.ParseIP("100.100.100.200") // Alibaba Cloud metadata
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Check returns an error when ip must not be contacted.
func Check(ip net.IP, publicOnly bool) error {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else if nat64.Contains(ip) {
		// 64:ff9b::a.b.c.d reaches IPv4 a.b.c.d through NAT64.
		ip = net.IP(ip[12:16])
	}
	for _, n := range tunnels {
		if n.Contains(ip) {
			return fmt.Errorf("refusing to contact %s: a tunnelled or translated IPv6 address, not a registry", ip)
		}
	}
	switch {
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.Equal(ec2v6), ip.Equal(alibab):
		return fmt.Errorf("refusing to contact %s: a link-local or cloud metadata address, not a registry", ip)
	case !publicOnly:
		return nil
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsUnspecified(), cgnat.Contains(ip), ip.IsMulticast():
		return fmt.Errorf("refusing to contact %s: not a public address (--public-registries-only)", ip)
	case ip.To4() == nil && !global6.Contains(ip):
		return fmt.Errorf("refusing to contact %s: not a global unicast IPv6 address (--public-registries-only)", ip)
	}
	return nil
}

// Transport returns a guarded transport based on Go's default one.
func Transport(publicOnly bool) http.RoundTripper {
	d := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("refusing to contact %q: not an IP address", host)
			}
			return Check(ip, publicOnly)
		},
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 30 * time.Second
	if publicOnly {
		t.Proxy = nil
		t.DialContext = d.DialContext
		return t
	}
	var proxies sync.Map // proxy host:port -> true; Proxy runs concurrently
	t.Proxy = func(req *http.Request) (*url.URL, error) {
		u, err := http.ProxyFromEnvironment(req)
		if u != nil {
			proxies.Store(u.Host, true)
		}
		return u, err
	}
	plain := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, ok := proxies.Load(addr); ok {
			// The proxy is the operator's; the target was checked in RoundTrip.
			return plain.DialContext(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}
	return &guarded{next: t, publicOnly: publicOnly, lookup: net.DefaultResolver.LookupIPAddr}
}

type guarded struct {
	next       http.RoundTripper
	publicOnly bool
	lookup     func(context.Context, string) ([]net.IPAddr, error)
}

// RoundTrip checks a proxied request's target before the proxy sees it. A direct
// request is checked by the dialer.
func (g *guarded) RoundTrip(req *http.Request) (*http.Response, error) {
	if p, err := http.ProxyFromEnvironment(req); err == nil && p != nil {
		host := req.URL.Hostname()
		if ip := net.ParseIP(host); ip != nil {
			if err := Check(ip, g.publicOnly); err != nil {
				return nil, err
			}
		} else {
			addrs, err := g.lookup(req.Context(), host)
			if err != nil {
				return nil, fmt.Errorf("resolving %s: %w", host, err)
			}
			for _, a := range addrs {
				if err := Check(a.IP, g.publicOnly); err != nil {
					return nil, err
				}
			}
		}
	}
	return g.next.RoundTrip(req)
}
