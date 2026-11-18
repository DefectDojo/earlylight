package conf

import (
	"fmt"
	"strings"
)

// State is what a configuration says about one CVE's preconditions.
type State string

const (
	// Exposed: HTTP/2 is on where the CVE's published path needs it (over
	// TLS for CVE-2026-123007, with a proxy for CVE-2026-123633).
	Exposed State = "exposed"
	// Cleartext: HTTP/2 is on only without TLS (prior knowledge). The
	// published path for CVE-2026-123007 is through TLS.
	Cleartext State = "http2-cleartext-only"
	// NoProxy: HTTP/2 is on, but no server that has it passes requests
	// to an upstream (CVE-2026-123633 needs a reverse proxy).
	NoProxy State = "http2-without-proxy"
	// NotExposed: every file was read, and HTTP/2 is on nowhere.
	NotExposed State = "not-exposed"
	// Unknown: the configuration could not be read or settled.
	Unknown State = "unknown"
)

// Exposure is the configuration's answer.
type Exposure struct {
	// HTTP2 is "on", "off" or "unknown".
	HTTP2 string `json:"http2"`
	Flow  State  `json:"flow"`
	Reuse State  `json:"reuse"`
	// Where lists the directives that turn HTTP/2 on (file:line).
	Where []string `json:"where,omitempty"`
	// Proxy lists proxy directives in servers with HTTP/2 (file:line).
	Proxy []string `json:"proxy,omitempty"`
	// WorkerConnections is the events block's value, "" when unset
	// (nginx's default is 512).
	WorkerConnections string   `json:"worker_connections,omitempty"`
	Unread            []string `json:"unread,omitempty"`
}

var proxyDirectives = map[string]bool{"proxy_pass": true, "grpc_pass": true, "fastcgi_pass": true, "uwsgi_pass": true, "scgi_pass": true, "memcached_pass": true}

type listen struct {
	port      string
	ssl, http2 bool
	where     string
}

type server struct {
	listens []listen
	h2      string // the http2 directive in force: on, off or ""
	h2Where string
	ssl     bool // "ssl on;" (before 1.25.1)
	proxy   []string
	where   string
}

// Analyze reads a loaded configuration.
func Analyze(c *Config) Exposure {
	e := Exposure{Unread: c.Unread}
	var servers []server
	for _, d := range c.Root {
		switch d.Name {
		case "events":
			for _, x := range d.Block {
				if x.Name == "worker_connections" && len(x.Args) == 1 {
					e.WorkerConnections = x.Args[0]
				}
			}
		case "http":
			servers = append(servers, httpServers(d)...)
		}
	}
	// The listen socket's http2 parameter holds for every server on that
	// port. Ports are compared without their address, which can only
	// count more servers as having HTTP/2, never fewer.
	portH2 := map[string]string{}
	for _, s := range servers {
		for _, l := range s.listens {
			if l.http2 {
				portH2[l.port] = l.where
			}
		}
	}
	flow, clear, reuse, noProxy := false, false, false, false
	add := func(list *[]string, w string) {
		for _, x := range *list {
			if x == w {
				return
			}
		}
		if len(*list) < 16 {
			*list = append(*list, w)
		}
	}
	for _, s := range servers {
		for _, l := range s.listens {
			on, why := false, ""
			switch {
			case l.http2:
				on, why = true, l.where
			case portH2[l.port] != "":
				on, why = true, portH2[l.port]
			case s.h2 == "on":
				on, why = true, s.h2Where
			}
			if !on {
				continue
			}
			add(&e.Where, why)
			if l.ssl || s.ssl {
				flow = true
			} else {
				clear = true
			}
			if len(s.proxy) > 0 {
				reuse = true
				for _, p := range s.proxy {
					add(&e.Proxy, p)
				}
			} else {
				noProxy = true
			}
		}
	}
	settled := len(c.Unread) == 0 && len(c.Files) > 0
	on := flow || clear
	switch {
	case on:
		e.HTTP2 = "on"
	case settled:
		e.HTTP2 = "off"
	default:
		e.HTTP2 = "unknown"
	}
	e.Flow = decide(flow, clear, settled, Cleartext)
	e.Reuse = decide(reuse, noProxy, settled, NoProxy)
	return e
}

// decide: positive evidence wins; a weaker state only when everything was
// read (an unread include could hold the stronger one).
func decide(full, partial, settled bool, partialState State) State {
	switch {
	case full:
		return Exposed
	case partial && settled:
		return partialState
	case settled:
		return NotExposed
	}
	return Unknown
}

func httpServers(h Directive) []server {
	h2, h2Where, ssl := "", "", false
	for _, d := range h.Block {
		switch {
		case d.Name == "http2" && len(d.Args) == 1:
			h2, h2Where = strings.ToLower(d.Args[0]), loc(d)
		case d.Name == "ssl" && len(d.Args) == 1:
			ssl = strings.EqualFold(d.Args[0], "on")
		}
	}
	var out []server
	for _, d := range h.Block {
		if d.Name != "server" || !d.HasBlock {
			continue
		}
		s := server{h2: h2, h2Where: h2Where, ssl: ssl, where: loc(d)}
		for _, x := range d.Block {
			switch {
			case x.Name == "listen" && len(x.Args) > 0:
				s.listens = append(s.listens, parseListen(x))
			case x.Name == "http2" && len(x.Args) == 1:
				s.h2, s.h2Where = strings.ToLower(x.Args[0]), loc(x)
			case x.Name == "ssl" && len(x.Args) == 1:
				s.ssl = strings.EqualFold(x.Args[0], "on")
			}
		}
		if len(s.listens) == 0 {
			s.listens = []listen{{port: "80", where: s.where + " (no listen: *:80)"}}
		}
		proxies(d.Block, &s.proxy, 0)
		out = append(out, s)
	}
	return out
}

func proxies(ds []Directive, out *[]string, depth int) {
	if depth > maxDepth {
		return
	}
	for _, d := range ds {
		if proxyDirectives[d.Name] && len(*out) < 16 {
			*out = append(*out, loc(d))
		}
		if d.HasBlock {
			proxies(d.Block, out, depth+1)
		}
	}
}

func parseListen(d Directive) listen {
	l := listen{port: portOf(d.Args[0]), where: loc(d)}
	for _, a := range d.Args[1:] {
		switch strings.ToLower(a) {
		case "ssl":
			l.ssl = true
		case "http2":
			l.http2 = true
		}
	}
	return l
}

// portOf reads the port of a listen address: "443", "*:443",
// "[::]:443", "10.0.0.1:443", "localhost:443", "unix:/path".
func portOf(a string) string {
	if strings.HasPrefix(a, "unix:") {
		return a
	}
	if i := strings.LastIndexByte(a, ']'); i >= 0 {
		if p := strings.TrimPrefix(a[i+1:], ":"); p != "" {
			return p
		}
		return "80"
	}
	if i := strings.LastIndexByte(a, ':'); i >= 0 {
		return a[i+1:]
	}
	if a != "" && strings.Trim(a, "0123456789") == "" {
		return a
	}
	return "80" // an address without a port listens on 80
}

func loc(d Directive) string { return fmt.Sprintf("%s:%d", d.File, d.Line) }
