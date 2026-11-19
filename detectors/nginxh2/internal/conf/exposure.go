package conf

import (
	"fmt"
	"regexp"
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

// proxyDirectives open connections to an upstream while a request is
// served (the pressure CVE-2026-123633 needs): the *_pass directives,
// subrequests, and handlers that can open sockets of their own (Lua
// cosockets, njs fetch, Perl).
var proxyDirectives = map[string]bool{"proxy_pass": true, "grpc_pass": true, "fastcgi_pass": true, "uwsgi_pass": true, "scgi_pass": true, "memcached_pass": true,
	"redis_pass": true, "redis2_pass": true, "postgres_pass": true, "drizzle_pass": true, "auth_request": true, "mirror": true,
	"js_content": true, "js_access": true, "perl": true}

// proxyHandler reports an OpenResty handler that can open its own
// connections (content_by_lua_block, access_by_lua_file, balancer_by_lua*).
func proxyHandler(name string) bool {
	return strings.Contains(name, "_by_lua")
}

type listen struct {
	port       string
	ssl, http2 bool
	dflt       bool // default_server
	where      string
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
	e := Exposure{Unread: append([]string(nil), c.Unread...)}
	var servers []server
	unsettled := func(msg string) {
		if len(e.Unread) < 64 {
			e.Unread = append(e.Unread, msg)
		}
	}
	placeholders(c.Root, unsettled, 0)
	for _, d := range c.Root {
		switch d.Name {
		case "events":
			for _, x := range d.Block {
				if x.Name == "worker_connections" && len(x.Args) == 1 {
					e.WorkerConnections = x.Args[0]
				}
			}
		case "http":
			servers = append(servers, httpServers(d, unsettled)...)
		}
	}
	// nginx keeps one socket per address and port: its ssl and http2
	// parameters, set on any listen of it, hold for every server on it, and
	// the default server's "http2 on" holds for connections that do not
	// select another server (no TLS, or no SNI). Ports are compared
	// without their address, which can only count more servers as
	// exposed, never fewer.
	portH2, portSSL, dflt := map[string]string{}, map[string]bool{}, map[string]int{}
	for i, s := range servers {
		for _, l := range s.listens {
			if l.http2 {
				portH2[l.port] = l.where
			}
			if l.ssl || s.ssl {
				portSSL[l.port] = true
			}
			if _, ok := dflt[l.port]; !ok || l.dflt {
				dflt[l.port] = i
			}
		}
	}
	for port, i := range dflt {
		if servers[i].h2 == "on" && portH2[port] == "" {
			portH2[port] = servers[i].h2Where + " (the default server of port " + port + ")"
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
			case s.h2 == "on":
				on, why = true, s.h2Where
			case portH2[l.port] != "":
				on, why = true, portH2[l.port]
			}
			if !on {
				continue
			}
			add(&e.Where, why)
			if l.ssl || s.ssl || portSSL[l.port] {
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
	settled := len(e.Unread) == 0 && len(c.Files) > 0
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

func httpServers(h Directive, unsettled func(string)) []server {
	h2, h2Where, ssl := "", "", false
	h2Value := func(d Directive) string {
		v := strings.ToLower(d.Args[0])
		if v != "on" && v != "off" {
			// A template variable or anything else: decided where it
			// runs, so not off.
			unsettled(fmt.Sprintf("http2 at %s is %q, which is decided where it runs", loc(d), d.Args[0]))
		}
		return v
	}
	for _, d := range h.Block {
		switch {
		case d.Name == "http2" && len(d.Args) == 1:
			h2, h2Where = h2Value(d), loc(d)
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
				l := parseListen(x)
				for _, a := range x.Args {
					if strings.Contains(a, "$") {
						unsettled(fmt.Sprintf("listen at %s has %q, which is decided where it runs", loc(x), a))
					}
				}
				s.listens = append(s.listens, l)
			case x.Name == "http2" && len(x.Args) == 1:
				s.h2, s.h2Where = h2Value(x), loc(x)
			case x.Name == "ssl" && len(x.Args) == 1:
				s.ssl = strings.EqualFold(x.Args[0], "on")
			}
		}
		if len(s.listens) == 0 {
			// *:80, or *:8000 when nginx does not run as root.
			s.listens = []listen{{port: "80", where: s.where + " (no listen: *:80)"}, {port: "8000", where: s.where + " (no listen: *:8000 when not root)"}}
		}
		proxies(d.Block, &s.proxy, 0)
		out = append(out, s)
	}
	return out
}

// placeholders reports a directive whose name is a variable (a template's
// ${EXTRA_DIRECTIVES} left unset): what it stands for is decided where
// the configuration runs.
func placeholders(ds []Directive, unsettled func(string), depth int) {
	if depth > maxDepth {
		return
	}
	for _, d := range ds {
		if placeholder.MatchString(d.Name) {
			unsettled(fmt.Sprintf("%s at %s stands for directives decided where it runs", d.Name, loc(d)))
		}
		if d.HasBlock && !valueBlocks[d.Name] {
			placeholders(d.Block, unsettled, depth+1)
		}
	}
}

// placeholder is a directive name that is one variable and nothing else
// (${EXTRA_DIRECTIVES}, $EXTRA): what a template leaves unset.
var placeholder = regexp.MustCompile(`^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)$`)

// valueBlocks hold keys and values, not directives: a key there may be
// anything ("~*(bot|crawler)$" in a map).
var valueBlocks = map[string]bool{"map": true, "geo": true, "split_clients": true, "types": true, "charset_map": true}

func proxies(ds []Directive, out *[]string, depth int) {
	if depth > maxDepth {
		return
	}
	for _, d := range ds {
		if (proxyDirectives[d.Name] || proxyHandler(d.Name)) && len(*out) < 16 {
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
		case "default_server", "default":
			l.dflt = true
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
