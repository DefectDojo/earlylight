package detect

import (
	"bytes"
	"strings"
	"testing"
)

// fakeELF builds bytes that look like a PHP runtime: an ELF header, then the
// two compiled-in strings, each NUL-terminated, among other data.
func fakeELF(parts ...string) []byte {
	var b bytes.Buffer
	b.WriteString("\x7fELF\x02\x01\x01\x00")
	b.Write(make([]byte, 64))
	for _, p := range parts {
		b.WriteString(p)
		b.WriteByte(0)
		b.Write([]byte("padding\x00\x00"))
	}
	return b.Bytes()
}

func php(v, zend string) []byte {
	return fakeELF("X-Powered-By: PHP/"+v, "Zend Engine v"+zend+", Copyright (c) Zend Technologies\n")
}

func TestInspect(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		data    []byte
		version string
		sapi    string
		problem string
		none    bool
	}{
		{name: "official fpm", path: "/usr/local/sbin/php-fpm", data: php("8.3.35", "4.3.35"), version: "8.3.35", sapi: "fpm-fcgi"},
		{name: "apache module", path: "/usr/lib/apache2/modules/libphp.so", data: php("8.3.35", "4.3.35"), version: "8.3.35", sapi: "apache2handler"},
		{name: "debian module", path: "/usr/lib/apache2/modules/libphp8.2.so", data: php("8.2.34", "4.2.34"), version: "8.2.34", sapi: "apache2handler"},
		{name: "debian embed", path: "/usr/lib/libphp8.2.so", data: php("8.2.34", "4.2.34"), version: "8.2.34", sapi: "embed"},
		{name: "alpine cli", path: "/usr/bin/php83", data: php("8.3.29", "4.3.29"), version: "8.3.29", sapi: "cli"},
		{name: "cgi", path: "/usr/bin/php-cgi8.3", data: php("8.3.6", "4.3.6"), version: "8.3.6", sapi: "cgi-fcgi"},
		{name: "windows dll", path: "/php/php8ts.dll", data: append([]byte("MZ"), php("8.4.1", "4.4.1")[4:]...), version: "8.4.1", sapi: "core-library"},
		{name: "php 7 has its own zend numbering", path: "/usr/bin/php7.4", data: php("7.4.3", "3.4.0"), version: "7.4.3", sapi: "cli"},
		{name: "php 5", path: "/usr/bin/php5", data: php("5.5.9-1ubuntu4.29", "2.5.0"), version: "5.5.9-1ubuntu4.29", sapi: "cli"},
		{name: "rc", path: "/usr/local/bin/php", data: php("8.5.0RC2", "4.5.0RC2"), version: "8.5.0RC2", sapi: "cli"},
		{name: "zend mismatch", path: "/usr/local/bin/php", data: php("8.3.36", "4.3.35"), version: "8.3.36", sapi: "cli", problem: "does not match Zend engine"},
		{name: "two versions", path: "/usr/local/bin/php", data: fakeELF("X-Powered-By: PHP/8.3.35", "X-Powered-By: PHP/8.3.36", "Zend Engine v4.3.35, Copyright (c) Zend Technologies"), version: "8.3.35", sapi: "cli", problem: "several PHP versions"},
		{name: "not an executable", path: "/usr/share/doc/php/README", data: []byte("X-Powered-By: PHP/8.3.35\x00Zend Engine v4.3.35, Copyright (c)\x00"), none: true},
		{name: "header without the engine string", path: "/usr/bin/nuclei", data: fakeELF("X-Powered-By: PHP/5.2.17"), none: true},
		{name: "engine string without the header", path: "/usr/bin/x", data: fakeELF("Zend Engine v4.3.35, Copyright (c) Zend Technologies"), none: true},
		{name: "header not NUL-terminated", path: "/usr/bin/x", data: append(php("8.3.35", "4.3.35")[:0:0], []byte("\x7fELF....X-Powered-By: PHP/8.3.35 and more\x00Zend Engine v4.3.35, Copyright (c)\x00")...), none: true},
		{name: "header without a version", path: "/usr/bin/php2shell-scan", data: fakeELF("X-Powered-By: PHP/", "Zend Engine v4.3.35, Copyright (c)"), none: true},
		{name: "java class file", path: "/app/X.class", data: append([]byte("\xca\xfe\xba\xbe\x00\x00\x00\x41"), php("8.3.35", "4.3.35")[8:]...), none: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := Inspect(c.path, c.data)
			if c.none {
				if b != nil {
					t.Fatalf("got %+v, want nothing", b)
				}
				return
			}
			if b == nil {
				t.Fatal("not recognised")
			}
			if b.Version != c.version || b.SAPI != c.sapi {
				t.Errorf("got version %q sapi %q, want %q %q", b.Version, b.SAPI, c.version, c.sapi)
			}
			if c.problem == "" && b.Problem != "" || !strings.Contains(b.Problem, c.problem) {
				t.Errorf("problem %q, want %q", b.Problem, c.problem)
			}
			if len(b.MD5) != 16 || len(b.SHA1) != 20 || len(b.SHA256) != 32 {
				t.Error("digests not computed")
			}
		})
	}
}

func TestExecutable(t *testing.T) {
	yes := [][]byte{[]byte("\x7fELF"), []byte("MZ\x90\x00"), []byte("\xcf\xfa\xed\xfe"), []byte("\xca\xfe\xba\xbe\x00\x00\x00\x02")}
	no := [][]byte{[]byte("#!/bin/sh"), []byte("<?php"), []byte("\xca\xfe\xba\xbe\x00\x00\x00\x34"), nil, []byte("\x7fEL")}
	for _, h := range yes {
		if !Executable(h) {
			t.Errorf("%q not recognised", h)
		}
	}
	for _, h := range no {
		if Executable(h) {
			t.Errorf("%q recognised", h)
		}
	}
}

func FuzzInspect(f *testing.F) {
	f.Add(php("8.3.35", "4.3.35"))
	f.Add(fakeELF("X-Powered-By: PHP/8.3.35", "X-Powered-By: PHP/"))
	f.Add([]byte("\x7fELFX-Powered-By: PHP/8\x00Zend Engine v"))
	f.Fuzz(func(t *testing.T, data []byte) {
		b := Inspect("/usr/bin/php", data)
		if b == nil {
			return
		}
		if !bytes.Contains(data, append(append([]byte{}, Marker...), b.Version...)) {
			t.Fatalf("version %q not in data", b.Version)
		}
		if len(b.Version) > maxVersionLen {
			t.Fatalf("version too long: %d", len(b.Version))
		}
	})
}
