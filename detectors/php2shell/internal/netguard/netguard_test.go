package netguard

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	always := []string{"169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200", "64:ff9b::a9fe:a9fe",
		"64:ff9b:1::a9fe:a9fe", "2002:a9fe:a9fe::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"}
	publicOnly := []string{"127.0.0.1", "::1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "100.64.0.1", "fd12::1", "0.0.0.0", "::ffff:10.0.0.1"}
	public := []string{"93.184.216.34", "2606:4700::1111", "64:ff9b::5db8:d822"}
	if Check(net.ParseIP("fc00::1"), true) == nil || Check(net.ParseIP("100::1"), true) == nil {
		t.Error("non-global IPv6 allowed with public-only")
	}
	for _, s := range always {
		if Check(net.ParseIP(s), false) == nil {
			t.Errorf("%s allowed by default", s)
		}
	}
	for _, s := range publicOnly {
		if Check(net.ParseIP(s), false) != nil {
			t.Errorf("%s refused by default (internal registries are allowed)", s)
		}
		if Check(net.ParseIP(s), true) == nil {
			t.Errorf("%s allowed with public-only", s)
		}
	}
	for _, s := range public {
		if Check(net.ParseIP(s), true) != nil {
			t.Errorf("%s refused", s)
		}
	}
}

func TestTransportRefusesAtDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := &http.Client{Transport: Transport(true)}
	if _, err := c.Get(srv.URL); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("loopback reached with public-only: %v", err)
	}
	c = &http.Client{Transport: Transport(false)}
	if resp, err := c.Get(srv.URL); err != nil {
		t.Fatalf("loopback refused by default: %v", err)
	} else {
		resp.Body.Close()
	}
}

func TestPublicOnlyIgnoresProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	tr := Transport(true).(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("public-only transport uses a proxy")
	}
}
