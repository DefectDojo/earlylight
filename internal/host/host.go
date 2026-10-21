// Package host fetches the certificate chain a TLS server presents.
package host

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"time"
)

// Chain connects to addr ("host" or "host:port", default port 443) and returns the
// certificates the server sent. It does not verify them: the point is to inspect
// exactly what the server presents.
func Chain(addr string, timeout time.Duration) (string, []*x509.Certificate, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "443"
	}
	target := net.JoinHostPort(host, port)
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", target, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // inspection only; nothing is sent over this connection
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return target, nil, err
	}
	defer conn.Close()
	return target, conn.ConnectionState().PeerCertificates, nil
}
