package nginxh2

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/netguard"
)

// apkMirror is where fix reads an Alpine branch's package index.
const apkMirror = "https://dl-cdn.alpinelinux.org/alpine"

// maxAPKIndex bounds the index fix reads (main/x86_64 is a few MiB).
const maxAPKIndex = 32 << 20

var apkBranch = regexp.MustCompile(`^(?:edge|3\.\d{1,2})$`)

// apkIndex returns the nginx version in an Alpine branch's main index,
// read through the guarded transport within the timeout.
func apkIndex(o engine.Options) func(context.Context, string) (string, error) {
	return func(ctx context.Context, branch string) (string, error) {
		if !apkBranch.MatchString(branch) {
			return "", fmt.Errorf("%q is not an Alpine branch", branch)
		}
		dir := branch
		if branch != "edge" {
			dir = "v" + branch
		}
		timeout := o.Timeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apkMirror+"/"+dir+"/main/x86_64/APKINDEX.tar.gz", nil)
		if err != nil {
			return "", err
		}
		resp, err := (&http.Client{Transport: netguard.Transport(o.PublicOnly)}).Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("%s: HTTP %d", req.URL, resp.StatusCode)
		}
		return nginxInIndex(io.LimitReader(resp.Body, maxAPKIndex))
	}
}

// nginxInIndex reads the nginx package's version from an APKINDEX.tar.gz.
func nginxInIndex(r io.Reader) (string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", err
	}
	// The index is a gzip stream of signature then index; read on
	// through every member.
	gz.Multistream(true)
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", errors.New("the index has no APKINDEX file")
			}
			return "", err
		}
		if h.Name != "APKINDEX" {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(tr, maxAPKIndex))
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		pkg := ""
		for sc.Scan() {
			l := sc.Text()
			switch {
			case l == "":
				pkg = ""
			case strings.HasPrefix(l, "P:"):
				pkg = l[2:]
			case strings.HasPrefix(l, "V:") && pkg == "nginx":
				return l[2:], nil
			}
		}
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", errors.New("the index lists no nginx package")
	}
}
