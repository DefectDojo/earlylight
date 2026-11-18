package repo

import (
	"context"
	"testing"
)

// FuzzScanText: any Dockerfile, configuration or YAML text scans without a
// panic, and every finding has a status and a message.
func FuzzScanText(f *testing.F) {
	f.Add("FROM nginx:1.31.8\nRUN apt-get install -y nginx=1.22.1-9 && sh -c 'apk add nginx'\n", "server { listen 443 ssl http2; proxy_pass x; }", "kind: ConfigMap\ndata:\n  a.conf: |\n    server { listen 1 http2; }\n")
	f.Add("ARG V=1\nFROM nginx:${V}-alpine AS a\nFROM a\nRUN <<EOF\napk add nginx\nEOF\n", "http { http2 on; server { listen 443 ssl; } }", "controller:\n  image:\n    image: ingress-nginx/controller\n    tag: v1.15.1\n")
	root := f.TempDir()
	f.Fuzz(func(t *testing.T, df, cf, yf string) {
		res, err := Scan(context.Background(), root, Options{Overlay: map[string][]byte{
			"Dockerfile": []byte(df), "nginx/site.conf": []byte(cf), "values.yaml": []byte(yf),
		}})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range res.Findings {
			if x.Status == "" || x.Message == "" || x.Rule == "" {
				t.Fatalf("incomplete finding %+v", x)
			}
		}
	})
}
