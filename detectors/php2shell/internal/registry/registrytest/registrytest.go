// Package registrytest runs an in-memory OCI registry for tests and builds
// images that look like the official php image and images derived from it.
// Images carry a real (small) layer so tests can check that layers are never
// downloaded.
package registrytest

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Server is an in-memory registry.
type Server struct {
	t    testing.TB
	srv  *httptest.Server
	Host string

	mu       sync.Mutex
	requests []string // "METHOD path"
	// Fail, when set, may answer a request itself with a status code (and
	// Retry-After seconds when >= 0): return 0 to pass the request through.
	Fail func(r *http.Request) (status int, retryAfter int)
	// layers holds every layer digest pushed, to check none is fetched.
	layers map[string]bool
}

// New starts a registry; it stops when the test ends.
func New(t testing.TB) *Server {
	s := &Server{t: t, layers: map[string]bool{}}
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		fail := s.Fail
		s.mu.Unlock()
		if fail != nil {
			if code, ra := fail(r); code != 0 {
				if ra >= 0 {
					w.Header().Set("Retry-After", fmt.Sprint(ra))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				if code == http.StatusTooManyRequests {
					fmt.Fprint(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"rate limited"}]}`)
				}
				return
			}
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(s.srv.Close)
	s.Host = strings.TrimPrefix(s.srv.URL, "http://")
	return s
}

// Mirrors maps Docker Hub to this registry (registry.Options.Mirrors).
func (s *Server) Mirrors() map[string]string {
	return map[string]string{name.DefaultRegistry: s.Host}
}

// Requests returns the requests seen so far and forgets them.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.requests
	s.requests = nil
	return r
}

// LayerFetched reports whether any request fetched a pushed layer blob.
func (s *Server) LayerFetched(reqs []string) bool {
	for _, r := range reqs {
		if i := strings.Index(r, "/blobs/"); i >= 0 && strings.HasPrefix(r, "GET ") {
			if s.layers[r[i+len("/blobs/"):]] {
				return true
			}
		}
	}
	return false
}

// Spec describes one platform image.
type Spec struct {
	OS, Arch, Variant string
	Env               []string
	Created           time.Time
	// Base and Version set the org.opencontainers.image.base.name and
	// org.opencontainers.image.version annotations (on the image manifest
	// and its index entry), as Docker Hub's official images carry them.
	Base, Version string
	// History, when set, is the config's first history entry (created_by).
	History string
}

func (sp Spec) annotations() map[string]string {
	a := map[string]string{}
	if sp.Base != "" {
		a["org.opencontainers.image.base.name"] = sp.Base
	}
	if sp.Version != "" {
		a["org.opencontainers.image.version"] = sp.Version
	}
	if len(a) == 0 {
		return nil
	}
	return a
}

// PHPEnv is the environment the official php image sets for version v.
func PHPEnv(v string) []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"PHPIZE_DEPS=autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c",
		"PHP_INI_DIR=/usr/local/etc/php",
		"PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2",
		"GPG_KEYS=1198C0117593497A5EC5C199286AF1F9897469DC",
		"PHP_VERSION=" + v,
		"PHP_URL=https://www.php.net/distributions/php-" + v + ".tar.xz",
		"PHP_ASC_URL=https://www.php.net/distributions/php-" + v + ".tar.xz.asc",
		"PHP_SHA256=" + strings.Repeat("ab", 32),
	}
}

// Image builds an image for spec with one random layer.
func (s *Server) Image(sp Spec) v1.Image {
	s.t.Helper()
	l, err := random.Layer(512, types.DockerLayer)
	if err != nil {
		s.t.Fatal(err)
	}
	d, _ := l.Digest()
	s.mu.Lock()
	s.layers[d.String()] = true
	s.mu.Unlock()
	img, err := mutate.AppendLayers(empty.Image, l)
	if err != nil {
		s.t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		s.t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = sp.OS, sp.Arch, sp.Variant
	cf.Config.Env = sp.Env
	created := sp.Created
	if created.IsZero() {
		created = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	}
	cf.Created = v1.Time{Time: created}
	if sp.History != "" {
		cf.History = []v1.History{{CreatedBy: sp.History}}
	}
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		s.t.Fatal(err)
	}
	if a := sp.annotations(); a != nil {
		img = mutate.Annotations(img, a).(v1.Image)
	}
	return img
}

// Push pushes a single-platform image to repo:tag (repo like "library/php").
func (s *Server) Push(repo, tag string, img v1.Image) v1.Hash {
	s.t.Helper()
	ref, err := name.NewTag(s.Host + "/" + repo + ":" + tag)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := remote.Write(ref, img); err != nil {
		s.t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		s.t.Fatal(err)
	}
	return d
}

// Attestation is an index entry that is a BuildKit attestation manifest.
const Attestation = "attestation"

// Index builds an OCI index of one image per spec; a spec with OS
// Attestation adds an attestation manifest (platform unknown/unknown).
func (s *Server) Index(specs ...Spec) v1.ImageIndex {
	s.t.Helper()
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	var adds []mutate.IndexAddendum
	for _, sp := range specs {
		if sp.OS == Attestation {
			img := s.Image(Spec{OS: "unknown", Arch: "unknown"})
			adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{
				Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
				Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": "sha256:" + strings.Repeat("0", 64)},
			}})
			continue
		}
		img := s.Image(sp)
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: sp.OS, Architecture: sp.Arch, Variant: sp.Variant},
			Annotations: sp.annotations(),
		}})
	}
	return mutate.AppendManifests(idx, adds...)
}

// PushIndex pushes an index to repo:tag.
func (s *Server) PushIndex(repo, tag string, idx v1.ImageIndex) v1.Hash {
	s.t.Helper()
	ref, err := name.NewTag(s.Host + "/" + repo + ":" + tag)
	if err != nil {
		s.t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, idx); err != nil {
		s.t.Fatal(err)
	}
	d, err := idx.Digest()
	if err != nil {
		s.t.Fatal(err)
	}
	return d
}

// PHPIndex pushes an official-style multi-platform php index for version v at
// each tag, with an attestation manifest, and returns its digest. Platforms
// default to linux/amd64 and linux/arm64/v8.
func (s *Server) PHPIndex(v string, tags ...string) v1.Hash {
	s.t.Helper()
	idx := s.Index(
		Spec{OS: "linux", Arch: "amd64", Env: PHPEnv(v)},
		Spec{OS: "linux", Arch: "arm64", Variant: "v8", Env: PHPEnv(v)},
		Spec{OS: Attestation},
	)
	var d v1.Hash
	for _, t := range tags {
		d = s.PushIndex("library/php", t, idx)
	}
	return d
}

// PHPIndexOn pushes an official-style php index for version v built on base
// (an org.opencontainers.image.base.name value such as "debian:bookworm-slim"
// or "alpine:3.21") for each platform (default linux/amd64 and
// linux/arm64/v8), with an attestation manifest, at each tag. The first tag is
// the image version annotation.
func (s *Server) PHPIndexOn(v, base string, platforms []string, tags ...string) (v1.Hash, []v1.Hash) {
	s.t.Helper()
	if len(platforms) == 0 {
		platforms = []string{"linux/amd64", "linux/arm64/v8"}
	}
	var specs []Spec
	for _, p := range platforms {
		parts := strings.Split(p, "/")
		sp := Spec{OS: parts[0], Arch: parts[1], Env: PHPEnv(v), Base: base}
		if len(parts) == 3 {
			sp.Variant = parts[2]
		}
		if len(tags) > 0 {
			sp.Version = tags[0]
		}
		specs = append(specs, sp)
	}
	specs = append(specs, Spec{OS: Attestation})
	idx := s.Index(specs...)
	var d v1.Hash
	for _, t := range tags {
		d = s.PushIndex("library/php", t, idx)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		s.t.Fatal(err)
	}
	var ms []v1.Hash
	for _, m := range im.Manifests {
		ms = append(ms, m.Digest)
	}
	return d, ms
}

// EmptyIndex pushes an index with no manifests ({"manifests":[]}).
func (s *Server) EmptyIndex(repo, tag string) v1.Hash {
	return s.PushIndex(repo, tag, mutate.IndexMediaType(empty.Index, types.OCIImageIndex))
}
