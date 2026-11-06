// Package image opens a container image and yields its final filesystem.
package image

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Opened is an image's flattened filesystem and what identifies it.
type Opened struct {
	// FS is the final filesystem as a tar stream, whiteouts applied.
	FS io.ReadCloser
	// Digest is the image manifest digest.
	Digest string
	// Platform is the platform that was opened, when known.
	Platform string
	// Env is the image configuration's environment.
	Env []string
	// Command is what the container runs: the configuration's Entrypoint
	// followed by its Cmd.
	Command []string
}

// Open resolves ref and returns the image's flattened filesystem.
//
//	docker-archive:PATH   a tarball from `docker save`
//	anything else         a registry reference, e.g. php:8.3-fpm or ghcr.io/o/r@sha256:...
func Open(ref, platform string) (*Opened, error) {
	img, err := load(ref, platform)
	if err != nil {
		return nil, err
	}
	return opened(img)
}

func opened(img v1.Image) (*Opened, error) {
	digest, err := img.Digest()
	if err != nil {
		return nil, err
	}
	o := &Opened{Digest: digest.String()}
	if cf, err := img.ConfigFile(); err == nil && cf != nil {
		o.Env = cf.Config.Env
		o.Command = append(append([]string(nil), cf.Config.Entrypoint...), cf.Config.Cmd...)
		if cf.OS != "" {
			o.Platform = cf.OS + "/" + cf.Architecture
			if cf.Variant != "" {
				o.Platform += "/" + cf.Variant
			}
		}
	}
	o.FS = mutate.Extract(img)
	return o, nil
}

// Platforms lists the platforms a registry reference offers (empty for a
// single-platform image), skipping attestation manifests.
func Platforms(ref string) ([]string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", ref, err)
	}
	desc, err := remote.Get(r, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	if !desc.MediaType.IsIndex() {
		return nil, nil
	}
	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range m.Manifests {
		if d.Platform == nil || d.Platform.OS == "unknown" || d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" {
			continue
		}
		out = append(out, d.Platform.String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s is an image index with no images", ref)
	}
	return out, nil
}

// OpenRegistry is Open for a registry reference only, with every request
// carried by rt: a caller scanning references it does not trust passes a
// guarded transport (internal/netguard). Local archives are refused.
func OpenRegistry(ref, platform string, rt http.RoundTripper) (*Opened, error) {
	if strings.HasPrefix(ref, "docker-archive:") || strings.HasPrefix(ref, "rootfs:") {
		return nil, fmt.Errorf("%q: only registry references can be opened here", ref)
	}
	img, err := loadRemote(ref, platform, rt)
	if err != nil {
		return nil, err
	}
	return opened(img)
}

func load(ref, platform string) (v1.Image, error) {
	if p, ok := strings.CutPrefix(ref, "docker-archive:"); ok {
		return tarball.ImageFromPath(p, nil)
	}
	return loadRemote(ref, platform, nil)
}

func loadRemote(ref, platform string, rt http.RoundTripper) (v1.Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference %q: %w", ref, err)
	}
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	if rt != nil {
		opts = append(opts, remote.WithTransport(rt))
	}
	if platform != "" {
		p, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, err
		}
		opts = append(opts, remote.WithPlatform(*p))
	}
	return remote.Image(r, opts...)
}
