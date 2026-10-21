package registry

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// Reference is a parsed image reference. Unlike name.ParseReference, it keeps
// both the tag and the digest of "repo:tag@sha256:...".
type Reference struct {
	// Original is the reference as given.
	Original string
	// Registry is the registry host as go-containerregistry normalizes it
	// ("index.docker.io" for Docker Hub).
	Registry string
	// Path is the repository path within the registry ("library/php").
	Path string
	// Tag is the tag as written, "" when there is none (for a reference
	// without a digest that means "latest").
	Tag string
	// Digest is the digest as written, "" when there is none.
	Digest string
}

// ParseReference parses an image reference string.
func ParseReference(s string) (Reference, error) {
	r := Reference{Original: s}
	rest := s
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		r.Digest = rest[i+1:]
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, ':'); i > strings.LastIndexByte(rest, '/') {
		r.Tag = rest[i+1:]
		rest = rest[:i]
	}
	repo, err := name.NewRepository(rest)
	if err != nil {
		return Reference{}, fmt.Errorf("invalid image reference %q: %w", s, err)
	}
	r.Registry = repo.RegistryStr()
	r.Path = repo.RepositoryStr()
	if r.Tag != "" {
		if _, err := name.NewTag(rest + ":" + r.Tag); err != nil {
			return Reference{}, fmt.Errorf("invalid image reference %q: %w", s, err)
		}
	}
	if r.Digest != "" {
		if _, err := name.NewDigest(rest + "@" + r.Digest); err != nil {
			return Reference{}, fmt.Errorf("invalid image reference %q: %w", s, err)
		}
	}
	return r, nil
}

// Repository is the repository name with Docker Hub shown as docker.io:
// "docker.io/library/php", "ghcr.io/org/app".
func (r Reference) Repository() string {
	reg := r.Registry
	if reg == name.DefaultRegistry {
		reg = "docker.io"
	}
	return reg + "/" + r.Path
}

// EffectiveTag is the tag a pull by tag uses: Tag, or "latest".
func (r Reference) EffectiveTag() string {
	if r.Tag == "" {
		return "latest"
	}
	return r.Tag
}

// String is the canonical form: repository, tag (if written) and digest (if
// written).
func (r Reference) String() string {
	s := r.Repository()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// IsOfficialPHP reports whether the reference names Docker Hub's official php
// image (php, library/php, docker.io/library/php, index.docker.io/library/php).
func (r Reference) IsOfficialPHP() bool {
	return r.Registry == name.DefaultRegistry && r.Path == "library/php"
}

// NormalizePlatform makes platform strings comparable: "linux/arm64/v8" and
// "linux/arm64" are the same platform.
func NormalizePlatform(p string) string {
	if strings.HasSuffix(p, "/arm64/v8") {
		return strings.TrimSuffix(p, "/v8")
	}
	return p
}
