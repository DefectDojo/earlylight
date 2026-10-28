package pins

import (
	"errors"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

// reference is an image reference as written, normalized the way the
// registry reads it: Docker Hub as index.docker.io, official images under
// library/.
type reference struct {
	Registry, Path, Tag, Digest string
}

// parseReference reads "registry/path:tag@digest", any part optional but the
// path.
func parseReference(s string) (reference, error) {
	var r reference
	base := strings.TrimSpace(s)
	if i := strings.Index(base, "@"); i >= 0 {
		base, r.Digest = base[:i], base[i+1:]
		if !strings.HasPrefix(r.Digest, "sha256:") || len(r.Digest) != len("sha256:")+64 {
			return reference{}, errors.New("not a sha256 digest")
		}
	}
	if i := strings.LastIndex(base, ":"); i > strings.LastIndex(base, "/") {
		base, r.Tag = base[:i], base[i+1:]
	}
	repo, err := name.NewRepository(base)
	if err != nil {
		return reference{}, err
	}
	r.Registry, r.Path = repo.RegistryStr(), repo.RepositoryStr()
	return r, nil
}
