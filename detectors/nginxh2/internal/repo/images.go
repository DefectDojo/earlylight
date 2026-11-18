package repo

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/DefectDojo/earlylight/detectors/nginxh2/internal/knowledge"
)

// Family is a kind of image whose tags name the nginx it holds.
type Family struct {
	ID     string
	Vendor string
	// NoFix is set when the family will publish no fixed tag, or had none
	// on the check date and is not expected to: fix explains instead of
	// looking.
	NoFix string
}

// Families.
var (
	Official     = Family{ID: "nginx", Vendor: "the Docker official image"}
	Unprivileged = Family{ID: "nginx-unprivileged", Vendor: "nginxinc/nginx-unprivileged"}
	OpenResty    = Family{ID: "openresty", Vendor: "OpenResty", NoFix: "OpenResty had published no release with the fix on " + knowledge.Checked + " (newest 1.31.8.1, nginx 1.31.8)"}
	Bitnami      = Family{ID: "bitnami-nginx", Vendor: "Bitnami", NoFix: "Bitnami's public nginx tags stop at 1.29.1 (bitnamilegacy) and will receive no fix"}
	Ingress      = Family{ID: "ingress-nginx", Vendor: "Kubernetes ingress-nginx", NoFix: "the ingress-nginx project was archived on 2026-03-23 and will publish no fix; its last controllers (v1.15.1, v1.14.5, v1.13.9) run nginx 1.27.1"}
	F5Ingress    = Family{ID: "nginx-ingress", Vendor: "F5 NGINX Ingress Controller"}
	AngieImage   = Family{ID: "angie", Vendor: "Angie", NoFix: "Angie had published no release with the fix on " + knowledge.Checked + " (newest 1.12.4)"}
)

// Classify returns the family of an image reference, or false.
func Classify(image string) (Family, bool) {
	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return Family{}, false
	}
	reg := ref.Context().RegistryStr()
	repo := ref.Context().RepositoryStr()
	switch {
	case repo == "library/nginx" || strings.HasSuffix(repo, "/library/nginx") || reg == "public.ecr.aws" && repo == "nginx/nginx":
		return Official, true
	case repo == "nginxinc/nginx-unprivileged" || repo == "nginx/nginx-unprivileged" || strings.HasSuffix(repo, "/nginxinc/nginx-unprivileged"):
		return Unprivileged, true
	case repo == "openresty/openresty" || strings.HasSuffix(repo, "/openresty/openresty"):
		return OpenResty, true
	case repo == "bitnami/nginx" || repo == "bitnamilegacy/nginx" || strings.HasSuffix(repo, "/bitnami/nginx"):
		return Bitnami, true
	case strings.HasSuffix(repo, "ingress-nginx/controller") || strings.HasSuffix(repo, "ingress-nginx/controller-chroot") ||
		repo == "bitnami/nginx-ingress-controller" || repo == "bitnamilegacy/nginx-ingress-controller":
		return Ingress, true
	case repo == "nginx/nginx-ingress" || strings.HasSuffix(repo, "/nginx/nginx-ingress"):
		return F5Ingress, true
	case strings.HasSuffix(repo, "angie") && (reg == "docker.angie.software" || strings.HasPrefix(repo, "angie")):
		return AngieImage, true
	}
	return Family{}, false
}

// Tag is what a tag says.
type Tag struct {
	// Version is the release the tag names, "" for a moving tag.
	Version string
	// Variant is what follows the version ("-alpine3.24-perl"), with its
	// leading dash.
	Variant string
}

var (
	semverTag    = regexp.MustCompile(`^(\d+\.\d+\.\d+)(-[a-z0-9][a-z0-9.-]*)?$`)
	openrestyTag = regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)((?:-\d+)?(?:-[a-z][a-z0-9.-]*)?)$`)
	ingressTag   = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)(-[a-z0-9][a-z0-9.-]*)?$`)
)

// ParseTag reads a tag of the family. ok is false for a moving tag
// (latest, mainline, 1.31, alpine): only reading the image says what it
// holds.
func (f Family) ParseTag(tag string) (Tag, bool) {
	var m []string
	switch f.ID {
	case OpenResty.ID:
		m = openrestyTag.FindStringSubmatch(tag)
	case Ingress.ID:
		m = ingressTag.FindStringSubmatch(tag)
	default:
		m = semverTag.FindStringSubmatch(tag)
	}
	if m == nil {
		return Tag{}, false
	}
	return Tag{Version: m[1], Variant: m[2]}, true
}

// Judge returns each CVE's status for a tag of the family, with the
// reason.
func (f Family) Judge(t Tag) map[string]Verdict {
	out := map[string]Verdict{}
	for _, c := range knowledge.CVEs {
		out[c.ID] = f.judge(c, t)
	}
	return out
}

// Verdict is one CVE's status for a tag.
type Verdict struct {
	Status knowledge.Status
	Reason string
}

func (f Family) judge(c knowledge.CVE, t Tag) Verdict {
	v, err := knowledge.ParseV(t.Version)
	if err != nil {
		return Verdict{knowledge.Unknown, "the tag's version could not be read"}
	}
	switch f.ID {
	case Official.ID, Unprivileged.ID, Bitnami.ID:
		st, why := knowledge.Nginx(c, v)
		return Verdict{st, why}
	case OpenResty.ID:
		st, why := knowledge.OpenResty(c, v)
		return Verdict{st, why}
	case AngieImage.ID:
		st, why := knowledge.Angie(c, v)
		return Verdict{st, why}
	case Ingress.ID:
		if v[0] >= 1 {
			return Verdict{knowledge.Vulnerable, fmt.Sprintf("ingress-nginx controller %s runs nginx 1.20.1 or later (1.27.1 from v1.13), read from its build scripts; the project publishes no fix", v)}
		}
		if c.ID == knowledge.Flow {
			return Verdict{knowledge.Vulnerable, fmt.Sprintf("ingress-nginx controller %s runs an nginx later than 1.9.5; the project publishes no fix", v)}
		}
		return Verdict{knowledge.Unknown, fmt.Sprintf("ingress-nginx controller %s: which nginx it runs was not read (before v1.0 some ran nginx older than 1.19.7)", v)}
	case F5Ingress.ID:
		if knowledge.Cmp(v.Line(), knowledge.MustV("5.8")) > 0 {
			return Verdict{knowledge.Unknown, fmt.Sprintf("NGINX Ingress Controller %s is newer than any release known on %s (5.8.0): not judged", v, knowledge.Checked)}
		}
		if knowledge.Cmp(v, knowledge.MustV("5.8.0")) >= 0 {
			return Verdict{knowledge.Fixed, fmt.Sprintf("NGINX Ingress Controller %s builds on nginx 1.31.9 (5.8.0's build file)", v)}
		}
		return Verdict{knowledge.Vulnerable, fmt.Sprintf("NGINX Ingress Controller %s builds on an nginx before 1.31.9 (5.7.1 used 1.31.8); 5.8.0 is the first on 1.31.9", v)}
	}
	return Verdict{knowledge.Unknown, "not a family the detector judges"}
}

// FixedTag is the tag of the first fixed release on the same line and
// variant, "" when the family has none.
func (f Family) FixedTag(t Tag) string {
	v, err := knowledge.ParseV(t.Version)
	if err != nil || f.NoFix != "" {
		return ""
	}
	switch f.ID {
	case Official.ID, Unprivileged.ID:
		c, _ := knowledge.ByID(knowledge.Flow)
		for _, fx := range c.Fixed {
			if knowledge.Cmp(fx.Line(), v.Line()) == 0 && knowledge.Cmp(v, fx) < 0 {
				return fx.String() + t.Variant
			}
		}
	case F5Ingress.ID:
		if knowledge.Cmp(v, knowledge.MustV("5.8.0")) < 0 && v[0] == 5 {
			return "5.8.0" + t.Variant
		}
	}
	return ""
}

// LineText says why a vulnerable tag has no fixed tag of its own line.
func (f Family) LineText(t Tag) string {
	if f.NoFix != "" {
		return f.NoFix
	}
	switch f.ID {
	case Official.ID, Unprivileged.ID:
		return fmt.Sprintf("nginx %s is on a line that received no fix (fixed lines: %s); move to 1.30.7 (stable) or 1.31.9 (mainline) by hand and test it", t.Version, knowledge.FixedText)
	case F5Ingress.ID:
		return fmt.Sprintf("NGINX Ingress Controller %s is not on the 5.x line; move to 5.8.0 by hand", t.Version)
	}
	return "no fixed tag is known"
}
