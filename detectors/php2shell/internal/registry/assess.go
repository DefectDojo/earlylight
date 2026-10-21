package registry

import (
	"fmt"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/knowledge"
	"github.com/DefectDojo/earlylight/detectors/php2shell/internal/version"
)

// Verdict is what a Resolution proves about CVE-2026-109618/109619.
type Verdict string

const (
	// Vulnerable: at least one platform carries a PHP release without the fix.
	Vulnerable Verdict = "vulnerable"
	// Fixed: every platform that proves a PHP version carries the fix.
	Fixed Verdict = "fixed"
	// Unknown: PHP versions are proven but at least one cannot be judged (a
	// development or pre-release build), and none is vulnerable.
	Unknown Verdict = "unknown"
	// NoPHP: no platform's config proves a PHP version. Not a finding.
	NoPHP Verdict = "no-php-evidence"
	// NoImages: the reference exists but holds no images (an empty index).
	NoImages Verdict = "no-images"
	// Unresolved: the reference could not be resolved.
	Unresolved Verdict = "unresolved"
)

// PlatformVerdict is the judgement for one platform with a proven PHP version.
type PlatformVerdict struct {
	Platform   string                   `json:"platform"`
	PHPVersion string                   `json:"php_version"`
	Status     knowledge.UpstreamStatus `json:"status"`
	Reason     string                   `json:"reason"`
}

// Assessment is the verdict for a Resolution, with the per-platform reasons.
type Assessment struct {
	Verdict Verdict `json:"verdict"`
	Reason  string  `json:"reason"`
	// Platforms lists the platforms that prove a PHP version.
	Platforms []PlatformVerdict `json:"platforms,omitempty"`
	// VulnerablePlatforms lists the vulnerable ones ("linux/amd64 (PHP 8.3.35)").
	VulnerablePlatforms []string `json:"vulnerable_platforms,omitempty"`
	// WithoutPHP lists platforms whose config proves no PHP version.
	WithoutPHP []string `json:"without_php,omitempty"`
}

func platformName(p string) string {
	if p == "" {
		return "the image"
	}
	return p
}

// Assess judges a Resolution by knowledge.Upstream, platform by platform.
func Assess(res *Resolution) Assessment {
	if res == nil {
		return Assessment{Verdict: Unresolved, Reason: "not resolved"}
	}
	if res.Empty {
		return Assessment{Verdict: NoImages, Reason: CleanText(fmt.Sprintf("%s exists but has no images (an empty index; on Docker Hub this is a tag whose builds are still being published)", res.Ref), 600)}
	}
	if len(res.Platforms) == 0 && len(res.OmittedPlatforms) > 0 {
		return Assessment{Verdict: NoImages, Reason: CleanText(fmt.Sprintf("%s has no image for the selected platform (it has %s)", res.Ref, strings.Join(res.OmittedPlatforms, ", ")), 600)}
	}
	var a Assessment
	var vulnerable, unknown int
	for _, p := range res.Platforms {
		if p.PHPVersion == "" {
			a.WithoutPHP = append(a.WithoutPHP, platformName(p.Platform))
			continue
		}
		v, err := version.ParsePHP(p.PHPVersion)
		if err != nil {
			// PHPFromEnv only accepts X.Y.Z, so this does not happen; treat it
			// as no claim rather than guess.
			a.WithoutPHP = append(a.WithoutPHP, platformName(p.Platform))
			continue
		}
		st, why := knowledge.Upstream(v)
		a.Platforms = append(a.Platforms, PlatformVerdict{Platform: p.Platform, PHPVersion: p.PHPVersion, Status: st, Reason: why})
		switch st {
		case knowledge.UpstreamVulnerable:
			vulnerable++
			a.VulnerablePlatforms = append(a.VulnerablePlatforms, fmt.Sprintf("%s (PHP %s)", platformName(p.Platform), p.PHPVersion))
		case knowledge.UpstreamUnknown:
			unknown++
		}
	}
	switch {
	case vulnerable > 0:
		a.Verdict = Vulnerable
		a.Reason = fmt.Sprintf("%s carries a PHP release without the fix: %s", res.Ref, strings.Join(a.VulnerablePlatforms, ", "))
	case len(a.Platforms) == 0:
		a.Verdict = NoPHP
		a.Reason = fmt.Sprintf("no image config of %s proves a PHP version", res.Ref)
	case unknown > 0:
		a.Verdict = Unknown
		var parts []string
		for _, p := range a.Platforms {
			if p.Status == knowledge.UpstreamUnknown {
				parts = append(parts, fmt.Sprintf("%s: %s", platformName(p.Platform), p.Reason))
			}
		}
		a.Reason = strings.Join(parts, "; ")
	default:
		a.Verdict = Fixed
		var parts []string
		for _, p := range a.Platforms {
			parts = append(parts, fmt.Sprintf("%s (PHP %s)", platformName(p.Platform), p.PHPVersion))
		}
		a.Reason = fmt.Sprintf("every platform that proves a PHP version carries the fix: %s", strings.Join(parts, ", "))
		if len(a.WithoutPHP) > 0 {
			a.Reason += fmt.Sprintf("; no PHP version proven for %s", strings.Join(a.WithoutPHP, ", "))
		}
	}
	a.Reason = CleanText(a.Reason, 2000)
	return a
}

// AssessPlatform judges res for one platform only, as a FROM --platform=
// does; an empty platform judges every platform.
func AssessPlatform(res *Resolution, platform string) Assessment {
	if res == nil || platform == "" {
		return Assess(res)
	}
	return Assess(FilterPlatforms(res, []string{platform}))
}
