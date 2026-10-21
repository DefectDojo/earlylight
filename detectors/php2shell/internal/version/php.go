// Package version parses PHP release versions and compares distribution package
// versions with each package manager's own rules (dpkg, apk, rpm).
package version

import (
	"fmt"
	"regexp"
	"strconv"
)

// PHP is an upstream PHP version as PHP itself reports it in PHP_VERSION:
// MAJOR.MINOR.PATCH, optionally followed by a pre-release or development tag
// ("8.4.0RC1", "8.5.0alpha2", "8.6.0-dev") and PHP_EXTRA_VERSION, which some
// builders set ("-0ubuntu0.20.04.1" on old Ubuntu releases).
type PHP struct {
	Major, Minor, Patch int
	// Pre is a pre-release or development tag ("RC1", "alpha2", "beta1", "dev"),
	// empty for a release.
	Pre string
	// Extra is anything after the version and tag, as written.
	Extra string
}

var phpRe = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,4})((?:alpha|beta|RC|rc)[0-9]{0,3}|-dev)?(.*)$`)

// ParsePHP parses a PHP_VERSION string. Strings that do not start with
// MAJOR.MINOR.PATCH are rejected: a branch alone ("8.3") is not a version.
func ParsePHP(s string) (PHP, error) {
	m := phpRe.FindStringSubmatch(s)
	if m == nil {
		return PHP{}, fmt.Errorf("not a PHP version: %q", s)
	}
	var v PHP
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	v.Pre = m[4]
	if v.Pre == "-dev" {
		v.Pre = "dev"
	}
	v.Extra = m[5]
	return v, nil
}

// String returns MAJOR.MINOR.PATCH plus the tag, without Extra.
func (v PHP) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	switch v.Pre {
	case "":
	case "dev":
		s += "-dev"
	default:
		s += v.Pre
	}
	return s
}

// Branch is MAJOR.MINOR.
func (v PHP) Branch() Branch { return Branch{v.Major, v.Minor} }

// IsRelease reports whether v is a final release (no pre-release or dev tag).
func (v PHP) IsRelease() bool { return v.Pre == "" }

// CompareRelease compares the numeric MAJOR.MINOR.PATCH parts only.
func (v PHP) CompareRelease(o PHP) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Branch is a PHP release branch such as 8.3.
type Branch struct{ Major, Minor int }

func (b Branch) String() string { return fmt.Sprintf("%d.%d", b.Major, b.Minor) }

// Less orders branches.
func (b Branch) Less(o Branch) bool {
	return b.Major < o.Major || (b.Major == o.Major && b.Minor < o.Minor)
}
