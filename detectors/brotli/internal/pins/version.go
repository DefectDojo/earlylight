package pins

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/assess"
	"github.com/DefectDojo/earlylight/detectors/brotli/internal/fingerprint"
)

// product is a runtime that bundles the Brotli decoder.
type product int

const (
	node product = iota
	dotnet
	bun
	dotnetSDK  // a .NET SDK release, which carries a runtime
	dependency // a package that bundles the decoder (deps.go)
)

func (p product) rule() string {
	return [...]string{RuleNode, RuleDotnet, RuleBun, RuleDotnet, RuleDependency}[p]
}

func (p product) name() string {
	return [...]string{"Node.js", ".NET", "Bun", ".NET SDK", "package"}[p]
}

// fixedText lists every fixed release, for messages.
func (p product) fixedText() string {
	return [...]string{"22.23.4, 24.22.1 or 26.12.1", "8.0.33, 9.0.22 or 10.0.14", "1.4.4",
		"8.0.133 or 8.0.427, 9.0.123 or 9.0.320, 10.0.114 or 10.0.403", ""}[p]
}

// newest is the newest release line known to need the fix; any later line
// was released with it.
func (p product) newest() int {
	return [...]int{26, 10, 1, 10, 0}[p]
}

// sdkFixed is the first SDK of each serviced feature band that ships the
// fixed runtime (Microsoft's release metadata for 8.0.33, 9.0.22 and
// 10.0.14, October 25, 2026). The bands left out (8.0.2xx, 8.0.3xx,
// 9.0.2xx, 10.0.2xx, 10.0.3xx) are no longer serviced and got no fix.
var sdkFixed = map[[2]int]int{ // {major, band} -> patch within the band
	{8, 1}: 33, {8, 4}: 27, {9, 1}: 23, {9, 3}: 20, {10, 1}: 14, {10, 4}: 3,
}

// judgeSDK judges an SDK version: 8.0.426 (exact), 8.0.4xx (a band), 8.0 or
// 8.0.x (a channel, which floats to the newest SDK).
func judgeSDK(value string, allowRest bool) judgement {
	v := strings.TrimSpace(value)
	pv, rest, ok := parseVersion(v)
	if !ok || (rest != "" && !(allowRest && strings.HasPrefix(rest, "-")) && !strings.HasPrefix(rest, ".x") && !strings.HasPrefix(rest, "xx")) {
		return judgement{vd: notJudged, reason: fmt.Sprintf("%q is not a .NET SDK version this check reads", clean(v, 60))}
	}
	j := judgement{current: pv.text}
	major := pv.parts[0]
	if _, line := assess.DotnetFixed[major]; !line {
		if major > dotnetSDK.newest() {
			j.vd = fine
		} else {
			j.vd, j.fixed = noFixLine, dotnetSDK.fixedText()
		}
		return j
	}
	if len(pv.parts) < 3 {
		j.vd = fine // a channel: the newest SDK, which has the fix
		return j
	}
	feature := pv.parts[2]
	band, patch := feature/100, feature%100
	if strings.HasPrefix(rest, "xx") {
		band, patch = feature, -1 // "8.0.4xx": parseVersion read the band digit
	}
	fixedPatch, serviced := sdkFixed[[2]int{major, band}]
	switch {
	case !serviced:
		j.vd, j.fixed = noFixLine, dotnetSDK.fixedText()
	case patch < 0 || patch >= fixedPatch:
		j.vd = fine
	default:
		j.vd, j.fixed = bump, fmt.Sprintf("%d.%d.%d", major, pv.parts[1], band*100+fixedPatch)
	}
	return j
}

// Node.js release codenames, as nvm aliases (lts/iron) and image tags (iron-slim) use them.
var nodeCodenames = map[string]int{
	"argon": 4, "boron": 6, "carbon": 8, "dubnium": 10, "erbium": 12, "fermium": 14,
	"gallium": 16, "hydrogen": 18, "iron": 20, "jod": 22, "krypton": 24,
}

// verdict is how a pinned value is judged.
type verdict int

const (
	fine      verdict = iota // has the fix, or floats to a release that has it
	bump                     // below the fixed release of its own line: a one-line edit fixes it
	noFixLine                // its line has no fixed release: a manual upgrade
	notJudged                // not a version this package reads (an alias, an expression)
)

// judgement is the verdict on one value, with the version text to replace and
// what to replace it with.
type judgement struct {
	vd      verdict
	current string // the version as written, without a leading v
	fixed   string // the replacement (same precision as current), or the release to move to
	reason  string // for notJudged
}

// parsed is a version written as 1, 1.2 or 1.2.3.
type parsed struct {
	parts []int
	text  string
}

// parseVersion reads a version at the start of s, digits and dots only, and
// returns it and the rest of s. A leading "v" is skipped.
func parseVersion(s string) (parsed, string, bool) {
	s = strings.TrimPrefix(s, "v")
	var p parsed
	i := 0
	for len(p.parts) < 3 {
		j := i
		for j < len(s) && j-i < 6 && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i {
			return parsed{}, "", false
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil {
			return parsed{}, "", false
		}
		p.parts = append(p.parts, n)
		i = j
		if i < len(s) && s[i] == '.' && len(p.parts) < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			i++
			continue
		}
		break
	}
	p.text = s[:i]
	return p, s[i:], true
}

func (p parsed) version() fingerprint.Version {
	v := fingerprint.Version{}
	if len(p.parts) > 0 {
		v.Major = p.parts[0]
	}
	if len(p.parts) > 1 {
		v.Minor = p.parts[1]
	}
	if len(p.parts) > 2 {
		v.Patch = p.parts[2]
	}
	return v
}

// judgeValue judges a whole value such as "24.22.0", "v24", "lts/iron" or
// "1.4.3". rest is what follows the version (an image tag's variant); a
// value with anything else after the version is not judged.
func judgeValue(p product, value string, allowRest bool) judgement {
	v := strings.TrimSpace(value)
	lower := strings.ToLower(v)
	if p == node {
		alias := strings.TrimPrefix(lower, "lts/")
		if !allowRest || !strings.Contains(alias, "-") {
			switch alias {
			case "*", "node", "stable", "latest", "current", "lts", "":
				return judgement{vd: fine}
			}
		} else if a, _, _ := strings.Cut(alias, "-"); a == "lts" || a == "current" || a == "latest" {
			return judgement{vd: fine}
		}
		name := alias
		if allowRest {
			name, _, _ = strings.Cut(alias, "-")
		}
		if major, ok := nodeCodenames[name]; ok {
			return judgeLine(p, parsed{parts: []int{major}, text: name})
		}
	}
	if p == bun {
		base := lower
		if allowRest {
			base, _, _ = strings.Cut(lower, "-")
		}
		switch base {
		case "latest", "canary", "slim", "alpine", "debian", "distroless", "":
			return judgement{vd: fine}
		}
	}
	if p == dotnetSDK {
		return judgeSDK(v, allowRest)
	}
	pv, rest, ok := parseVersion(v)
	if !ok {
		return judgement{vd: notJudged, reason: fmt.Sprintf("%q is not a %s version this check reads", clean(v, 60), p.name())}
	}
	if (p == node || p == dotnet) && strings.HasPrefix(rest, ".x") && len(pv.parts) < 3 {
		rest = strings.TrimPrefix(rest, ".x") // "20.x", "8.0.x": a line that floats
	}
	if rest != "" && !(allowRest && strings.HasPrefix(rest, "-")) {
		return judgement{vd: notJudged, reason: fmt.Sprintf("%q is not an exact %s version", clean(v, 60), p.name())}
	}
	return judgeLine(p, pv)
}

// judgeLine judges a parsed version. A Node.js codename arrives as its major
// version alone, so it floats like one.
func judgeLine(p product, pv parsed) judgement {
	v := pv.version()
	j := judgement{current: pv.text}
	switch p {
	case node, dotnet:
		fixedIn, ok := assess.NodeFixed[v.Major]
		if p == dotnet {
			fixedIn, ok = assess.DotnetFixed[v.Major]
		}
		if !ok {
			if v.Major > p.newest() {
				j.vd = fine // released after October 21, 2026, with the fix
				return j
			}
			j.vd, j.fixed = noFixLine, p.fixedText()
			return j
		}
		j.fixed = fixedIn.String()
		switch len(pv.parts) {
		case 3:
			if v.Less(fixedIn) {
				j.vd = bump
				return j
			}
		case 2:
			if v.Minor < fixedIn.Minor {
				j.vd, j.fixed = bump, fmt.Sprintf("%d.%d", fixedIn.Major, fixedIn.Minor)
				return j
			}
		}
		j.vd = fine
		return j
	case bun:
		fixedIn := assess.BunFixed
		j.fixed = fixedIn.String()
		switch {
		case v.Major > fixedIn.Major, len(pv.parts) == 1 && v.Major == fixedIn.Major:
			j.vd = fine
		case len(pv.parts) >= 2 && v.Major == fixedIn.Major && v.Minor > fixedIn.Minor:
			j.vd = fine
		case len(pv.parts) == 2 && v.Major == fixedIn.Major && v.Minor == fixedIn.Minor:
			j.vd = fine // 1.4 floats to 1.4.4 and later
		case len(pv.parts) == 3 && v.Major == fixedIn.Major && v.Minor == fixedIn.Minor:
			if v.Patch < fixedIn.Patch {
				j.vd = bump
			} else {
				j.vd = fine
			}
		default:
			// An older minor (Bun fixes only its newest minor) or 0.x.
			j.vd = noFixLine
		}
		return j
	}
	j.vd = notJudged
	return j
}

// manual is the step for a pin on a line with no fixed release.
func manual(p product, current string) string {
	switch p {
	case node:
		return clean(fmt.Sprintf("Node.js %s is on a release line with no fixed release: only Node.js 22, 24 and 26 received the October 2026 security releases. Move to %s by hand, since a major upgrade can change behaviour: change this pin, run your tests on the new release, then rebuild and redeploy.", current, p.fixedText()), 1000)
	case dotnetSDK:
		return clean(fmt.Sprintf(".NET SDK %s is on a feature band or release with no fixed SDK: only the 8.0.1xx, 8.0.4xx, 9.0.1xx, 9.0.3xx, 10.0.1xx and 10.0.4xx bands got one. Move to %s by hand (a feature band change can change build behaviour), run your tests, then rebuild and redeploy.", current, p.fixedText()), 1000)
	case dotnet:
		return clean(fmt.Sprintf(".NET %s is out of support and has no fixed release. Move to %s by hand (retarget the project if the major version changes), run your tests, then rebuild and redeploy.", current, p.fixedText()), 1000)
	}
	return clean(fmt.Sprintf("Bun %s has no fixed release on its minor line: Bun fixes only its newest minor. Move to Bun %s by hand, run your tests, then rebuild and redeploy (including executables made with bun build --compile).", current, p.fixedText()), 1000)
}

// nodeUpgradeLines are the lines a pin with no fixed release moves to, in
// order: the even (LTS) lines first, then 26.
var nodeUpgradeLines = []int{22, 24, 26}

var nodeLineNames = map[int]string{22: "jod", 24: "krypton"}

// upgrade returns the value that moves a pin on a line with no fixed release
// to the nearest newer line with one, keeping its form ("20" -> "22",
// "20.x" -> "22.x", "20.20.2" -> "22.23.4", "iron" -> "jod"), and the kind of
// upgrade. It returns "" when no one-line change is safe: .NET, whose runtime
// line must match the app's target framework, or a form it does not read.
func upgrade(p pin) (string, string) {
	cur := p.j.current
	if strings.Contains(p.desc, "(matrix.") {
		// A test matrix lists lines on purpose: moving one to another line
		// the matrix may already test is a choice to make by hand.
		return "", ""
	}
	switch p.prod {
	case node:
		if major, ok := nodeCodenames[strings.ToLower(cur)]; ok {
			for _, l := range nodeUpgradeLines {
				if l > major {
					if n, ok := nodeLineNames[l]; ok {
						return n, "major"
					}
				}
			}
			return "", ""
		}
		if p.source == "engines-range" {
			return rangeUpgrade(cur)
		}
		pv, rest, ok := parseVersion(cur)
		if !ok || rest != "" {
			return "", ""
		}
		for _, l := range nodeUpgradeLines {
			if l <= pv.parts[0] {
				continue
			}
			f := assess.NodeFixed[l]
			switch len(pv.parts) {
			case 1:
				return strconv.Itoa(l), "major"
			case 2:
				return fmt.Sprintf("%d.%d", f.Major, f.Minor), "major"
			default:
				return f.String(), "major"
			}
		}
	case bun:
		pv, _, ok := parseVersion(cur)
		if !ok {
			return "", ""
		}
		f := assess.BunFixed
		switch len(pv.parts) {
		case 1:
			return strconv.Itoa(f.Major), "major"
		case 2:
			return fmt.Sprintf("%d.%d", f.Major, f.Minor), "minor"
		default:
			if pv.parts[0] < f.Major {
				return f.String(), "major"
			}
			return f.String(), "minor"
		}
	case dotnetSDK:
		pv, _, ok := parseVersion(cur)
		if !ok || len(pv.parts) < 3 {
			return "", ""
		}
		best := -1
		for k, patch := range sdkFixed {
			if k[0] == pv.parts[0] && k[1] > best {
				best = k[1]
				_ = patch
			}
		}
		if best < 0 {
			return "", "" // an SDK line with no fix: the app must retarget
		}
		if pv.parts[2] < 10 { // "8.0.3" of "8.0.3xx": a band
			return fmt.Sprintf("%d.%d.%d", pv.parts[0], pv.parts[1], best), "feature band"
		}
		return fmt.Sprintf("%d.%d.%d", pv.parts[0], pv.parts[1], best*100+sdkFixed[[2]int{pv.parts[0], best}]), "feature band"
	}
	return "", ""
}

// rangeUpgrade moves a one-line engines range to the nearest line with the
// fix: "20.x" -> "22.x", "^20.11.0" -> "^22.23.4", "~20.5" -> "~22.23".
func rangeUpgrade(r string) (string, string) {
	t := strings.TrimSpace(r)
	if strings.Contains(t, "||") {
		return "", ""
	}
	prefix := t[:len(t)-len(strings.TrimLeft(t, "^~=v "))]
	body := t[len(prefix):]
	suffix := ""
	for _, s := range []string{".x.x", ".x", ".*"} {
		if strings.HasSuffix(body, s) {
			suffix, body = s, strings.TrimSuffix(body, s)
			break
		}
	}
	pv, rest, ok := parseVersion(body)
	if !ok || rest != "" {
		return "", ""
	}
	for _, l := range nodeUpgradeLines {
		if l <= pv.parts[0] {
			continue
		}
		f := assess.NodeFixed[l]
		switch len(pv.parts) {
		case 1:
			return prefix + strconv.Itoa(l) + suffix, "major"
		case 2:
			return fmt.Sprintf("%s%d.%d%s", prefix, f.Major, f.Minor, suffix), "major"
		default:
			return prefix + f.String() + suffix, "major"
		}
	}
	return "", ""
}
