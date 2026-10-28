package pins

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// RuleDependency is a package that bundles the C decoder without the fix.
const RuleDependency = "brotli/dependency"

// bundler is a package that ships Google's C Brotli decoder in its own
// build. Each row was checked on 2026-10-27 against the package's artifacts
// (BLOCK_SWITCH in its vendored decode.h, or Early Light's verdict on its
// compiled library). OSV has no advisory for any of them, so the dependency
// scanner cannot report them; PyPI Brotli and brotlicffi, which OSV does
// cover, are left to it.
type bundler struct {
	eco, name string
	// fixed is the first fixed release, "" when there is none.
	fixed string
	// from is the first affected release ("" for every release).
	from string
	// replace is what to move to when there is no fix.
	replace string
	// level is the result level: "warning" for a flaw that is not the C
	// decoder's memory corruption.
	level string
	note  string
}

var bundlers = []bundler{
	{eco: "Maven", name: "com.aayushatharva.brotli4j:*", fixed: "1.24.0"},
	{eco: "Maven", name: "com.nixxcode.jvmbrotli:*", replace: "com.aayushatharva.brotli4j 1.24.0 or later"},
	{eco: "RubyGems", name: "brotli", fixed: "0.9.1", from: "0.2.1", note: "when it builds its vendored copy (no system libbrotli at install)"},
	{eco: "npm", name: "iltorb", from: "2.0.4", replace: "Node.js's built-in zlib Brotli functions, on a fixed Node.js"},
	{eco: "npm", name: "tiny-brotli-dec-wasm", replace: "Node.js's built-in zlib Brotli functions, or a fixed decoder build"},
	{eco: "crates.io", name: "brotlic-sys", replace: "the pure Rust brotli crate (9.1 or later)"},
	{eco: "crates.io", name: "brotlic", replace: "the pure Rust brotli crate (9.1 or later)"},
	{eco: "PyPI", name: "pyarrow", replace: "a pyarrow release that bundles Brotli 1.2.1 (none yet; 26.0.0 bundles 1.2.0), or avoid reading untrusted Brotli-compressed data with it"},
	{eco: "PyPI", name: "duckdb", from: "1.1.0", replace: "a duckdb release that vendors a fixed Brotli (none yet; 2.0.0 vendors 1.1.0), or avoid reading untrusted Brotli-compressed data with it"},
	{eco: "PyPI", name: "pillow", from: "9.5.0", replace: "a Pillow release with a fixed bundled libbrotlidec (none yet; 13.0.0 bundles 1.2.0); its FreeType uses it for WOFF2 fonts, so avoid loading untrusted WOFF2 fonts"},
	{eco: "PyPI", name: "pycurl", fixed: "7.49.0", from: "7.45.3"},
	{eco: "PyPI", name: "curl-cffi", fixed: "0.17.0"},
	{eco: "PyPI", name: "pymupdf", fixed: "1.28.0", from: "1.26.0"},
	{eco: "Go", name: "github.com/andybalholm/brotli", fixed: "1.2.7", level: "warning",
		note: "a pure Go port with the same logic error: it panics (a denial of service) instead of corrupting memory"},
	{eco: "npm", name: "electron", replace: "Electron 42 or later (43.8.4, 44.10.0 and 45.1.0 are current)", note: "Electron's decoder is Chromium's copy; Electron 40 and older carry one from before the fix"},
}

// electronUnfixedThrough is the newest Electron major known to carry an
// unfixed Chromium decoder (40.0.0 does; 42.11.18 does not). 41 is not known.
const electronUnfixedThrough = 40

func normPy(n string) string {
	return strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(n))
}

func findBundler(eco, name string) (bundler, bool) {
	for _, b := range bundlers {
		if b.eco != eco {
			continue
		}
		switch {
		case strings.HasSuffix(b.name, ":*") && strings.HasPrefix(name, strings.TrimSuffix(b.name, "*")):
			return b, true
		case eco == "PyPI" && normPy(name) == b.name, b.name == name:
			return b, true
		}
	}
	return bundler{}, false
}

// cmpVersions compares dotted numeric versions ("1.24.0" < "1.3.0" is
// false); a leading v and build metadata after a plus are ignored. A
// pre-release or development suffix (1.24.0-rc1, 1.24.0rc1, 1.24.0.dev1, a
// Go pseudo-version) sorts before its release, so it is never taken for the
// fixed release itself.
func cmpVersions(a, b string) int {
	pre := func(s string) bool {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		s, _, _ = strings.Cut(s, "+")
		return strings.IndexFunc(s, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }) >= 0
	}
	if c := cmpCore(a, b); c != 0 {
		return c
	}
	switch pa, pb := pre(a), pre(b); {
	case pa && !pb:
		return -1
	case !pa && pb:
		return 1
	}
	return 0
}

func cmpCore(a, b string) int {
	clean := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		s, _, _ = strings.Cut(s, "+")
		var out []int
		for _, p := range strings.Split(s, ".") {
			digits := p
			if i := strings.IndexFunc(p, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
				digits = p[:i]
			}
			n, err := strconv.Atoi(digits)
			if err != nil {
				break
			}
			out = append(out, n)
			if digits != p {
				break
			}
		}
		return out
	}
	x, y := clean(a), clean(b)
	for i := 0; i < max(len(x), len(y)); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p != q {
			if p < q {
				return -1
			}
			return 1
		}
	}
	return 0
}

// depVerdict judges version of a bundler: affected, and the fix text.
func depVerdict(b bundler, version string) (affected bool, fixed string) {
	if version == "" || !regexp.MustCompile(`^v?\d+(\.\d+)*`).MatchString(version) {
		return false, ""
	}
	if b.name == "electron" {
		major, _ := strconv.Atoi(strings.Split(strings.TrimPrefix(version, "v"), ".")[0])
		return major <= electronUnfixedThrough, ""
	}
	if b.from != "" && cmpVersions(version, b.from) < 0 {
		return false, ""
	}
	if b.fixed == "" {
		return true, ""
	}
	return cmpVersions(version, b.fixed) < 0, b.fixed
}

// depPin is one dependency at one place in a file.
type depPin struct {
	eco, name, version string
	file               string
	line, col          int // col of version on line, -1 when not editable there
	// lock is true for a lockfile, which a package manager must rewrite.
	lock bool
}

func (s *scanner) addDep(d depPin) {
	b, ok := findBundler(d.eco, d.name)
	if !ok {
		return
	}
	affected, fixed := depVerdict(b, d.version)
	if !affected {
		return
	}
	j := judgement{vd: noFixLine, current: d.version, fixed: b.replace}
	if fixed != "" {
		j = judgement{vd: bump, current: d.version, fixed: fixed}
	}
	p := pin{prod: dependency, source: "dependency", desc: path.Base(d.file), file: d.file, line: d.line, editFile: d.file, editLine: d.line, col: d.col, j: j,
		dep: &depInfo{eco: d.eco, name: d.name, bundler: b, lock: d.lock}}
	if d.lock {
		p.col = -1
		p.notes = lockCommand(d.eco, d.name, fixed, d.file)
	}
	s.add(p)
}

type depInfo struct {
	eco, name string
	bundler   bundler
	lock      bool
}

// lockCommand is the command that moves a locked dependency.
func lockCommand(eco, name, fixed, file string) string {
	base := path.Base(file)
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return fmt.Sprintf("run `npm install %s@%s` (or update what pulls it in), which rewrites the lockfile", name, orLatest(fixed))
	case base == "yarn.lock":
		return fmt.Sprintf("run `yarn up %s@%s`", name, orLatest(fixed))
	case base == "pnpm-lock.yaml":
		return fmt.Sprintf("run `pnpm update %s@%s`", name, orLatest(fixed))
	case base == "poetry.lock":
		return fmt.Sprintf("run `poetry update %s`", name)
	case base == "uv.lock":
		return fmt.Sprintf("run `uv lock --upgrade-package %s`", name)
	case base == "Pipfile.lock":
		return fmt.Sprintf("run `pipenv update %s`", name)
	case strings.HasPrefix(base, "requirements"):
		return fmt.Sprintf("the requirement is hash-pinned: set %s==%s and regenerate its hashes (pip-compile --generate-hashes)", name, orLatest(fixed))
	case base == "Gemfile.lock" || base == "Gemfile":
		return fmt.Sprintf("run `bundle update %s` (with Gemfile.lock, an edit to the Gemfile alone fails a frozen install)", name)
	case base == "Cargo.lock":
		return fmt.Sprintf("replace %s in Cargo.toml, then run `cargo update`", name)
	case base == "gradle.lockfile":
		return "bump the version in the build file, then run `./gradlew dependencies --write-locks`"
	case base == "build.gradle" || base == "build.gradle.kts" || base == "libs.versions.toml":
		return fmt.Sprintf("bump %s to %s here, then run `./gradlew dependencies --write-locks` so gradle.lockfile agrees", name, orLatest(fixed))
	case base == "packages.lock.json":
		return "update the SDK or runtime pack, then run `dotnet restore --force-evaluate`"
	}
	return "update it with the package manager, which rewrites the lockfile"
}

func orLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

var (
	reqLine     = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][0-9A-Za-z.+-]*)`)
	tomlName    = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	tomlVersion = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
	gemLock     = regexp.MustCompile(`^    ([A-Za-z0-9_-]+) \(([0-9][^)]*)\)$`)
	gemfileLine = regexp.MustCompile(`^\s*gem\s+["']([A-Za-z0-9_-]+)["']\s*,\s*["']=?\s*([0-9][0-9.]*)["']`)
	goRequire   = regexp.MustCompile(`^\s*(?:require\s+)?(github\.com/andybalholm/brotli)\s+(v[0-9][^\s]*)`)
	gradleCoord = regexp.MustCompile(`["']((?:com\.aayushatharva\.brotli4j|com\.nixxcode\.jvmbrotli):[A-Za-z0-9_.-]+):([0-9][0-9A-Za-z.+-]*)["']`)
	gradleLock  = regexp.MustCompile(`^((?:com\.aayushatharva\.brotli4j|com\.nixxcode\.jvmbrotli):[A-Za-z0-9_.-]+):([0-9][^=]*)=`)
	yarnHeader  = regexp.MustCompile(`^"?(@?[^@\s"]+)@`)
	yarnVersion = regexp.MustCompile(`^\s+version:?\s+"?([0-9][^"\s]*)"?`)
	pnpmKey     = regexp.MustCompile(`^\s+/?(@?[^@\s/]+(?:/[^@\s]+)?)@([0-9][^:(\s]*)[:(]`)
	pomArtifact = regexp.MustCompile(`<artifactId>\s*([A-Za-z0-9_.-]+)\s*</artifactId>`)
	pomGroup    = regexp.MustCompile(`<groupId>\s*([A-Za-z0-9_.-]+)\s*</groupId>`)
	pomVersion  = regexp.MustCompile(`<version>\s*([^<\s]+)\s*</version>`)
	pomProp     = regexp.MustCompile(`<([A-Za-z0-9_.-]+)>\s*([0-9][^<\s]*)\s*</[A-Za-z0-9_.-]+>`)
)

// dependencyFile reads the dependency files a bundler can be named in.
func dependencyFile(rel string) bool {
	base := path.Base(rel)
	switch base {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock",
		"Gemfile", "Gemfile.lock", "Cargo.lock", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile", "libs.versions.toml", "packages.lock.json":
		return true
	}
	return strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")
}

// dependencies reads one dependency file.
func (s *scanner) dependencies(rel string, b []byte) {
	base := path.Base(rel)
	lines := splitLines(b)
	switch {
	case base == "package.json":
		var doc map[string]any
		if json.Unmarshal(b, &doc) != nil {
			return
		}
		for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
			m, _ := doc[sec].(map[string]any)
			for name, v := range m {
				ver, _ := v.(string)
				if _, ok := findBundler("npm", name); !ok || ver == "" {
					continue
				}
				line, col, ok := locateJSON(b, sec, name, ver)
				if !ok {
					line, col = 1, -1
				}
				exact := strings.TrimLeft(ver, "^~=v ")
				s.addDep(depPin{eco: "npm", name: name, version: exact, file: rel, line: line, col: col + strings.Index(ver, exact)})
			}
		}
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		var doc struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
		}
		if json.Unmarshal(b, &doc) != nil {
			return
		}
		for key, p := range doc.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 {
				continue
			}
			name := key[i+len("node_modules/"):]
			if _, ok := findBundler("npm", name); !ok {
				continue
			}
			line, _, _ := locateJSON(b, "", key, "")
			s.addDep(depPin{eco: "npm", name: name, version: p.Version, file: rel, line: max(line, 1), col: -1, lock: true})
		}
	case base == "yarn.lock":
		name := ""
		for i, l := range lines {
			if m := yarnHeader.FindStringSubmatch(l); m != nil && !strings.HasPrefix(l, " ") {
				name = m[1]
				continue
			}
			if m := yarnVersion.FindStringSubmatch(l); m != nil && name != "" {
				s.addDep(depPin{eco: "npm", name: name, version: m[1], file: rel, line: i + 1, col: -1, lock: true})
				name = ""
			}
		}
	case base == "pnpm-lock.yaml":
		for i, l := range lines {
			if m := pnpmKey.FindStringSubmatch(l); m != nil {
				s.addDep(depPin{eco: "npm", name: m[1], version: m[2], file: rel, line: i + 1, col: -1, lock: true})
			}
		}
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		for i, l := range lines {
			if m := reqLine.FindStringSubmatchIndex(l); m != nil {
				d := depPin{eco: "PyPI", name: l[m[2]:m[3]], version: l[m[4]:m[5]], file: rel, line: i + 1, col: m[4]}
				// A hash-pinned requirement needs the new release's hashes
				// too: pip-compile --generate-hashes rewrites them.
				if strings.Contains(l, "--hash") || strings.HasSuffix(strings.TrimSpace(l), "\\") {
					d.lock = true
				}
				s.addDep(d)
			}
		}
	case base == "poetry.lock" || base == "uv.lock" || base == "Cargo.lock":
		eco := "PyPI"
		if base == "Cargo.lock" {
			eco = "crates.io"
		}
		name := ""
		for i, l := range lines {
			if strings.HasPrefix(l, "[[package]]") {
				name = ""
			}
			if m := tomlName.FindStringSubmatch(l); m != nil {
				name = m[1]
			}
			if m := tomlVersion.FindStringSubmatch(l); m != nil && name != "" {
				s.addDep(depPin{eco: eco, name: name, version: m[1], file: rel, line: i + 1, col: -1, lock: true})
				name = ""
			}
		}
	case base == "Pipfile.lock":
		// Only default and develop: _meta and anything else have other shapes.
		var raw map[string]json.RawMessage
		if json.Unmarshal(b, &raw) != nil {
			s.skips = append(s.skips, Skip{File: rel, Reason: "not valid JSON"})
			return
		}
		for _, sec := range []string{"default", "develop"} {
			var pkgs map[string]struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(raw[sec], &pkgs) != nil {
				continue
			}
			for name, p := range pkgs {
				if _, ok := findBundler("PyPI", name); !ok {
					continue
				}
				v := strings.TrimLeft(p.Version, "=")
				line, _, _ := locateJSON(b, sec, name, "")
				s.addDep(depPin{eco: "PyPI", name: name, version: v, file: rel, line: max(line, 1), col: -1, lock: true})
			}
		}
	case base == "Gemfile.lock":
		for i, l := range lines {
			if m := gemLock.FindStringSubmatch(l); m != nil {
				s.addDep(depPin{eco: "RubyGems", name: m[1], version: m[2], file: rel, line: i + 1, col: -1, lock: true})
			}
		}
	case base == "Gemfile":
		locked := s.exists(path.Join(path.Dir(rel), "Gemfile.lock"))
		for i, l := range lines {
			if m := gemfileLine.FindStringSubmatchIndex(l); m != nil {
				// With a Gemfile.lock, bundler must move both: an edit to the
				// Gemfile alone leaves a frozen install failing.
				s.addDep(depPin{eco: "RubyGems", name: l[m[2]:m[3]], version: l[m[4]:m[5]], file: rel, line: i + 1, col: m[4], lock: locked})
			}
		}
	case base == "go.mod":
		for i, l := range lines {
			if m := goRequire.FindStringSubmatchIndex(l); m != nil {
				v := l[m[4]:m[5]]
				// go.sum must move with go.mod: the go tool does that (depfix).
				s.addDep(depPin{eco: "Go", name: l[m[2]:m[3]], version: strings.TrimPrefix(v, "v"), file: rel, line: i + 1, col: -1, lock: true})
			}
		}
	case base == "build.gradle" || base == "build.gradle.kts":
		locked := s.gradleLocked(rel)
		for i, l := range lines {
			if m := gradleCoord.FindStringSubmatchIndex(l); m != nil {
				s.addDep(depPin{eco: "Maven", name: l[m[2]:m[3]], version: l[m[4]:m[5]], file: rel, line: i + 1, col: m[4], lock: locked})
			}
		}
	case base == "gradle.lockfile":
		for i, l := range lines {
			if m := gradleLock.FindStringSubmatch(l); m != nil {
				s.addDep(depPin{eco: "Maven", name: m[1], version: m[2], file: rel, line: i + 1, col: -1, lock: true})
			}
		}
	case base == "libs.versions.toml":
		s.versionCatalog(rel, lines, s.gradleLocked(rel))
	case base == "pom.xml":
		s.pom(rel, lines)
	case base == "packages.lock.json":
		s.nugetLock(rel, b)
	}
}

// versionCatalog reads a Gradle version catalog: module = "g:a:v" inline,
// or module = "g:a" with version.ref into [versions].
func (s *scanner) versionCatalog(rel string, lines []string, locked bool) {
	versions := map[string][2]int{} // key -> line, col of the value
	section := ""
	modRe := regexp.MustCompile(`module\s*=\s*"((?:com\.aayushatharva\.brotli4j|com\.nixxcode\.jvmbrotli):[^":]+)"`)
	refRe := regexp.MustCompile(`version\.ref\s*=\s*"([^"]+)"`)
	inlineRe := regexp.MustCompile(`version\s*=\s*"([0-9][^"]*)"`)
	keyRe := regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*"([0-9][^"]*)"`)
	type use struct {
		name, ref string
		line      int
		inline    string
		col       int
	}
	var uses []use
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			section = t
			continue
		}
		if section == "[versions]" {
			if m := keyRe.FindStringSubmatchIndex(l); m != nil {
				versions[l[m[2]:m[3]]] = [2]int{i + 1, m[4]}
			}
			continue
		}
		if m := gradleCoord.FindStringSubmatchIndex(l); m != nil {
			s.addDep(depPin{eco: "Maven", name: l[m[2]:m[3]], version: l[m[4]:m[5]], file: rel, line: i + 1, col: m[4], lock: locked})
			continue
		}
		if m := modRe.FindStringSubmatch(l); m != nil {
			u := use{name: m[1], line: i + 1, col: -1}
			if r := refRe.FindStringSubmatch(l); r != nil {
				u.ref = r[1]
			} else if v := inlineRe.FindStringSubmatchIndex(l); v != nil {
				u.inline, u.col = l[v[2]:v[3]], v[2]
			}
			uses = append(uses, u)
		}
	}
	for _, u := range uses {
		if u.inline != "" {
			s.addDep(depPin{eco: "Maven", name: u.name, version: u.inline, file: rel, line: u.line, col: u.col, lock: locked})
			continue
		}
		if at, ok := versions[u.ref]; ok {
			l := lines[at[0]-1]
			m := keyRe.FindStringSubmatch(l)
			s.addDep(depPin{eco: "Maven", name: u.name, version: m[2], file: rel, line: at[0], col: at[1], lock: locked})
		}
	}
}

// pom reads <dependency> blocks: a literal version, or ${property} from the
// same pom's <properties>.
func (s *scanner) pom(rel string, lines []string) {
	props := map[string][2]int{}
	inProps := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "<properties>"):
			inProps = true
			continue
		case strings.HasPrefix(t, "</properties>"):
			inProps = false
		}
		if inProps {
			if m := pomProp.FindStringSubmatchIndex(l); m != nil {
				props[l[m[2]:m[3]]] = [2]int{i + 1, m[4]}
			}
		}
	}
	var group, artifact string
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "<dependency>") || strings.HasPrefix(t, "<plugin>") {
			group, artifact = "", ""
		}
		if m := pomGroup.FindStringSubmatch(l); m != nil {
			group = m[1]
		}
		if m := pomArtifact.FindStringSubmatch(l); m != nil {
			artifact = m[1]
		}
		m := pomVersion.FindStringSubmatchIndex(l)
		if m == nil || group == "" || artifact == "" {
			continue
		}
		name := group + ":" + artifact
		v := l[m[2]:m[3]]
		if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			if at, ok := props[v[2:len(v)-1]]; ok {
				pl := lines[at[0]-1]
				pm := pomProp.FindStringSubmatch(pl)
				s.addDep(depPin{eco: "Maven", name: name, version: pm[2], file: rel, line: at[0], col: at[1]})
			}
		} else {
			s.addDep(depPin{eco: "Maven", name: name, version: v, file: rel, line: i + 1, col: m[2]})
		}
		group, artifact = "", ""
	}
}

// runtimePackRe names the NuGet packages that carry the .NET runtime's
// native code (the advisory's list, plus the ASP.NET Core and per-platform
// ILCompiler packs it leaves out).
var runtimePackRe = regexp.MustCompile(`^(?:Microsoft\.NETCore\.App\.Runtime\.|Microsoft\.AspNetCore\.App\.Runtime\.|Microsoft\.DotNet\.ILCompiler$|runtime\.[^.]+.*\.Microsoft\.DotNet\.ILCompiler$)`)

// nugetLock reads packages.lock.json for runtime packs below the fix.
func (s *scanner) nugetLock(rel string, b []byte) {
	var doc struct {
		Dependencies map[string]map[string]struct {
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return
	}
	for _, pkgs := range doc.Dependencies {
		for name, p := range pkgs {
			if !runtimePackRe.MatchString(name) || p.Resolved == "" {
				continue
			}
			j := judgeValue(dotnet, p.Resolved, false)
			if j.vd != bump && j.vd != noFixLine {
				continue
			}
			line, _, _ := locateJSON(b, "", name, "")
			s.add(pin{prod: dotnet, source: "runtime-pack-lock", desc: "packages.lock.json " + name, file: rel, line: max(line, 1), editFile: rel,
				editLine: max(line, 1), col: -1, j: j, notes: lockCommand("NuGet", name, j.fixed, rel)})
		}
	}
}

// gradleLocked reports whether the project that rel builds is locked.
func (s *scanner) gradleLocked(rel string) bool {
	// Gradle keeps one lockfile per project, next to its build file. A
	// version catalog in gradle/ serves the root project's.
	d := path.Dir(rel)
	if path.Base(rel) == "libs.versions.toml" && path.Base(d) == "gradle" {
		d = path.Dir(d)
	}
	return s.exists(path.Join(d, "gradle.lockfile"))
}
