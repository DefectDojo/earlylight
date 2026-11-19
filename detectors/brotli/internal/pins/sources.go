package pins

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DefectDojo/earlylight/internal/refs"
)

func isYAML(lower string) bool {
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}

// yamlDoc parses b, recording a skip when it does not parse.
func (s *scanner) yamlDoc(rel string, b []byte) (*yaml.Node, bool) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: "not valid YAML: " + clean(err.Error(), 200)})
		return nil, false
	}
	return &doc, true
}

// mapGet returns the value of key in a mapping node.
func mapGet(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// nodePin judges a YAML scalar as a pin of prod at the scalar's own line.
func (s *scanner) nodePin(prod product, source, desc, rel string, lines []string, v *yaml.Node, judge func(string) judgement) {
	if v == nil || v.Kind != yaml.ScalarNode {
		return
	}
	if strings.Contains(v.Value, "${{") || strings.Contains(v.Value, "$(") || strings.Contains(v.Value, "<<") {
		s.expression(rel, v.Line, desc, strings.TrimSpace(v.Value))
		return
	}
	if strings.Contains(v.Value, "\n") {
		// A block of one version per line (setup-dotnet takes several).
		for _, part := range strings.Split(strings.TrimSpace(v.Value), "\n") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			line := 0
			for i := v.Line; i < len(lines) && i < v.Line+64; i++ {
				if strings.TrimSpace(lines[i]) == part {
					line = i + 1
					break
				}
			}
			if line == 0 {
				continue
			}
			s.addJudged(prod, source, desc, rel, line, strings.Index(lines[line-1], part), part, judge(part))
		}
		return
	}
	col := -1
	if v.Line >= 1 && v.Line <= len(lines) && v.Column >= 1 && v.Column-1 <= len(lines[v.Line-1]) {
		if k := strings.Index(lines[v.Line-1][v.Column-1:], v.Value); k >= 0 {
			col = v.Column - 1 + k
		}
	}
	s.addJudged(prod, source, desc, rel, v.Line, col, v.Value, judge(v.Value))
}

// addJudged adds a judged value written at col of line (col -1: not
// editable verbatim).
func (s *scanner) addJudged(prod product, source, desc, rel string, line, col int, value string, j judgement) {
	if j.vd == notJudged || unresolvedRe.MatchString(value) {
		s.expression(rel, line, desc, value)
		return
	}
	p := pin{prod: prod, source: source, desc: desc, file: rel, line: line, editFile: rel, editLine: line, col: -1, j: j}
	if col >= 0 && j.current != "" {
		if k := strings.Index(value, j.current); k >= 0 {
			p.col = col + k
		}
	}
	if p.col < 0 {
		p.notes = "the value is not written on one line as it is read"
	}
	s.add(p)
}

func plain(prod product) func(string) judgement {
	return func(v string) judgement { return judgeValue(prod, v, false) }
}

// setupInputs are the workflow steps whose input picks a runtime release.
var setupInputs = []struct {
	uses, input, source string
	prod                product
}{
	{"actions/setup-node", "node-version", "setup-node", node},
	{"oven-sh/setup-bun", "bun-version", "setup-bun", bun},
	{"actions/setup-dotnet", "dotnet-version", "setup-dotnet", dotnetSDK},
}

var exprRe = regexp.MustCompile(`^\$\{\{\s*(matrix|env)\.([A-Za-z0-9_-]+)\s*\}\}$`)

// workflow reads setup-node, setup-bun and setup-dotnet steps in a GitHub
// Actions workflow or composite action. A value written as ${{ matrix.X }}
// is judged at each value of the job's matrix X, and ${{ env.X }} at the
// job's or workflow's env X; any other expression is not read.
func (s *scanner) workflow(rel string, b []byte) {
	doc, ok := s.yamlDoc(rel, b)
	if !ok || len(doc.Content) == 0 {
		return
	}
	lines := splitLines(b)
	root := doc.Content[0]
	wfEnv := mapGet(root, "env")
	steps := func(job *yaml.Node, list *yaml.Node) {
		if list == nil || list.Kind != yaml.SequenceNode {
			return
		}
		var matrix, jobEnv *yaml.Node
		if job != nil {
			matrix = mapGet(mapGet(job, "strategy"), "matrix")
			jobEnv = mapGet(job, "env")
		}
		for _, st := range list.Content {
			uses := mapGet(st, "uses")
			with := mapGet(st, "with")
			if uses == nil || with == nil {
				continue
			}
			action, _, _ := strings.Cut(uses.Value, "@")
			for _, a := range setupInputs {
				if action != a.uses {
					continue
				}
				v := mapGet(with, a.input)
				if v == nil {
					continue
				}
				desc := a.uses + " " + a.input
				m := exprRe.FindStringSubmatch(strings.TrimSpace(v.Value))
				switch {
				case m == nil:
					s.nodePin(a.prod, a.source, desc, rel, lines, v, plain(a.prod))
				case m[1] == "matrix":
					var vals []*yaml.Node
					if v := mapGet(matrix, m[2]); v != nil && v.Kind == yaml.SequenceNode {
						vals = append(vals, v.Content...)
					} else if v != nil {
						vals = append(vals, v)
					}
					// matrix.include adds combinations, each of which may set the key.
					if inc := mapGet(matrix, "include"); inc != nil && inc.Kind == yaml.SequenceNode {
						for _, e := range inc.Content {
							if v := mapGet(e, m[2]); v != nil {
								vals = append(vals, v)
							}
						}
					}
					if len(vals) == 0 {
						s.skips = append(s.skips, Skip{File: rel, Line: v.Line, Reason: clean(fmt.Sprintf("%s %s is not resolved from the job's matrix", desc, v.Value), 200)})
					}
					for _, e := range vals {
						s.nodePin(a.prod, a.source, desc+" (matrix."+m[2]+")", rel, lines, e, plain(a.prod))
					}
				case m[1] == "env":
					e := mapGet(jobEnv, m[2])
					if e == nil {
						e = mapGet(wfEnv, m[2])
					}
					if e == nil {
						s.skips = append(s.skips, Skip{File: rel, Line: v.Line, Reason: clean(fmt.Sprintf("%s %s is not set in the job's or workflow's env", desc, v.Value), 200)})
					}
					s.nodePin(a.prod, a.source, desc+" (env."+m[2]+")", rel, lines, e, plain(a.prod))
				}
			}
		}
	}
	if jobs := mapGet(root, "jobs"); jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 1; i < len(jobs.Content); i += 2 {
			steps(jobs.Content[i], mapGet(jobs.Content[i], "steps"))
		}
	}
	steps(nil, mapGet(mapGet(root, "runs"), "steps")) // a composite action
}

// azurePipelines reads NodeTool, UseNode and UseDotNet tasks.
func (s *scanner) azurePipelines(rel string, b []byte) {
	doc, ok := s.yamlDoc(rel, b)
	if !ok {
		return
	}
	lines := splitLines(b)
	walk(doc, func(n *yaml.Node) {
		task := mapGet(n, "task")
		inputs := mapGet(n, "inputs")
		if task == nil || inputs == nil {
			return
		}
		name, _, _ := strings.Cut(task.Value, "@")
		switch name {
		case "NodeTool", "UseNode":
			v := mapGet(inputs, "versionSpec")
			if v == nil {
				v = mapGet(inputs, "version")
			}
			s.nodePin(node, "azure-pipelines", "Azure Pipelines "+name+" task", rel, lines, v, plain(node))
		case "UseDotNet":
			prod := dotnetSDK
			if pt := mapGet(inputs, "packageType"); pt != nil && (pt.Value == "runtime" || pt.Value == "aspnetcore") {
				prod = dotnet
			}
			s.nodePin(prod, "azure-pipelines", "Azure Pipelines UseDotNet task", rel, lines, mapGet(inputs, "version"), plain(prod))
		}
	})
}

func walk(n *yaml.Node, f func(*yaml.Node)) {
	var rec func(*yaml.Node, int)
	rec = func(n *yaml.Node, depth int) {
		if n == nil || depth > 64 {
			return
		}
		f(n)
		for _, c := range n.Content {
			rec(c, depth+1)
		}
	}
	rec(n, 0)
}

// circleCI reads docker executor images and the node orb's node-version.
func (s *scanner) circleCI(rel string, b []byte) {
	doc, ok := s.yamlDoc(rel, b)
	if !ok {
		return
	}
	lines := splitLines(b)
	walk(doc, func(n *yaml.Node) {
		if d := mapGet(n, "docker"); d != nil && d.Kind == yaml.SequenceNode {
			for _, e := range d.Content {
				img := mapGet(e, "image")
				if img == nil || img.Kind != yaml.ScalarNode {
					continue
				}
				if k := strings.Index(img.Value, "<<"); k >= 0 {
					// A runtime image whose tag is a parameter is not checked.
					if ref, err := parseReference(strings.TrimSuffix(strings.TrimSpace(img.Value[:k]), ":")); err == nil {
						if _, ok := imageRepos[ref.Registry+"/"+ref.Path]; ok {
							s.expression(rel, img.Line, "CircleCI docker image", img.Value)
						}
					}
					continue
				}
				s.judgeImage(refs.Ref{File: rel, Line: img.Line, Column: img.Column, Kind: "circleci", Context: "docker image",
					Text: img.Value, Image: img.Value, EditFile: rel, EditLine: img.Line, EditText: img.Value})
			}
		}
		for _, orb := range []string{"node/install", "node/default"} {
			if o := mapGet(n, orb); o != nil {
				s.nodePin(node, "circleci-node-orb", "CircleCI "+orb+" node-version", rel, lines, mapGet(o, "node-version"), plain(node))
			}
		}
	})
}

// globalJSON reads sdk.version.
func (s *scanner) globalJSON(rel string, b []byte) {
	var doc struct {
		SDK struct {
			Version string `json:"version"`
		} `json:"sdk"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		s.skips = append(s.skips, Skip{File: rel, Reason: jsonProblem(err)})
		return
	}
	if doc.SDK.Version == "" {
		return
	}
	v := doc.SDK.Version
	line, col, ok := locateJSON(b, "sdk", "version", v)
	if !ok {
		line, col = 1, -1
	}
	s.addJudged(dotnetSDK, "global.json", "global.json sdk.version", rel, line, col, v, judgeSDK(v, false))
}

var (
	tfmRe  = regexp.MustCompile(`<TargetFrameworks?>([^<]+)</TargetFrameworks?>`)
	tfmOne = regexp.MustCompile(`^net(?:coreapp)?(\d+)\.(\d+)`)
	rfvRe  = regexp.MustCompile(`<RuntimeFrameworkVersion>\s*([0-9][0-9.]*)\s*</RuntimeFrameworkVersion>`)
	// appRe marks a project that runs itself: each of its targets is a
	// build someone may deploy.
	appRe        = regexp.MustCompile(`Sdk="Microsoft\.NET\.Sdk\.(?:Web|Worker|BlazorWebAssembly)|<OutputType>\s*(?:Exe|WinExe)\s*</OutputType>|<AzureFunctionsVersion>`)
	runtimePkgRe = regexp.MustCompile(`<PackageReference\s+[^>]*Include="((?:Microsoft\.NETCore\.App\.Runtime|Microsoft\.AspNetCore\.App\.Runtime|runtime\.[^"]+\.Microsoft\.DotNet\.ILCompiler|Microsoft\.DotNet\.ILCompiler)[^"]*)"[^>]*Version="([0-9][0-9.]*)"`)
)

// dotnetProject reads a project or props file: target frameworks on a .NET
// release with no fix, RuntimeFrameworkVersion, and runtime pack references.
func (s *scanner) dotnetProject(rel string, b []byte) {
	app := appRe.Match(b)
	for i, l := range splitLines(b) {
		if m := tfmRe.FindStringSubmatchIndex(l); m != nil {
			list := l[m[2]:m[3]]
			// A library that also targets a supported .NET runs on whatever
			// its consumer runs: only a list of unsupported targets pins one.
			// An app's every target is a build that may be deployed.
			supported := false
			for _, tfm := range strings.Split(list, ";") {
				if app {
					break
				}
				if mm := tfmOne.FindStringSubmatch(strings.TrimSpace(tfm)); mm != nil && !strings.HasPrefix(strings.TrimSpace(tfm), "netcoreapp") && atoi(mm[1]) >= 8 {
					supported = true
				}
			}
			if supported {
				s.judge(rel, i+1, RuleDotnet, "target-framework") // judged: on a supported .NET
			}
			for _, tfm := range strings.Split(list, ";") {
				if supported {
					break
				}
				t := strings.TrimSpace(tfm)
				mm := tfmOne.FindStringSubmatch(t)
				if mm == nil || strings.HasPrefix(t, "netstandard") || (len(t) >= 5 && t[3] >= '1' && t[3] <= '4' && !strings.Contains(t, ".")) {
					continue // .NET Framework (net48) and netstandard carry no .NET runtime
				}
				major := atoi(mm[1])
				if strings.HasPrefix(t, "netcoreapp") {
					major = 3 // netcoreapp1.x to 3.1: long out of support
				}
				s.judge(rel, i+1, RuleDotnet, "target-framework")
				j := judgeLine(dotnet, parsed{parts: []int{major}, text: t})
				if j.vd == noFixLine {
					s.add(pin{prod: dotnet, source: "target-framework", desc: path.Base(rel) + " TargetFramework", file: rel, line: i + 1,
						editFile: rel, editLine: i + 1, col: -1, j: j, notes: "retargeting the project to a supported .NET is a code change: update the TargetFramework, the packages it pulls in, and test"})
				}
			}
		}
		if m := rfvRe.FindStringSubmatchIndex(l); m != nil {
			v := l[m[2]:m[3]]
			s.addJudged(dotnet, "runtime-framework-version", path.Base(rel)+" RuntimeFrameworkVersion", rel, i+1, m[2], v, judgeValue(dotnet, v, false))
		}
		if m := runtimePkgRe.FindStringSubmatchIndex(l); m != nil {
			v := l[m[4]:m[5]]
			s.addJudged(dotnet, "runtime-pack", path.Base(rel)+" PackageReference "+l[m[2]:m[3]], rel, i+1, m[4], v, judgeValue(dotnet, v, false))
		}
	}
}

var netlifyRe = regexp.MustCompile(`^\s*NODE_VERSION\s*=\s*["']([^"']+)["']`)

// netlify reads [build.environment] NODE_VERSION.
func (s *scanner) netlify(rel string, b []byte) {
	for i, l := range splitLines(b) {
		if m := netlifyRe.FindStringSubmatchIndex(l); m != nil {
			v := l[m[2]:m[3]]
			s.addJudged(node, "netlify", "netlify.toml NODE_VERSION", rel, i+1, m[2], v, judgeValue(node, v, false))
		}
	}
}

// enginesRange judges an engines.node range that a platform resolves to one
// release line (Heroku, Vercel and Render pick the newest release that
// satisfies it): "20.x", "^20.11.0", "~20", "20". A range open above
// (">=18", "*") or with an alternative on a line with a fix is fine.
func (s *scanner) enginesRange(rel string, b []byte, v string) {
	if _, _, ok := parseVersion(strings.TrimSpace(v)); ok && len(strings.Split(strings.TrimSpace(strings.TrimPrefix(v, "v")), ".")) == 3 {
		return // an exact release: judged as a pin
	}
	best := -1
	for _, alt := range strings.Split(v, "||") {
		a := strings.TrimSpace(alt)
		a = strings.TrimLeft(a, "^~=v ")
		if a == "" || strings.ContainsAny(a, "<>*") || strings.Contains(a, " - ") {
			return // open above, or a span this check does not resolve
		}
		pv, rest, ok := parseVersion(a)
		if !ok || (rest != "" && rest != ".x" && rest != ".x.x" && rest != ".*") {
			return
		}
		if pv.parts[0] > best {
			best = pv.parts[0]
		}
	}
	if best < 0 {
		return
	}
	j := judgeLine(node, parsed{parts: []int{best}, text: strings.TrimSpace(v)})
	if j.vd != noFixLine {
		return
	}
	line, col, ok := locateJSON(b, "engines", "node", v)
	if !ok {
		line, col = 1, -1
	}
	s.add(pin{prod: node, source: "engines-range", desc: "package.json engines.node", file: rel, line: line, editFile: rel, editLine: line, col: col, j: j,
		notes: "the range keeps the app on a Node.js line with no fix"})
}

// textCandidate reports whether a file may hold install commands, runtime
// identifiers or version variables the text patterns read.
func textCandidate(rel string) bool {
	lower := strings.ToLower(rel)
	base := path.Base(lower)
	switch {
	case base == "dockerfile" || base == "containerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") || strings.HasPrefix(base, "containerfile."):
		return true
	case base == "makefile" || base == "jenkinsfile" || base == "procfile" || base == "app.yaml" || base == "app.yml" || base == "firebase.json" ||
		base == "serverless.yml" || base == "serverless.yaml" || base == "template.yaml" || base == "template.yml" || base == ".gitlab-ci.yml" ||
		base == "render.yaml" || base == "bitbucket-pipelines.yml" || base == "cdk.json":
		return true
	}
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "bun.lock", "packages.lock.json":
		return false // lockfiles name packages, not runtimes
	}
	switch path.Ext(lower) {
	case ".sh", ".bash", ".mk", ".tf", ".bicep", ".ps1":
		return true
	case ".ts", ".js", ".mjs", ".cjs", ".py", ".java", ".cs", ".go", ".kt":
		return !strings.Contains(lower, "node_modules/") && !strings.HasSuffix(lower, ".d.ts") && !strings.HasSuffix(lower, ".min.js")
	case ".yml", ".yaml", ".json", ".toml":
		return true
	}
	return false
}

// textGates are the strings a file must contain for the text patterns to be
// worth running.
var textGates = [][]byte{[]byte("node"), []byte("NODE"), []byte("Node"), []byte("dotnet"), []byte("DOTNET"), []byte("bun"), []byte("BUN"), []byte("nvm "), []byte("fnm ")}

// textPattern is one way a file names a runtime release in plain text.
type textPattern struct {
	re     *regexp.Regexp // group 1 is the value
	prod   product
	source string
	desc   string
	// line: the value names only a release line (a major), so only a line
	// with no fix is reported, with manual steps.
	line bool
	// sourceOnly limits the pattern to program source (CDK); otherwise it
	// does not run on program source.
	sourceOnly bool
	// managed: a provider's managed runtime, which the provider patches on
	// supported lines.
	managed bool
}

var textPatterns = []textPattern{
	{re: regexp.MustCompile(`nodejs\.org/(?:dist|download/release)/v(\d+\.\d+\.\d+)/`), prod: node, source: "node-download", desc: "Node.js download"},
	{re: regexp.MustCompile(`\b(?:ENV|ARG|export)\s+NODE_VERSION[= ]["']?([0-9v][0-9.x]*)`), prod: node, source: "node-version-var", desc: "NODE_VERSION"},
	{re: regexp.MustCompile(`^\s*NODE_VERSION:\s*["']?([0-9v][0-9.x]*)`), prod: node, source: "node-version-var", desc: "NODE_VERSION"},
	{re: regexp.MustCompile(`\b(?:nvm|fnm)\s+(?:install|use)\s+(?:--lts=)?["']?(v?\d+(?:\.\d+){0,2})\b`), prod: node, source: "node-version-manager", desc: "nvm or fnm"},
	{re: regexp.MustCompile(`\bvolta\s+(?:install|pin)\s+node@(\d+(?:\.\d+){0,2})\b`), prod: node, source: "node-version-manager", desc: "volta"},
	{re: regexp.MustCompile(`\basdf\s+(?:install|local|global|set)\s+nodejs\s+(\d+\.\d+\.\d+)\b`), prod: node, source: "node-version-manager", desc: "asdf"},
	{re: regexp.MustCompile(`\bmise\s+(?:use|install)\s+(?:-g\s+|--global\s+)?node(?:js)?@(\d+(?:\.\d+){0,2})\b`), prod: node, source: "node-version-manager", desc: "mise"},
	{re: regexp.MustCompile(`(?:deb|rpm)\.nodesource\.com/setup_(\d+)\.x`), prod: node, source: "nodesource", desc: "NodeSource setup script", line: true},
	{re: regexp.MustCompile(`bun\.sh/install[^\n]*bun-v(\d+\.\d+\.\d+)`), prod: bun, source: "bun-download", desc: "Bun install script"},
	{re: regexp.MustCompile(`\b(?:ENV|ARG|export)\s+BUN_VERSION[= ]["']?(\d+\.\d+\.\d+)`), prod: bun, source: "bun-version-var", desc: "BUN_VERSION"},
	{re: regexp.MustCompile(`\b(?:ENV|ARG|export)\s+(?:DOTNET_VERSION|ASPNET_VERSION|ASPNETCORE_VERSION)[= ]["']?(\d+\.\d+\.\d+)\b`), prod: dotnet, source: "dotnet-version-var", desc: ".NET runtime version variable"},
	{re: regexp.MustCompile(`dotnet-install\.(?:sh|ps1)\b[^\n]*(?:--runtime|-Runtime)\s+(?:dotnet|aspnetcore)[^\n]*(?:--version|-Version)\s+(\d+\.\d+\.\d+)\b`), prod: dotnet, source: "dotnet-install", desc: "dotnet-install runtime"},
	{re: regexp.MustCompile(`dotnet-install\.(?:sh|ps1)\b[^\n]*(?:--version|-Version)\s+(\d+\.\d+\.\d+)\b[^\n]*(?:--runtime|-Runtime)\s+(?:dotnet|aspnetcore)`), prod: dotnet, source: "dotnet-install", desc: "dotnet-install runtime"},
	// Managed serverless runtimes: AWS Lambda, Google Cloud, Azure.
	{re: regexp.MustCompile(`(?i)\bruntime\s*[:=]\s*["']?nodejs(\d+)(?:\.x)?\b`), prod: node, source: "managed-runtime", desc: "serverless runtime", line: true, managed: true},
	{re: regexp.MustCompile(`--runtime[= ]nodejs(\d+)\b`), prod: node, source: "managed-runtime", desc: "gcloud --runtime", line: true, managed: true},
	{re: regexp.MustCompile(`(?i)\bruntime\s*[:=]\s*["']?dotnet(?:core)?(\d+)(?:\.\d+)?\b`), prod: dotnet, source: "managed-runtime", desc: "serverless runtime", line: true, managed: true},
	{re: regexp.MustCompile(`(?i)linuxFxVersion["']?\s*[:=]\s*["']NODE\|(\d+)`), prod: node, source: "managed-runtime", desc: "Azure linuxFxVersion", line: true, managed: true},
	{re: regexp.MustCompile(`(?i)linuxFxVersion["']?\s*[:=]\s*["']DOTNET(?:CORE)?\|(\d+)`), prod: dotnet, source: "managed-runtime", desc: "Azure linuxFxVersion", line: true, managed: true},
	{re: regexp.MustCompile(`\bnode_version\s*=\s*["']~?(\d+)(?:-lts)?["']`), prod: node, source: "managed-runtime", desc: "Azure application_stack node_version", line: true, managed: true},
	{re: regexp.MustCompile(`\bdotnet_version\s*=\s*["']v?(\d+)\.0["']`), prod: dotnet, source: "managed-runtime", desc: "Azure application_stack dotnet_version", line: true, managed: true},
	{re: regexp.MustCompile(`WEBSITE_NODE_DEFAULT_VERSION["']?\s*[:=,]\s*["']~?(\d+)`), prod: node, source: "managed-runtime", desc: "WEBSITE_NODE_DEFAULT_VERSION", line: true, managed: true},
	{re: regexp.MustCompile(`\bRuntime\.NODEJS_(\d+)_X\b`), prod: node, source: "managed-runtime", desc: "AWS CDK Lambda runtime", line: true, sourceOnly: true, managed: true},
	{re: regexp.MustCompile(`\bRuntime\.DOTNET_(\d+)\b`), prod: dotnet, source: "managed-runtime", desc: "AWS CDK Lambda runtime", line: true, sourceOnly: true, managed: true},
	{re: regexp.MustCompile(`\bRuntime\.DOTNET_CORE_(\d)_\d\b`), prod: dotnet, source: "managed-runtime", desc: "AWS CDK Lambda runtime", line: true, sourceOnly: true, managed: true},
}

// versionVarRe finds a runtime version variable and the value it is set
// to, as written: group 1 the variable, group 2 the value token.
var versionVarRe = regexp.MustCompile(`\b(?:ENV|ARG|export)\s+(NODE_VERSION|BUN_VERSION|DOTNET_VERSION|ASPNET_VERSION|ASPNETCORE_VERSION)[= ](\S+)`)

// varRefRe is a value that reads one variable, plainly or with a literal
// default: $X, ${X}, ${X:-24.22.1}, ${X-24.22.1}. Anything else with a $ or
// a backtick (${X:?..}, ${X%..}, ${X:+..}, a quoted default, $(..), a
// suffix) is not evaluated.
var varRefRe = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?-)(v?[0-9][0-9A-Za-z.+-]*))?\})$`)

// versionVars are the version variables' products and sources.
var versionVars = map[string]struct {
	prod   product
	source string
}{
	"NODE_VERSION": {node, "node-version-var"}, "BUN_VERSION": {bun, "bun-version-var"},
	"DOTNET_VERSION": {dotnet, "dotnet-version-var"}, "ASPNET_VERSION": {dotnet, "dotnet-version-var"}, "ASPNETCORE_VERSION": {dotnet, "dotnet-version-var"},
}

// assignRe finds a variable set to a release (ARG BUILD_NODE=24.22.0).
var assignRe = regexp.MustCompile(`\b(?:ENV|ARG|export)\s+([A-Za-z_][A-Za-z0-9_]*)[= ]["']?(v?[0-9][0-9A-Za-z.+-]*)`)

// unresolvedRe finds a value the scan does not resolve: a variable, a
// command substitution, a template or a parameter.
var unresolvedRe = regexp.MustCompile("\\$[A-Za-z_{(]|`|<<")

// commentLine reports a line that is a comment in rel's language: # in
// shell, Dockerfile, YAML, TOML, Makefile, Python and Terraform; // in
// JavaScript, TypeScript, C#, Go, Java, Kotlin, Bicep and Terraform. In
// JavaScript and TypeScript a leading # is a private field.
func commentLine(rel, l string) bool {
	t := strings.TrimLeft(l, " \t")
	switch path.Ext(strings.ToLower(rel)) {
	case ".ts", ".js", ".mjs", ".cjs", ".java", ".cs", ".go", ".kt", ".bicep":
		return strings.HasPrefix(t, "//")
	case ".py":
		return strings.HasPrefix(t, "#")
	}
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//")
}

// dockerScope is what a Dockerfile's stages need to resolve an ARG: the
// FROM lines (0-based), and the lines that declare each ARG without a value.
type dockerScope struct {
	froms    []int
	declared map[string][]int
}

func newDockerScope(lines []string) dockerScope {
	ds := dockerScope{declared: map[string][]int{}}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		switch strings.ToUpper(f[0]) {
		case "FROM":
			ds.froms = append(ds.froms, i)
		case "ARG":
			if !strings.Contains(f[1], "=") {
				ds.declared[f[1]] = append(ds.declared[f[1]], i)
			}
		}
	}
	return ds
}

// stage returns the FROM line that starts line i's stage, or -1 before any.
func (ds dockerScope) stage(i int) int {
	start := -1
	for _, f := range ds.froms {
		if f <= i {
			start = f
		}
	}
	return start
}

// value returns the assignment of name that line i reads, or ok false: in a
// file without stages the last one above it; in a Dockerfile stage the last
// one in the stage, or the global ARG (above the first FROM) when the stage
// declares the ARG.
func (ds dockerScope) value(assigned map[string][][3]int, name string, i int) ([3]int, bool) {
	start := ds.stage(i)
	var got [3]int
	ok := false
	for _, a := range assigned[name] {
		if a[0] < i && a[0] > start {
			got, ok = a, true
		}
	}
	if ok || start < 0 {
		return got, ok
	}
	declared := false
	for _, d := range ds.declared[name] {
		declared = declared || (d > start && d < i)
	}
	if !declared {
		return got, false
	}
	for _, a := range assigned[name] {
		if a[0] < ds.froms[0] {
			got, ok = a, true
		}
	}
	return got, ok
}

// sharedARG reports a variable a by-hand edit is safer for: set in more
// than one place, or read by a FROM, where moving it changes another stage
// or the base image.
func (ds dockerScope) sharedARG(lines []string, assigned map[string][][3]int, name string) bool {
	if len(assigned[name]) > 1 {
		return true
	}
	for _, f := range ds.froms {
		if strings.Contains(lines[f], "$"+name) || strings.Contains(lines[f], "${"+name) {
			return true
		}
	}
	return false
}

// versionVar judges a version variable set from another variable: by the
// value that variable holds there (in a Dockerfile, in the line's stage),
// edited where it is set; else by a ${X:-default}'s default; else it is
// listed as not checked. A value the scan does not evaluate is listed too.
func (s *scanner) versionVar(rel string, lines []string, i int, m []int, assigned map[string][][3]int, ds dockerScope) {
	l := lines[i]
	vv := versionVars[l[m[2]:m[3]]]
	desc := fmt.Sprintf("%s (%s)", l[m[2]:m[3]], path.Base(rel))
	tok := l[m[4]:m[5]]
	if !unresolvedRe.MatchString(tok) {
		return // a literal: the text patterns judge it
	}
	r := varRefRe.FindStringSubmatchIndex(tok)
	if r == nil {
		s.expression(rel, i+1, desc, tok)
		return
	}
	name := ""
	switch {
	case r[2] >= 0:
		name = tok[r[2]:r[3]]
	case r[4] >= 0:
		name = tok[r[4]:r[5]]
	}
	if a, ok := ds.value(assigned, name, i); ok {
		v := lines[a[0]][a[1]:a[2]]
		j := judgeValue(vv.prod, v, false)
		if j.vd == notJudged {
			s.expression(rel, i+1, desc, tok)
			return
		}
		p := pin{prod: vv.prod, source: vv.source, desc: desc, file: rel, line: i + 1, editFile: rel, editLine: a[0] + 1, col: -1, j: j, via: true}
		if k := strings.Index(v, j.current); j.current != "" && k >= 0 {
			p.col = a[1] + k
		}
		if p.col >= 0 && ds.sharedARG(lines, assigned, name) {
			p.col, p.notes = -1, fmt.Sprintf("%s is set in more than one place or read by a FROM, so moving it changes another stage or the base image", name)
		}
		s.add(p)
		return
	}
	if r[8] >= 0 {
		v := tok[r[8]:r[9]]
		j := judgeValue(vv.prod, v, false)
		if j.vd == notJudged {
			s.expression(rel, i+1, desc, tok)
			return
		}
		p := pin{prod: vv.prod, source: vv.source, desc: desc, file: rel, line: i + 1, editFile: rel, editLine: i + 1, col: -1, j: j}
		if k := strings.Index(v, j.current); j.current != "" && k >= 0 {
			p.col = m[4] + r[8] + k
		}
		s.add(p)
		return
	}
	s.expression(rel, i+1, desc, tok)
}

// sha256Re finds a pinned checksum, which a download's version change would
// also need.
var sha256Re = regexp.MustCompile(`\b[0-9a-f]{64}\b`)

func isProgramSource(rel string) bool {
	switch path.Ext(strings.ToLower(rel)) {
	case ".ts", ".js", ".mjs", ".cjs", ".py", ".java", ".cs", ".go", ".kt":
		return true
	}
	return false
}

// textPatterns runs the text patterns over one file.
func (s *scanner) textPatterns(rel string, b []byte) {
	gated := false
	for _, g := range textGates {
		if bytes.Contains(b, g) {
			gated = true
			break
		}
	}
	if !gated {
		return
	}
	src := isProgramSource(rel)
	lines := splitLines(b)
	spans := logicalSpans(lines)
	// Variables the file sets to a release, by line: a version variable
	// that reads one is judged by it.
	var assigned map[string][][3]int
	var ds dockerScope
	if !src {
		ds = newDockerScope(lines)
		for i, l := range lines {
			if commentLine(rel, l) {
				continue
			}
			for _, m := range assignRe.FindAllStringSubmatchIndex(l, -1) {
				if assigned == nil {
					assigned = map[string][][3]int{}
				}
				n := l[m[2]:m[3]]
				assigned[n] = append(assigned[n], [3]int{i, m[4], m[5]})
			}
		}
	}
	for i, l := range lines {
		if i%4096 == 0 && s.ctx != nil && s.ctx.Err() != nil {
			return
		}
		if commentLine(rel, l) {
			continue
		}
		if !src {
			if m := versionVarRe.FindStringSubmatchIndex(l); m != nil {
				s.versionVar(rel, lines, i, m, assigned, ds)
			}
		}
		for _, tp := range textPatterns {
			if tp.sourceOnly != src {
				continue
			}
			m := tp.re.FindStringSubmatchIndex(l)
			if m == nil {
				continue
			}
			v := l[m[2]:m[3]]
			if m[3] < len(l) && strings.ContainsRune("$`{(%", rune(l[m[3]])) {
				continue // only the start of a value the scan does not resolve (24$SUFFIX)
			}
			desc := fmt.Sprintf("%s (%s)", tp.desc, path.Base(rel))
			if tp.line {
				s.judge(rel, i+1, tp.prod.rule(), tp.source)
				j := judgeLine(tp.prod, parsed{parts: []int{atoi(v)}, text: v})
				if j.vd != noFixLine {
					continue
				}
				notes := "the value names its release line, not a version"
				if tp.managed {
					notes = "the provider stopped patching this runtime when it reached end of life"
				}
				s.add(pin{prod: tp.prod, source: tp.source, desc: desc, file: rel, line: i + 1, editFile: rel, editLine: i + 1, col: m[2], j: j, notes: notes})
				continue
			}
			col := m[2]
			notes := "the download is pinned with a checksum, which the new release's must replace"
			lo, hi := spans[i][0], spans[i][1]
			if hi-lo > maxSpan {
				hi = lo + maxSpan // a pathological chain of continuations: only its start is weighed
			}
			if tp.source == "node-download" || tp.source == "bun-download" {
				// A download pinned with a checksum needs the new release's
				// checksum too: not changed automatically.
				for k := lo; k <= hi; k++ {
					if sha256Re.MatchString(lines[k]) {
						col = -1
					}
				}
			}
			// The same release written twice in one command (a URL and its
			// file name, nvm install and nvm use) must all move together,
			// which a one-place edit cannot do.
			uses := 0
			for k := lo; k <= hi; k++ {
				uses += strings.Count(lines[k], v)
			}
			if uses > 1 {
				col, notes = -1, "the release is written more than once in the command (for example a URL and its file name); change every one"
			}
			j := judgeValue(tp.prod, v, false)
			if j.vd == notJudged {
				continue
			}
			p := pin{prod: tp.prod, source: tp.source, desc: desc, file: rel, line: i + 1, editFile: rel, editLine: i + 1, col: -1, j: j}
			if col >= 0 && j.current != "" {
				p.col = col + strings.Index(v, j.current)
			} else {
				p.notes = notes
			}
			s.add(p)
		}
	}
}

// maxSpan bounds the physical lines of one logical line that are weighed for
// a checksum or a repeated release.
const maxSpan = 64

// logicalSpans returns, for every physical line, the first and last physical
// line of the logical line (backslash continuations, as in a Dockerfile RUN
// or a shell command) it belongs to. One pass over the file.
func logicalSpans(lines []string) [][2]int {
	out := make([][2]int, len(lines))
	cont := func(k int) bool { return strings.HasSuffix(strings.TrimRight(lines[k], " \t\r"), "\\") }
	start := 0
	for i := range lines {
		if !cont(i) || i == len(lines)-1 {
			for k := start; k <= i; k++ {
				out[k] = [2]int{start, i}
			}
			start = i + 1
		}
	}
	return out
}
