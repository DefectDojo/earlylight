package pins_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/brotli/internal/pins"
)

var sourcesRepo = map[string]string{
	"azure-pipelines.yml":      "steps:\n- task: NodeTool@0\n  inputs:\n    versionSpec: '20.x'\n- task: UseNode@1\n  inputs:\n    version: '24.22.0'\n- task: UseDotNet@2\n  inputs:\n    packageType: runtime\n    version: '8.0.32'\n- task: UseDotNet@2\n  inputs:\n    version: '8.0.x'\n",
	".circleci/config.yml":     "version: 2.1\njobs:\n  build:\n    docker:\n      - image: cimg/node:24.21.1\n    steps:\n      - node/install:\n          node-version: '20.11'\n",
	"global.json":              "{\n  \"sdk\": {\n    \"version\": \"9.0.319\",\n    \"rollForward\": \"latestPatch\"\n  }\n}\n",
	"src/App/App.csproj":       "<Project Sdk=\"Microsoft.NET.Sdk.Web\">\n  <PropertyGroup>\n    <TargetFrameworks>net7.0;net8.0;net48</TargetFrameworks>\n    <RuntimeFrameworkVersion>8.0.30</RuntimeFrameworkVersion>\n  </PropertyGroup>\n  <ItemGroup>\n    <PackageReference Include=\"Microsoft.NETCore.App.Runtime.linux-x64\" Version=\"8.0.31\" />\n  </ItemGroup>\n</Project>\n",
	"lib/Lib.csproj":           "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFrameworks>netstandard2.0;net6.0;net8.0</TargetFrameworks>\n  </PropertyGroup>\n</Project>\n",
	"old/Old.csproj":           "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFrameworks>net6.0;net7.0</TargetFrameworks>\n  </PropertyGroup>\n</Project>\n",
	"netlify.toml":             "[build.environment]\n  NODE_VERSION = \"18\"\n",
	"web/package.json":         "{\n  \"engines\": { \"node\": \"20.x\" }\n}\n",
	"api/package.json":         "{\n  \"engines\": { \"node\": \">=18\" }\n}\n",
	"svc/package.json":         "{\n  \"engines\": { \"node\": \"^20.11.0 || ^22\" }\n}\n",
	".github/workflows/ci.yml": "on: push\nenv:\n  NODE: '22.23.3'\njobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        sdk: ['8.0.426', '9.0.x']\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ env.NODE }}\n      - uses: actions/setup-dotnet@v4\n        with:\n          dotnet-version: ${{ matrix.sdk }}\n      - run: nvm install 20\n",
	"docker/Dockerfile":        "FROM debian:12\nRUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -\nARG NODE_VERSION=24.22.0\nRUN curl -fsSLO https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz \\\n && echo \"" + strings.Repeat("a", 64) + "  node.tar.xz\" | sha256sum -c\nRUN ./dotnet-install.sh --runtime aspnetcore --version 9.0.21\nRUN curl -fsSL https://bun.sh/install | bash -s \"bun-v1.4.3\"\n",
	"infra/template.yaml":      "Resources:\n  Fn:\n    Type: AWS::Serverless::Function\n    Properties:\n      Runtime: nodejs20.x\n  Fn2:\n    Properties:\n      Runtime: nodejs22.x\n  Fn3:\n    Properties:\n      Runtime: dotnet6\n",
	"infra/stack.ts":           "import * as lambda from 'aws-cdk-lib/aws-lambda';\nnew lambda.Function(this, 'F', { runtime: lambda.Runtime.NODEJS_18_X });\nnew lambda.Function(this, 'G', { runtime: lambda.Runtime.NODEJS_24_X });\n",
	"app.yaml":                 "runtime: nodejs20\n",
	"main.tf":                  "resource \"azurerm_linux_web_app\" \"a\" {\n  site_config {\n    application_stack {\n      node_version = \"18-lts\"\n    }\n  }\n}\n",
	"package-lock.json":        "{\"packages\":{\"node_modules/x\":{\"engines\":{\"node\":\"NODE_VERSION=20\"}}}}\n",
}

func TestSources(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, sourcesRepo)
	res, err := pins.Scan(context.Background(), dir, nil, pins.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range res.Findings {
		fx := "manual"
		if f.Fixable {
			fx = "fix"
		}
		got[f.File+":"+strconv.Itoa(f.Line)] = f.Props["source"] + " " + f.Props["current"] + " " + fx
	}
	want := map[string]string{
		"azure-pipelines.yml:4":       "azure-pipelines 20 fix",
		"azure-pipelines.yml:7":       "azure-pipelines 24.22.0 fix",
		"azure-pipelines.yml:11":      "azure-pipelines 8.0.32 fix",
		".circleci/config.yml:5":      "node-image 24.21.1 fix",
		".circleci/config.yml:8":      "circleci-node-orb 20.11 fix",
		"global.json:3":               "global.json 9.0.319 fix",
		"src/App/App.csproj:3":        "target-framework net7.0 manual",
		"old/Old.csproj:3":            "target-framework net7.0 manual", // and net6.0, on the same line
		"src/App/App.csproj:4":        "runtime-framework-version 8.0.30 fix",
		"src/App/App.csproj:7":        "runtime-pack 8.0.31 fix",
		"netlify.toml:2":              "netlify 18 fix",
		"web/package.json:2":          "engines-range 20.x fix",
		".github/workflows/ci.yml:3":  "setup-node 22.23.3 fix",
		".github/workflows/ci.yml:9":  "setup-dotnet 8.0.426 fix",
		".github/workflows/ci.yml:17": "node-version-manager 20 fix",
		"docker/Dockerfile:2":         "nodesource 18 fix",
		"docker/Dockerfile:3":         "node-version-var 24.22.0 fix",
		"docker/Dockerfile:4":         "node-download 24.21.0 manual",
		"docker/Dockerfile:6":         "dotnet-install 9.0.21 fix",
		"docker/Dockerfile:7":         "bun-download 1.4.3 fix",
		"infra/template.yaml:5":       "managed-runtime 20 fix",
		"infra/template.yaml:11":      "managed-runtime 6 manual",
		"infra/stack.ts:2":            "managed-runtime 18 fix",
		"app.yaml:1":                  "managed-runtime 20 fix",
		"main.tf:4":                   "managed-runtime 18 fix",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %q, want %q", k, got[k], w)
		}
	}
	for k, g := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: unexpected %q", k, g)
		}
	}
}

func TestPlanSources(t *testing.T) {
	cases := []struct {
		file string
		line int
		rule string
		want string
	}{
		{"azure-pipelines.yml", 11, pins.RuleDotnet, "    version: '8.0.33'"},
		{"global.json", 3, pins.RuleDotnet, `    "version": "9.0.320",`},
		{"src/App/App.csproj", 4, pins.RuleDotnet, "    <RuntimeFrameworkVersion>8.0.33</RuntimeFrameworkVersion>"},
		{".github/workflows/ci.yml", 9, pins.RuleDotnet, "        sdk: ['8.0.427', '9.0.x']"},
		{".github/workflows/ci.yml", 3, pins.RuleNode, "  NODE: '22.23.4'"},
		{"docker/Dockerfile", 6, pins.RuleDotnet, "RUN ./dotnet-install.sh --runtime aspnetcore --version 9.0.22"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		write(t, dir, sourcesRepo)
		ch, _, err := pins.Plan(context.Background(), dir, c.file, c.line, c.rule, nil)
		if err != nil {
			t.Errorf("%s:%d: %v", c.file, c.line, err)
			continue
		}
		if ch.Edits[0].New[0] != c.want {
			t.Errorf("%s:%d: got %q, want %q", c.file, c.line, ch.Edits[0].New[0], c.want)
		}
	}
}
