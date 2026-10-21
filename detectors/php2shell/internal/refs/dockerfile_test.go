package refs

import (
	"strings"
	"testing"
)

func scanContent(t *testing.T, file, content string, extra ...string) ([]Ref, []Skip) {
	t.Helper()
	ov := map[string][]byte{file: []byte(content)}
	for i := 0; i+1 < len(extra); i += 2 {
		ov[extra[i]] = []byte(extra[i+1])
	}
	refs, skips, err := ScanFiles(t.TempDir(), []string{file}, Options{Overlay: ov})
	if err != nil {
		t.Fatal(err)
	}
	return refs, skips
}

type wantRef struct {
	line     int
	image    string
	stage    string
	platform string
	editLine int
	editText string
}

func TestDockerfile(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []wantRef
		skips   []string // substrings of skip reasons, in order
		skipsAt []int
	}{
		{name: "simple", in: "FROM php:8.3-fpm\n", want: []wantRef{{line: 1, image: "php:8.3-fpm", editLine: 1, editText: "php:8.3-fpm"}}},
		{name: "case and stage", in: "from php:8.3 as Base\nfrom base\nFROM BASE AS final\n", want: []wantRef{{line: 1, image: "php:8.3", stage: "base", editLine: 1}}},
		{name: "platform literal", in: "FROM --platform=linux/arm64 php:8.3\n", want: []wantRef{{line: 1, image: "php:8.3", platform: "linux/arm64", editLine: 1}}},
		{name: "platform variable", in: "FROM --platform=$BUILDPLATFORM php:8.3 AS build\n", want: []wantRef{{line: 1, image: "php:8.3", stage: "build", editLine: 1}}},
		{name: "scratch", in: "FROM scratch\nFROM Scratch\n"},
		{
			name: "arg braces",
			in:   "ARG PHP_VERSION=8.3.20\nFROM php:${PHP_VERSION}-fpm\n",
			want: []wantRef{{line: 2, image: "php:8.3.20-fpm", editLine: 1, editText: "8.3.20"}},
		},
		{
			name: "arg dollar",
			in:   "ARG PHP_VERSION=8.3.20\nFROM php:$PHP_VERSION-fpm-alpine\n",
			want: []wantRef{{line: 2, image: "php:8.3.20-fpm-alpine", editLine: 1, editText: "8.3.20"}},
		},
		{
			name: "default operator with ARG without default",
			in:   "ARG TAG\nFROM php:${TAG:-8.2-cli}\n",
			want: []wantRef{{line: 2, image: "php:8.2-cli", editLine: 2, editText: "8.2-cli"}},
		},
		{
			name: "default operator ignored when set",
			in:   "ARG TAG=8.4\nFROM php:${TAG:-8.2}\n",
			want: []wantRef{{line: 2, image: "php:8.4", editLine: 1, editText: "8.4"}},
		},
		{
			name: "dash without colon and empty value",
			in:   "ARG TAG=\nFROM php:8.3${TAG-x}\nFROM php:8.3${TAG:-.1}\n",
			want: []wantRef{{line: 2, image: "php:8.3", editLine: 2}, {line: 3, image: "php:8.3.1", editLine: 3}},
		},
		{
			name: "plus forms",
			in:   "ARG ALPINE=1\nARG NONE\nFROM php:8.3-fpm${ALPINE:+-alpine}${NONE:+-x}${NONE+-y}\n",
			want: []wantRef{{line: 3, image: "php:8.3-fpm-alpine", editLine: 3}},
		},
		{
			name:    "arg without default",
			in:      "ARG TAG\nFROM php:$TAG\n",
			skips:   []string{"ARG TAG (line 1) has no default"},
			skipsAt: []int{2},
		},
		{
			name:    "undeclared",
			in:      "FROM php:${TAG}\n",
			skips:   []string{"not declared by an ARG before the first FROM"},
			skipsAt: []int{1},
		},
		{
			name:    "required unset",
			in:      "ARG TAG\nFROM php:${TAG:?required}\n",
			skips:   []string{"not allowed to be empty"},
			skipsAt: []int{2},
		},
		{
			name:    "stage-scoped ARG is not visible to FROM",
			in:      "FROM php:8.3 AS a\nARG V=8.2\nFROM php:${V}\n",
			want:    []wantRef{{line: 1, image: "php:8.3", stage: "a", editLine: 1}},
			skips:   []string{"not declared"},
			skipsAt: []int{3},
		},
		{
			name: "nested ARG defaults",
			in:   "ARG MAJOR=8.3\nARG TAG=${MAJOR}.20-fpm\nFROM php:${TAG}\n",
			want: []wantRef{{line: 3, image: "php:8.3.20-fpm", editLine: 1, editText: "8.3"}},
		},
		{
			name:    "platform arg in image",
			in:      "FROM php:8.3-$TARGETARCH\n",
			skips:   []string{"depends on the platform"},
			skipsAt: []int{1},
		},
		{
			name: "quoted ARG and multiple ARGs on a line",
			in:   "ARG A=1 IMG=\"php:8.1-apache\"\nFROM $IMG\n",
			want: []wantRef{{line: 2, image: "php:8.1-apache", editLine: 1, editText: "php:8.1-apache"}},
		},
		{
			name: "heredoc body is not parsed",
			in:   "FROM php:8.3 AS a\nRUN <<EOF\nFROM php:7.4\nARG X=1\nEOF\nFROM php:8.2\n",
			want: []wantRef{{line: 1, image: "php:8.3", stage: "a", editLine: 1}, {line: 6, image: "php:8.2", editLine: 6}},
		},
		{
			name: "copy heredoc with chomp and quoted name",
			in:   "FROM php:8.3\nCOPY <<-\"DOCKERFILE\" /app/Dockerfile\n\tFROM php:5.6\n\tDOCKERFILE\nFROM php:8.4\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}, {line: 5, image: "php:8.4", editLine: 5}},
		},
		{
			name: "two heredocs on one line",
			in:   "FROM php:8.3\nRUN <<A cat - <<B\nFROM php:7.0\nA\nFROM php:7.1\nB\nFROM php:8.4\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}, {line: 7, image: "php:8.4", editLine: 7}},
		},
		{
			name: "onbuild heredoc",
			in:   "FROM php:8.3\nONBUILD RUN <<EOF\nFROM php:7.0\nEOF\nFROM php:8.4\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}, {line: 5, image: "php:8.4", editLine: 5}},
		},
		{
			name: "JSON form RUN does not open a heredoc",
			in:   "FROM php:8.3\nRUN [\"sh\", \"-c\", \"cat <<EOF\"]\nFROM php:8.2\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}, {line: 3, image: "php:8.2", editLine: 3}},
		},
		{
			name: "quoted << is not a heredoc",
			in:   "FROM php:8.3\nRUN echo \"<<EOF\"\nFROM php:8.2\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}, {line: 3, image: "php:8.2", editLine: 3}},
		},
		{
			name: "line continuation with comments and blank lines",
			in:   "FROM \\\n# comment\n\n   php:8.3-cli \\\n  AS x\n",
			want: []wantRef{{line: 1, image: "php:8.3-cli", stage: "x", editLine: 4, editText: "php:8.3-cli"}},
		},
		{
			name: "continuation with trailing whitespace after backslash",
			in:   "FROM \\ \t\nphp:8.3\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 2}},
		},
		{
			name: "backtick escape directive",
			in:   "# escape=`\nFROM `\n  php:8.3-fpm\nRUN echo C:\\path\\\nFROM php:8.2\n",
			want: []wantRef{{line: 2, image: "php:8.3-fpm", editLine: 3}, {line: 5, image: "php:8.2", editLine: 5}},
		},
		{
			name: "directive after an instruction is a comment",
			in:   "FROM php:8.3\n# escape=`\nFROM `\nphp:8.2\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}},
			// "FROM `" has the literal backtick as image; it is invalid.
			skips:   []string{"not a valid image reference"},
			skipsAt: []int{3},
		},
		{
			name: "syntax directive is not a runtime image",
			in:   "# syntax=docker/dockerfile:1.7\n# check=skip=all\nFROM php:8.3\n",
			want: []wantRef{{line: 3, image: "php:8.3", editLine: 3}},
		},
		{
			name: "CRLF",
			in:   "ARG V=8.3.20\r\nFROM php:${V}-fpm \\\r\n  AS app\r\n",
			want: []wantRef{{line: 2, image: "php:8.3.20-fpm", stage: "app", editLine: 1, editText: "8.3.20"}},
		},
		{
			name: "BOM",
			in:   "\ufeffFROM php:8.3\n",
			want: []wantRef{{line: 1, image: "php:8.3", editLine: 1}},
		},
		{
			name:    "bad FROM arity",
			in:      "FROM php:8.3 AS\nFROM php:8.3 base\n",
			skips:   []string{"one or three arguments", "one or three arguments"},
			skipsAt: []int{1, 2},
		},
		{
			name:    "invalid escape directive",
			in:      "# escape=x\nFROM php:8.3\n",
			skips:   []string{"invalid escape token"},
			skipsAt: []int{0},
		},
		{
			name:    "unterminated heredoc",
			in:      "FROM php:8.3\nRUN <<EOF\necho\n",
			skips:   []string{"unterminated heredoc"},
			skipsAt: []int{0},
		},
		{
			name: "digest",
			in:   "FROM php:8.3-fpm@sha256:0000000000000000000000000000000000000000000000000000000000000000\n",
			want: []wantRef{{line: 1, image: "php:8.3-fpm@sha256:0000000000000000000000000000000000000000000000000000000000000000", editLine: 1}},
		},
		{
			name:    "unknown flag",
			in:      "FROM --pull=always php:8.3\n",
			skips:   []string{"unknown FROM flag"},
			skipsAt: []int{1},
		},
		{
			name:    "pattern substitution unsupported",
			in:      "ARG V=8.3.20\nFROM php:${V%.*}\n",
			skips:   []string{"pattern substitution"},
			skipsAt: []int{2},
		},
		{
			name: "quotes in FROM",
			in:   "ARG V=8.3\nFROM \"php:${V}\"\n",
			want: []wantRef{{line: 2, image: "php:8.3", editLine: 1, editText: "8.3"}},
		},
		{
			name: "escaped dollar is literal",
			in:   "FROM php:8.3\\$X\n",
			// "php:8.3$X" is not a valid reference.
			skips:   []string{"not a valid image reference"},
			skipsAt: []int{1},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			refs, skips := scanContent(t, "Dockerfile", tc.in)
			if len(refs) != len(tc.want) {
				t.Fatalf("got %d refs %+v, want %d; skips %+v", len(refs), refs, len(tc.want), skips)
			}
			for i, w := range tc.want {
				r := refs[i]
				if r.Line != w.line || r.Image != w.image || r.Stage != w.stage || r.Platform != w.platform {
					t.Errorf("ref %d = line %d image %q stage %q platform %q, want %+v", i, r.Line, r.Image, r.Stage, r.Platform, w)
				}
				if r.EditLine != w.editLine {
					t.Errorf("ref %d edit line %d, want %d (parts %+v)", i, r.EditLine, w.editLine, r.Parts)
				}
				if w.editText != "" && r.EditText != w.editText {
					t.Errorf("ref %d edit text %q, want %q", i, r.EditText, w.editText)
				}
				checkParts(t, tc.in, r)
			}
			if len(skips) != len(tc.skips) {
				t.Fatalf("got skips %+v, want %v", skips, tc.skips)
			}
			for i, s := range tc.skips {
				if !strings.Contains(skips[i].Reason, s) || skips[i].Line != tc.skipsAt[i] {
					t.Errorf("skip %d = %+v, want %q at line %d", i, skips[i], s, tc.skipsAt[i])
				}
			}
		})
	}
}

// checkParts verifies that every Part with a Column appears verbatim there.
func checkParts(t *testing.T, content string, r Ref) {
	t.Helper()
	lines := rawLines([]byte(content))
	var b strings.Builder
	for _, p := range r.Parts {
		b.WriteString(p.Text)
		if p.Column == 0 {
			continue
		}
		l := lines[p.Line-1]
		if p.Column-1+len(p.Text) > len(l) || l[p.Column-1:p.Column-1+len(p.Text)] != p.Text {
			t.Errorf("part %+v not verbatim in line %q", p, l)
		}
	}
	if b.String() != r.Image {
		t.Errorf("parts %+v do not make up %q", r.Parts, r.Image)
	}
}

func TestDockerfileArgParts(t *testing.T) {
	refs, _ := scanContent(t, "Dockerfile", "ARG PHP_VERSION=8.3.20\nFROM php:${PHP_VERSION}-fpm\n")
	if len(refs) != 1 {
		t.Fatal(refs)
	}
	r := refs[0]
	want := []Part{
		{Text: "php:", File: "Dockerfile", Line: 2, Column: 6},
		{Text: "8.3.20", File: "Dockerfile", Line: 1, Column: 17, Var: "PHP_VERSION"},
		{Text: "-fpm", File: "Dockerfile", Line: 2, Column: 24},
	}
	if len(r.Parts) != len(want) {
		t.Fatalf("parts %+v", r.Parts)
	}
	for i := range want {
		if r.Parts[i] != want[i] {
			t.Errorf("part %d = %+v, want %+v", i, r.Parts[i], want[i])
		}
	}
	if len(r.Vars) != 1 || r.Vars[0].Name != "PHP_VERSION" || r.Vars[0].Line != 1 {
		t.Errorf("vars %+v", r.Vars)
	}
	if r.Text != "php:${PHP_VERSION}-fpm" || r.Column != 6 {
		t.Errorf("text %q column %d", r.Text, r.Column)
	}
}
