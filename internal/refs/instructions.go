package refs

import (
	"encoding/json"
	"strings"
)

// Instruction is one Dockerfile instruction as BuildKit reads it: the
// "# escape=" directive honoured, continuation lines joined, comment and
// blank lines inside a continuation dropped, and the bodies of the
// heredocs it opens attached. Detectors that read more than FROM (the
// packages a RUN installs, the images COPY --from names) start here, so
// that they read a Dockerfile the way the builder does.
type Instruction struct {
	// Cmd is the instruction word in lower case; for ONBUILD, the
	// instruction it wraps.
	Cmd string
	// Line is the 1-based line the instruction starts on.
	Line int
	// Flags are the leading --flags of the arguments, quotes removed
	// (--from=builder, --mount=type=bind,from=img, --platform=...).
	Flags []string
	// Args is what follows the flags.
	Args string
	// JSON holds the words when the arguments are in JSON (exec) form.
	JSON []string
	// Heredocs are the bodies of the heredocs the instruction opens
	// (RUN <<EOF).
	Heredocs []string
}

// Instructions parses a Dockerfile. The error is the parser's: a file the
// builder would refuse.
func Instructions(b []byte) ([]Instruction, error) {
	p, err := parseDockerfile("", b)
	if err != nil {
		return nil, err
	}
	out := make([]Instruction, 0, len(p.instrs))
	for _, in := range p.instrs {
		cmd, rest := in.cmd, in.rest.String()
		if cmd == "onbuild" {
			rest = strings.TrimSpace(rest)
			word, after, _ := strings.Cut(rest, " ")
			if i := strings.IndexAny(rest, " \t"); i >= 0 {
				word, after = rest[:i], rest[i+1:]
			}
			cmd, rest = strings.ToLower(word), strings.TrimSpace(after)
		}
		x := Instruction{Cmd: cmd, Line: in.line, Args: rest, Heredocs: in.heredocs}
		if args, flags, err := extractBuilderFlags(rest); err == nil {
			x.Args, x.Flags = args, flags
		}
		if t := strings.TrimSpace(x.Args); strings.HasPrefix(t, "[") {
			var words []string
			if json.Unmarshal([]byte(t), &words) == nil {
				x.JSON = words
			}
		}
		out = append(out, x)
	}
	return out, nil
}
