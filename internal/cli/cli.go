// Package cli is the command line shared by the engine binary and the thin
// per-detector binaries (emudhra-scan), which pin one detector and keep their
// old command names.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/DefectDojo/earlylight/internal/engine"
	"github.com/DefectDojo/earlylight/internal/image"
	"github.com/DefectDojo/earlylight/internal/report"
)

// Config describes one binary.
type Config struct {
	Tool    string
	Version string
	// Detector pins a single detector (thin binaries). Empty: --detector picks.
	Detector string
	// Summary is the first line of the usage text.
	Summary string
}

// SetMemoryLimit keeps the heap near what is actually live: archive members
// and large files are held one at a time, and without a limit the collector
// lets the heap grow to about twice that. GOMEMLIMIT in the environment wins.
func SetMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(1 << 30)
	}
}

func (c Config) usage() string {
	scan := c.Tool + " scan"
	if c.Detector != "" {
		scan = c.Tool
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\nUsage:\n", c.Summary)
	fmt.Fprintf(&b, "  %s fs [flags] PATH...      scan directories or files (use / for a whole system)\n", scan)
	fmt.Fprintf(&b, "  %s image [flags] REF...    scan container images: a registry ref, docker-archive:FILE\n", scan)
	fmt.Fprintf(&b, "  %*s                         (from docker save), or rootfs:FILE / rootfs:- (from docker export)\n", len(scan), "")
	fmt.Fprintf(&b, "  %s host [flags] HOST...    check live servers (host, host:port or https://host:port/...)\n", scan)
	if c.Detector == "" {
		fmt.Fprintf(&b, "  %s detectors                  list the detectors\n", c.Tool)
	}
	fmt.Fprintf(&b, "  %s version\n", c.Tool)
	b.WriteString(`
Flags:
`)
	if c.Detector == "" {
		b.WriteString("  --detector ID[,ID]         run only these detectors (repeatable; default all)\n")
	}
	b.WriteString(`  --format text|json|sarif   output format (default text)
  --output FILE              write the report to FILE instead of stdout
  --max-file-size BYTES      skip and record files larger than this (default 1 GiB)
  --platform OS/ARCH|all     image platform (default linux/amd64); all scans every platform
  --show-cleared             also list findings proven fixed or provably not used
  --show-skipped             list every file that could not be scanned
  --fail-on-skip             exit 3 when any file could not be scanned
  --exit-zero                exit 0 even with findings (errors still exit 2), for pipelines
                             that read the report instead of the exit status
  --as-root                  fs: treat the directory as a system root (a host mounted at /host,
                             an extracted image); "/" always is
  --timeout DURATION         connect timeout for host checks (default 10s)

Exit status: 0 nothing vulnerable or unknown, 1 something vulnerable, 2 error,
3 nothing vulnerable but something unknown, or (--fail-on-skip) not scanned.
`)
	return b.String()
}

type list []string

func (l *list) String() string { return strings.Join(*l, ",") }
func (l *list) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// Run runs the command line and returns the exit status.
func Run(c Config, args []string, stdout, stderr io.Writer) int {
	usage := c.usage()
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-version":
		fmt.Fprintln(stdout, c.Tool, c.Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "detectors":
		if c.Detector == "" {
			for _, d := range engine.Detectors() {
				m := d.Manifest()
				fmt.Fprintf(stdout, "%-12s %s\n", m.ID, m.Title)
			}
			return 0
		}
	}
	if c.Detector == "" {
		if args[0] != "scan" || len(args) < 2 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		args = args[1:]
	}
	mode := args[0]
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	var ids list
	if c.Detector == "" {
		fs.Var(&ids, "detector", "")
	}
	format := fs.String("format", "text", "")
	output := fs.String("output", "", "")
	maxSize := fs.Int64("max-file-size", 1<<30, "")
	platform := fs.String("platform", "linux/amd64", "")
	showCleared := fs.Bool("show-cleared", false, "")
	showInactive := fs.Bool("show-inactive", false, "") // emudhra-scan's name for --show-cleared
	showSkipped := fs.Bool("show-skipped", false, "")
	failOnSkip := fs.Bool("fail-on-skip", false, "")
	exitZero := fs.Bool("exit-zero", false, "")
	asRoot := fs.Bool("as-root", false, "")
	timeout := fs.Duration("timeout", 10*time.Second, "")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	targets := fs.Args()
	if len(targets) == 0 || (mode != "fs" && mode != "image" && mode != "host") {
		fs.Usage()
		return 2
	}
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "%s: unknown --format %q\n", c.Tool, *format)
		return 2
	}
	if c.Detector != "" {
		ids = list{c.Detector}
	}

	dets, err := engine.Select(ids)
	if err != nil {
		fmt.Fprintf(stderr, "%s: refusing to run: %v\n", c.Tool, err)
		return 2
	}
	kind := map[string]engine.TargetKind{"fs": engine.Filesystem, "image": engine.Image, "host": engine.Host}[mode]
	var running []engine.Detector
	for _, d := range dets {
		if d.Manifest().Supports(kind) {
			running = append(running, d)
		}
	}
	if len(running) == 0 {
		fmt.Fprintf(stderr, "%s: none of the selected detectors scan %s targets\n", c.Tool, kind)
		return 2
	}

	rep := report.New(c.Tool, c.Version, running)
	opts := engine.Options{MaxFileSize: *maxSize, AsRoot: *asRoot, Timeout: *timeout, Platform: *platform}
	failed := false
	add := func(t *engine.Target) {
		if t.Error != "" {
			failed = true
		}
		rep.Targets = append(rep.Targets, t)
	}
	for _, name := range targets {
		switch mode {
		case "fs":
			add(engine.ScanFS(running, name, opts))
		case "host":
			add(engine.ScanHost(running, name, opts))
		case "image":
			local := strings.HasPrefix(name, "rootfs:") || strings.HasPrefix(name, "docker-archive:")
			if *platform != "all" || local {
				o := opts
				if o.Platform == "all" {
					o.Platform = ""
				}
				add(engine.ScanImage(running, name, o))
				continue
			}
			ps, err := image.Platforms(name)
			if err != nil {
				add(&engine.Target{Name: name, Type: engine.Image, Error: err.Error()})
				continue
			}
			if len(ps) == 0 {
				ps = []string{""}
			}
			for _, p := range ps {
				o := opts
				o.Platform = p
				add(engine.ScanImage(running, name, o))
			}
		}
	}

	w := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", c.Tool, err)
			return 2
		}
		defer f.Close()
		w = f
	}
	switch *format {
	case "json":
		err = report.JSON(w, rep)
	case "sarif":
		err = report.SARIF(w, rep)
	default:
		report.Text(w, rep, report.Options{ShowCleared: *showCleared || *showInactive, ShowSkipped: *showSkipped})
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", c.Tool, err)
		return 2
	}

	vuln, unk, gaps := 0, 0, 0
	for _, t := range rep.Targets {
		vuln += t.Count(engine.Vulnerable)
		unk += t.Count(engine.Unknown)
		gaps += t.Gaps()
	}
	switch {
	case vuln > 0 && !*exitZero:
		return 1
	case failed:
		return 2 // errors are reported even with --exit-zero
	case unk > 0 && !*exitZero:
		return 3
	case *failOnSkip && gaps > 0:
		return 3
	}
	return 0
}
