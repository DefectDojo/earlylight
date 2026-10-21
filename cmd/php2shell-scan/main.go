// Command php2shell-scan finds PHP runtimes vulnerable to CVE-2026-109618 and
// CVE-2026-109619 ("PHP2Shell", fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12)
// in filesystems, container images and the image references in source code.
// It is the engine with only the php2shell detector, under the name people
// search for, with php2shell-scan's flags and exit status rules.
package main

import (
	"os"

	"github.com/DefectDojo/earlylight/detectors/php2shell"
	"github.com/DefectDojo/earlylight/internal/cli"
)

var version = "dev"

func main() {
	cli.SetMemoryLimit()
	os.Exit(cli.Run(cli.Config{
		Tool:        "php2shell-scan",
		Version:     version,
		Detector:    php2shell.ID,
		Summary:     "php2shell-scan finds PHP vulnerable to CVE-2026-109618 and CVE-2026-109619.",
		AsRootDir:   true,
		ErrorsFirst: true,
	}, os.Args[1:], os.Stdout, os.Stderr))
}
