// Command earlylight (Early Light) runs DefectDojo's emerging-vulnerability detectors against
// filesystems, container images and live hosts.
package main

import (
	"os"

	_ "github.com/DefectDojo/earlylight/detectors/all"
	"github.com/DefectDojo/earlylight/internal/cli"
)

var version = "dev"

func main() {
	cli.SetMemoryLimit()
	os.Exit(cli.Run(cli.Config{
		Tool:    "earlylight",
		Version: version,
		Summary: "earlylight (Early Light) finds emerging vulnerabilities, one detector per vulnerability.",
	}, os.Args[1:], os.Stdout, os.Stderr))
}
