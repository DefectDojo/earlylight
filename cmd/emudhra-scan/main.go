// Command emudhra-scan finds trust in the eMudhra intermediate CA keys
// compromised in October 2026 (Mozilla bug 2083449) in filesystems, container
// images and TLS servers. It is the engine with only the emudhra detector, under
// the name people search for.
package main

import (
	"os"

	"github.com/DefectDojo/earlylight/detectors/emudhra"
	"github.com/DefectDojo/earlylight/internal/cli"
)

var version = "dev"

func main() {
	cli.SetMemoryLimit()
	os.Exit(cli.Run(cli.Config{
		Tool:     "emudhra-scan",
		Version:  version,
		Detector: emudhra.ID,
		Summary:  "emudhra-scan finds trust in the eMudhra CA keys compromised in October 2026.",
	}, os.Args[1:], os.Stdout, os.Stderr))
}
