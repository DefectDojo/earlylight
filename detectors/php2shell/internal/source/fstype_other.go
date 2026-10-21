//go:build !linux

package source

// pseudoFS reports pseudo-filesystems by type. Outside Linux the default
// excludes and the read-time size limit cover the cases that matter.
func pseudoFS(string) bool { return false }
