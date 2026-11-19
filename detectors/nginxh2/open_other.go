//go:build !unix

package nginxh2

// syscallNoFollow is not available here; disk still checks that the file
// it opened is regular.
const syscallNoFollow = 0
