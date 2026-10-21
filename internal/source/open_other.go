//go:build !unix

package source

// openNoFollow is not available here; readOne still checks that the opened
// file is the regular file the walk saw.
const openNoFollow = 0
