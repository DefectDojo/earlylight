//go:build unix

package source

import "syscall"

// openNoFollow refuses symlinks and does not block on FIFOs or devices.
const openNoFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
