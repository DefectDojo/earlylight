//go:build unix

package nginxh2

import "syscall"

// syscallNoFollow refuses a symbolic link (the path was resolved first) and
// does not block on a FIFO or device.
const syscallNoFollow = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
