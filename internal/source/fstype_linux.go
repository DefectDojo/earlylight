//go:build linux

package source

import "syscall"

// Filesystem magic numbers from linux/magic.h for filesystems that hold no files
// worth scanning and can be endless or huge (/proc/kcore).
var pseudoMagic = map[int64]bool{
	0x9fa0:     true, // proc
	0x62656572: true, // sysfs
	0x1cd1:     true, // devpts
	0x27e0eb:   true, // cgroup
	0x63677270: true, // cgroup2
	0x64626720: true, // debugfs
	0x73636673: true, // securityfs
	0x74726163: true, // tracefs
	0xcafe4a11: true, // bpf
	0x6e736673: true, // nsfs
	0x42494e4d: true, // binfmt_misc
	0x19800202: true, // mqueue
	0x958458f6: true, // hugetlbfs
}

func pseudoFS(dir string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false
	}
	return pseudoMagic[int64(st.Type)]
}
