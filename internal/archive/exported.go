package archive

// IsExecutable reports whether b starts like an ELF, Mach-O or PE file.
// It lives apart from executable.go so that file stays a verbatim copy of
// emudhra-scan's.
func IsExecutable(b []byte) bool { return isExecutable(b) }

// IsArchive reports whether b starts like an archive or compressed file the
// walker unpacks: zip (and so wheels, jars and NuGet packages), gzip, zstd,
// xz, bzip2, tar, cpio, ar (and so .deb) or rpm.
func IsArchive(b []byte) bool {
	f, _ := sniff(b)
	return f != fNone && f != fPyInstaller && f != fUPX
}
