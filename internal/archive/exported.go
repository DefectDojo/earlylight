package archive

// IsExecutable reports whether b starts like an ELF, Mach-O or PE file.
// It lives apart from executable.go so that file stays a verbatim copy of
// emudhra-scan's.
func IsExecutable(b []byte) bool { return isExecutable(b) }
