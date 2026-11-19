package pkgdb

import "testing"

// FuzzDatabases: dpkg's status and .list files and apk's database parse
// without a panic.
func FuzzDatabases(f *testing.F) {
	f.Add([]byte("Package: nginx\nStatus: install ok installed\nVersion: 1.22.1-9\nSource: nginx (1.22.1-9)\n\n"), []byte("P:nginx\nV:1.30.6-r0\nF:usr/sbin\nR:nginx\n\n"))
	f.Add([]byte(":\n \n"), []byte("R:x\nF:\n"))
	f.Fuzz(func(t *testing.T, dpkg, apk []byte) {
		DpkgStatus(dpkg)
		ListHas(dpkg, "/usr/sbin/nginx")
		DpkgListName(string(dpkg))
		APKOwners(apk)
	})
}
