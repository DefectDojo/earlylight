package java4shell

import "testing"

func FuzzReadCrash(f *testing.F) {
	f.Add([]byte("# JRE version: OpenJDK Runtime Environment (21.0.13+9) (build 21.0.13+9-LTS)\n# Problematic frame:\n# v  ~StubRoutines::decodeBlock\nCPU: total 8, avx512f, avx512_vbmi\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c := readCrash("/tmp/hs_err_pid1.log", b)
		if len(c.Frame) > 300 || len(c.Version) > 61 {
			t.Fatalf("unbounded field: %d %d", len(c.Frame), len(c.Version))
		}
	})
}
