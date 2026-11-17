package jvm

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

func TestInspect(t *testing.T) {
	for _, c := range []struct {
		name, path string
		lib        testlib.Lib
		arch       Arch
		version    string
		vbmi       bool
	}{
		{"elf x86-64", "/opt/java/openjdk/lib/server/libjvm.so", testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true}, X8664, "21.0.13+9-LTS", true},
		{"elf aarch64", "/opt/java/openjdk/lib/server/libjvm.so", testlib.Lib{Machine: "aarch64", Version: "21.0.13+9-LTS"}, AArch64, "21.0.13+9-LTS", false},
		{"pe", "C:/Program Files/Java/jdk-21/bin/server/jvm.dll", testlib.Lib{Format: "pe", OS: "windows", Version: "21.0.13+9-LTS", VBMI: true}, X8664, "21.0.13+9-LTS", true},
		{"macho", "/Library/Java/JavaVirtualMachines/x/Contents/Home/lib/server/libjvm.dylib", testlib.Lib{Format: "macho", OS: "bsd", Version: "17.0.21+9"}, X8664, "17.0.21+9", false},
		{"java 8", "/usr/lib/jvm/java-8/jre/lib/amd64/server/libjvm.so", testlib.Lib{Version: "1.8.0_452-b09"}, X8664, "1.8.0_452-b09", false},
	} {
		l, ok := Inspect(c.path, testlib.Build(c.lib))
		if !ok {
			t.Fatalf("%s: not inspected", c.name)
		}
		if !l.Has(c.arch) || l.JREVersion != c.version || l.VBMIStubs != c.vbmi || !l.HotSpot() {
			t.Errorf("%s: got %+v", c.name, l)
		}
	}
	fat, ok := Inspect("/x/lib/server/libjvm.dylib", testlib.Build(testlib.Lib{Format: "fat", Version: "21.0.13+9"}))
	if !ok || !fat.Has(X8664) || !fat.Has(AArch64) {
		t.Errorf("universal binary: %+v", fat)
	}
	if _, ok := Inspect("/x/lib/server/libfoo.so", testlib.Build(testlib.Lib{Version: "21"})); ok {
		t.Error("a library with another name was inspected")
	}
	if _, ok := Inspect("/x/lib/server/libjvm.so", []byte("#!/bin/sh\necho")); ok {
		t.Error("a script named libjvm.so was inspected")
	}
	// A Java class file has the universal binary's magic.
	class := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65}
	if _, ok := Inspect("/x/lib/server/libjvm.dylib", class); ok {
		t.Error("a class file was taken for a universal binary")
	}
	j9, ok := Inspect("/opt/java/openjdk/lib/default/libj9vm29.so", testlib.Build(testlib.Lib{}))
	if !ok || !j9.OpenJ9 || j9.HotSpot() {
		t.Errorf("OpenJ9: %+v", j9)
	}
}

func TestInspectHostile(t *testing.T) {
	// A version line with parentheses or spaces in the version is refused,
	// and an over-long one does not match.
	b := testlib.Build(testlib.Lib{Extra: "\x00OpenJDK 64-Bit Server VM (21 (x)) for linux-amd64 JRE (21)\x00" + strings.Repeat("A", 1000) + "VM (" + strings.Repeat("9", 500) + ") for linux-amd64 JRE (1)"})
	l, ok := Inspect("/a/lib/server/libjvm.so", b)
	if !ok || l.JREVersion != "" {
		t.Errorf("hostile version line read: %+v", l)
	}
	// Stub names must be whole names.
	b = testlib.Build(testlib.Lib{Version: "17.0.5+8", Extra: "xlookup_lo_base64url\x00pack_vec_base64x\x00"})
	if l, _ := Inspect("/a/lib/server/libjvm.so", b); l.VBMIStubs {
		t.Error("partial stub names counted")
	}
	// Truncated headers.
	for _, h := range [][]byte{[]byte("\x7fELF"), []byte("MZ"), append([]byte("MZ"), bytes.Repeat([]byte{0xff}, 62)...), {0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 3}} {
		if _, ok := Inspect("/a/lib/server/libjvm.so", h); ok {
			t.Errorf("truncated header %x accepted", h)
		}
	}
}

func TestRoot(t *testing.T) {
	for in, want := range map[string]string{
		"/opt/java/openjdk/lib/server/libjvm.so":                                    "/opt/java/openjdk",
		"/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/server/libjvm.so":          "/usr/lib/jvm/java-8-openjdk-amd64/jre",
		"C:/Program Files/Java/jdk-21/bin/server/jvm.dll":                           "C:/Program Files/Java/jdk-21",
		"/Library/Java/JavaVirtualMachines/t/Contents/Home/lib/server/libjvm.dylib": "/Library/Java/JavaVirtualMachines/t/Contents/Home",
		"/opt/java/openjdk/lib/default/libj9vm29.so":                                "/opt/java/openjdk",
		"/opt/java/openjdk/lib/libjvm.so":                                           "/opt/java/openjdk",
	} {
		if got, ok := Root(in); !ok || got != want {
			t.Errorf("Root(%s) = %q %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := Root("/tmp/libjvm.so"); ok {
		t.Error("a stray libjvm.so got a runtime root")
	}
}

func TestRelease(t *testing.T) {
	r, ok := ParseRelease(testlib.Release("JAVA_VERSION", "21.0.13", "JAVA_RUNTIME_VERSION", "21.0.13+9-LTS", "OS_ARCH", "aarch64", "JVM_VARIANT", "Openj9", "MODULES", "java.base java.se"))
	if !ok || r.Version() != "21.0.13+9-LTS" || r.Arch() != AArch64 || !r.OpenJ9() || r.JLinked() {
		t.Errorf("release: %v", r)
	}
	jl, ok := ParseRelease([]byte("JAVA_VERSION=\"21.0.13\"\nMODULES=\"java.base java.logging\"\n"))
	if !ok || !jl.JLinked() || jl.Version() != "21.0.13" || jl.Arch() != "" {
		t.Errorf("jlink release: %v", jl)
	}
	if _, ok := ParseRelease(bytes.Repeat([]byte("JAVA_VERSION=\"21\"\n"), 10000)); ok {
		t.Error("a huge release file was read")
	}
	if _, ok := ParseRelease([]byte("IMPLEMENTOR=\"x\"\n")); ok {
		t.Error("a release file without JAVA_VERSION was read")
	}
	// The first value of a repeated key wins: a forged second line does not
	// replace it.
	r, _ = ParseRelease([]byte("JAVA_VERSION=\"21.0.13\"\nJAVA_VERSION=\"21.0.13.1\"\n"))
	if r.Version() != "21.0.13" {
		t.Errorf("repeated key: %v", r.Version())
	}
}

func TestOptions(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"-XX:-UseBASE64Intrinsics", true},
		{"-Xmx1g -XX:UseAVX=2", true},
		{"-XX:UseAVX=3", false},
		{"-XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics", false},
		{"-XX:+UseBASE64Intrinsics -XX:-UseBASE64Intrinsics", true},
		{"-XX:UseBASE64Intrinsics=false", true},
		{"'-XX:-UseBASE64Intrinsics'", true},
		{"-XX:-UseBASE64IntrinsicsX", false},
		{"-XX:UseAVX=two", false},
		{"", false},
	} {
		var o Options
		o.Apply(c.in, "test")
		if got, how := o.Mitigates(); got != c.want || got && how == "" {
			t.Errorf("%q: %v %q", c.in, got, how)
		}
	}
	// _JAVA_OPTIONS overrides the command line, which overrides
	// JAVA_TOOL_OPTIONS.
	env := map[string]string{"JAVA_TOOL_OPTIONS": "-XX:-UseBASE64Intrinsics", "_JAVA_OPTIONS": "-XX:+UseBASE64Intrinsics"}
	if ok, _ := FromEnv(env, nil, 21, nil).Mitigates(); ok {
		t.Error("_JAVA_OPTIONS did not override")
	}
	env = map[string]string{"JDK_JAVA_OPTIONS": "-XX:-UseBASE64Intrinsics"}
	if ok, _ := FromEnv(env, nil, 8, nil).Mitigates(); ok {
		t.Error("JDK_JAVA_OPTIONS counted for Java 8")
	}
	env = map[string]string{"JAVA_OPTS": "-XX:-UseBASE64Intrinsics"}
	if ok, _ := FromEnv(env, nil, 21, nil).Mitigates(); ok {
		t.Error("JAVA_OPTS counted without a script that passes it on")
	}
	if ok, _ := FromEnv(env, nil, 21, map[string]bool{"JAVA_OPTS": true}).Mitigates(); !ok {
		t.Error("JAVA_OPTS not counted when the script passes it on")
	}
}

func TestJavaOptions(t *testing.T) {
	for _, c := range []struct {
		cmd  []string
		want string
		ok   bool
	}{
		{[]string{"java", "-XX:-UseBASE64Intrinsics", "-jar", "app.jar", "-XX:+UseBASE64Intrinsics"}, "-XX:-UseBASE64Intrinsics", true},
		{[]string{"/opt/java/openjdk/bin/java", "-cp", "-XX:UseAVX=2", "Main"}, "", true},
		{[]string{"sh", "-c", "exec java -XX:UseAVX=2 -jar /app.jar"}, "-XX:UseAVX=2", true},
		{[]string{"catalina.sh", "run"}, "", false},
	} {
		got, ok := JavaOptions(c.cmd)
		if ok != c.ok || strings.Join(got, " ") != c.want {
			t.Errorf("%v: %v %v", c.cmd, got, ok)
		}
	}
}

func TestSettings(t *testing.T) {
	s, ok := ReadSetting("/usr/share/elasticsearch/config/jvm.options.d/j4s.options", []byte("# c\n17-:-XX:-UseBASE64Intrinsics\n-Xmx1g\n"))
	if !ok || s.Scope != "/usr/share/elasticsearch" {
		t.Fatalf("jvm.options: %+v", s)
	}
	if m, _ := s.Options(21).Mitigates(); !m {
		t.Error("jvm.options line for 17- not applied to 21")
	}
	s, _ = ReadSetting("/opt/es/config/jvm.options", []byte("8-11:-XX:-UseBASE64Intrinsics\n"))
	if m, _ := s.Options(21).Mitigates(); m {
		t.Error("jvm.options line for 8-11 applied to 21")
	}
	s, ok = ReadSetting("/opt/atlassian/jira/bin/setenv.sh", []byte("JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\n# -XX:+UseBASE64Intrinsics\n"))
	if !ok || s.Scope != "/opt/atlassian/jira" {
		t.Fatalf("setenv: %+v", s)
	}
	if m, _ := s.Options(17).Mitigates(); !m {
		t.Error("setenv.sh mitigation not read (or the comment counted)")
	}
	s, ok = ReadSetting("/etc/systemd/system/app.service", []byte("[Service]\nEnvironment=\"JAVA_TOOL_OPTIONS=-XX:UseAVX=2\" FOO=bar\nExecStart=/opt/app/jre/bin/java -jar /opt/app/app.jar\n"))
	if !ok || s.Unit != "app.service" || s.Exec != "/opt/app/jre/bin/java" {
		t.Fatalf("systemd: %+v", s)
	}
	if m, _ := s.Options(17).Mitigates(); !m {
		t.Error("systemd Environment not read")
	}
	if _, ok := ReadSetting("/home/u/app.service", []byte("x")); ok {
		t.Error("a unit outside systemd's directories was read")
	}
	if _, ok := ReadSetting("/opt/x/bin/setenv.sh", bytes.Repeat([]byte("a"), 2<<20)); ok {
		t.Error("a huge settings file was read")
	}
}

func FuzzInspect(f *testing.F) {
	f.Add("/a/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9", VBMI: true}))
	f.Add("/a/lib/server/libjvm.dylib", testlib.Build(testlib.Lib{Format: "fat"}))
	f.Add("/a/bin/server/jvm.dll", testlib.Build(testlib.Lib{Format: "pe", Version: "17.0.6+10"}))
	f.Fuzz(func(t *testing.T, p string, b []byte) {
		l, ok := Inspect(p, b)
		if ok && (l == nil || len(l.Archs) == 0) {
			t.Fatal("inspected without an architecture")
		}
	})
}

func FuzzSettings(f *testing.F) {
	f.Add("/opt/x/config/jvm.options", []byte("17-:-XX:-UseBASE64Intrinsics\n"))
	f.Add("/etc/systemd/system/a.service", []byte("Environment=\"JAVA_TOOL_OPTIONS=-XX:UseAVX=2\"\nExecStart=sh -c 'java -XX:UseAVX=1'\n"))
	f.Add("/opt/x/bin/setenv.sh", []byte("CATALINA_OPTS=\"$CATALINA_OPTS -XX:-UseBASE64Intrinsics\"\n"))
	f.Fuzz(func(t *testing.T, p string, b []byte) {
		s, ok := ReadSetting(p, b)
		if !ok {
			return
		}
		for _, feat := range []int{0, 8, 17, 21} {
			s.Options(feat).Mitigates()
		}
		var o Options
		o.Apply(string(b), "fuzz")
		JavaOptions(Words(string(b)))
	})
}

func TestInspectLargePrintable(t *testing.T) {
	// Printable text everywhere used to make the version-line search scan
	// from every position.
	b := append(testlib.Build(testlib.Lib{}), bytes.Repeat([]byte("VM (1) for a-b JRE x "), (16<<20)/21)...)
	start := time.Now()
	if l, ok := Inspect("/a/lib/server/libjvm.so", b); !ok || l.JREVersion != "" {
		t.Fatalf("%+v", l)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("16 MiB of printable text took %s", d)
	}
}
