package jvm

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
)

// Review finding 1: musl builds name their platform linux-amd64-musl.
func TestInspectMusl(t *testing.T) {
	l, ok := Inspect("/opt/java/openjdk/lib/server/libjvm.so", testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true, Musl: true, Extra: "\x00j9vm\x00"}))
	if !ok || !l.HotSpot() || l.JREVersion != "21.0.13+9-LTS" || l.Platform != "linux-amd64-musl" {
		t.Fatalf("musl: %+v", l)
	}
	if l.OpenJ9 {
		t.Error("the bytes j9vm made a HotSpot library OpenJ9")
	}
	// Without a readable version line, four bytes do not make it OpenJ9
	// when the HotSpot decoder stubs are there.
	l, _ = Inspect("/opt/java/openjdk/lib/server/libjvm.so", testlib.Build(testlib.Lib{VBMI: true, Extra: "\x00j9vm\x00"}))
	if l.OpenJ9 {
		t.Error("an unreadable HotSpot library with j9vm bytes taken for OpenJ9")
	}
}

// Review finding 5: only options a launcher variable ends up with count.
func TestSettingsOnlyWhatLaunches(t *testing.T) {
	for _, text := range []string{
		"if [ \"$X\" = 1 ]; then JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"; fi\n",
		"if [ \"$X\" = 1 ]; then\n  JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\nfi\n",
		"OLD_OPTS=\"-XX:-UseBASE64Intrinsics\"\n",
		"JAVA_OPTS=\"-XX:-UseBASE64Intrinsics\"\nJAVA_OPTS=\"-Xmx2g\"\n",
		"echo \"to mitigate Java4Shell add -XX:-UseBASE64Intrinsics\"\n",
	} {
		s, ok := ReadSetting("/opt/atlassian/jira/bin/setenv.sh", []byte(text))
		if !ok {
			t.Fatal("not read")
		}
		if m, _ := s.Options(21).Mitigates(); m {
			t.Errorf("counted: %q", text)
		}
	}
	for _, text := range []string{
		"JAVA_OPTS=\"-Xmx2g\"\nJAVA_OPTS=\"$JAVA_OPTS -XX:-UseBASE64Intrinsics\"\n",
		"export CATALINA_OPTS=\"${CATALINA_OPTS} -XX:-UseBASE64Intrinsics\"\n",
		"JVM_SUPPORT_RECOMMENDED_ARGS='-XX:-UseBASE64Intrinsics'\n",
	} {
		s, _ := ReadSetting("/opt/atlassian/jira/bin/setenv.sh", []byte(text))
		if m, _ := s.Options(21).Mitigates(); !m {
			t.Errorf("not counted: %q", text)
		}
	}
	// A Windows batch file applies to Windows runtimes only.
	s, _ := ReadSetting("/opt/tomcat/bin/setenv.bat", []byte(":: set CATALINA_OPTS=-XX:-UseBASE64Intrinsics\nrem set JAVA_OPTS=-XX:-UseBASE64Intrinsics\n"))
	if m, _ := s.Options(21).Mitigates(); m {
		t.Error("batch comments counted")
	}
	s, _ = ReadSetting("/opt/tomcat/bin/setenv.bat", []byte("set \"CATALINA_OPTS=%CATALINA_OPTS% -XX:-UseBASE64Intrinsics\"\n"))
	if m, _ := s.Options(21).Mitigates(); !m || !s.WindowsOnly {
		t.Errorf("batch set: %v windows-only %v", m, s.WindowsOnly)
	}
	// Cassandra names the Java release in the file name.
	s, _ = ReadSetting("/opt/cassandra/conf/jvm11-server.options", []byte("-XX:UseAVX=2\n"))
	if m, _ := s.Options(21).Mitigates(); m {
		t.Error("jvm11-server.options applied to Java 21")
	}
	if m, _ := s.Options(11).Mitigates(); !m {
		t.Error("jvm11-server.options not applied to Java 11")
	}
}

func FuzzParseRelease(f *testing.F) {
	f.Add([]byte("JAVA_VERSION=\"21.0.13\"\nJAVA_RUNTIME_VERSION=\"21.0.13+9-LTS\"\nOS_ARCH=\"x86_64\"\nMODULES=\"java.base\"\n"))
	f.Add([]byte("JAVA_VERSION=21\r\nJVM_VARIANT=Openj9\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, ok := ParseRelease(b)
		if !ok {
			return
		}
		if r["JAVA_VERSION"] == "" {
			t.Fatal("accepted without JAVA_VERSION")
		}
		_ = r.Version()
		_ = r.OpenJ9()
		_ = r.JLinked()
	})
}

// Round-2 finding 2: what the setenv.sh model still accepted.
func TestSetenvModelRound2(t *testing.T) {
	jira := "/opt/atlassian/jira/bin/setenv.sh"
	tomcat := "/opt/tomcat/bin/setenv.sh"
	for _, c := range []struct {
		file, text string
		want       bool
	}{
		{jira, "never_called() {\n  JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\n}\n", false},
		{jira, "function f {\n  CATALINA_OPTS=\"-XX:-UseBASE64Intrinsics\"\n}\n", false},
		{jira, "[ \"$X\" = 1 ] && {\n  JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\n}\n", false},
		{jira, "if [ -n \"$Y\" ]; then\n  echo done\n  JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\nfi\n", false},
		{jira, "cat <<EOF\nJVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\nEOF\n", false},
		{tomcat, "JAVA_OPTS=\"-XX:-UseBASE64Intrinsics\"; JAVA_OPTS=\"-Xmx1g\"\n", false},
		{tomcat, "JAVA_OPTS=\"-XX:-UseBASE64Intrinsics\"\nunset JAVA_OPTS\n", false},
		{tomcat, "JAVA_TOOL_OPTIONS=\"-XX:-UseBASE64Intrinsics\"\n", false},
		{jira, "SOLR_OPTS=\"-XX:-UseBASE64Intrinsics\"\n", false},
		{tomcat, "JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\n", false},
		// Launcher order: catalina.sh passes $JAVA_OPTS then $CATALINA_OPTS.
		{tomcat, "CATALINA_OPTS=\"-XX:-UseBASE64Intrinsics\"\nJAVA_OPTS=\"-XX:+UseBASE64Intrinsics\"\n", true},
		{tomcat, "CATALINA_OPTS=\"-XX:+UseBASE64Intrinsics\"\nJAVA_OPTS=\"-XX:-UseBASE64Intrinsics\"\n", false},
		// Still counted.
		{tomcat, "export JAVA_TOOL_OPTIONS=\"-XX:-UseBASE64Intrinsics\"\n", true},
		{tomcat, "JAVA_TOOL_OPTIONS=\"-XX:-UseBASE64Intrinsics\"\nexport JAVA_TOOL_OPTIONS\n", true},
		{tomcat, "cat <<'EOF'\nignored\nEOF\nCATALINA_OPTS=\"$CATALINA_OPTS -XX:-UseBASE64Intrinsics\"\n", true},
		{jira, "JVM_SUPPORT_RECOMMENDED_ARGS=\"-XX:-UseBASE64Intrinsics\"\n", true},
		// After a function or group closes, assignments count again.
		{tomcat, "f() {\n  echo hi\n}\nCATALINA_OPTS=\"-XX:-UseBASE64Intrinsics\"\n", true},
		{tomcat, "function g {\n  echo hi\n}\nCATALINA_OPTS=\"-XX:-UseBASE64Intrinsics\"\n", true},
		{tomcat, "[ -f x ] && {\n  echo hi\n}\nCATALINA_OPTS=\"-XX:-UseBASE64Intrinsics\"\n", true},
	} {
		s, ok := ReadSetting(c.file, []byte(c.text))
		if !ok {
			t.Fatal("not read")
		}
		if m, _ := s.Options(21).Mitigates(); m != c.want {
			t.Errorf("%s %q: %v, want %v", c.file, c.text, m, c.want)
		}
	}
}
