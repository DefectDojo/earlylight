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
