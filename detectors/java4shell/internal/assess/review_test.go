package assess

import (
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
)

// Regressions from the independent review: mitigations that covered more
// than they do.
func TestReviewMitigationScope(t *testing.T) {
	setting := func(p, text string) jvm.Setting {
		t.Helper()
		s, ok := jvm.ReadSetting(p, []byte(text))
		if !ok {
			t.Fatalf("%s not read", p)
		}
		return s
	}
	status := func(in Input, root string) Status {
		t.Helper()
		for _, f := range Run(in) {
			if f.Path == root {
				return f.Status
			}
		}
		t.Fatalf("no finding for %s", root)
		return ""
	}

	// catalina.sh passes CATALINA_OPTS only to the JVM JAVA_HOME names.
	in := Input{Libraries: []*jvm.Library{vulnLib(t, temurin), vulnLib(t, "/opt/other/jre")},
		Env: []string{"CATALINA_OPTS=-XX:-UseBASE64Intrinsics", "JAVA_HOME=/opt/java/openjdk"}, Command: []string{"catalina.sh", "run"}}
	if status(in, temurin) != Mitigated || status(in, "/opt/other/jre") != Vulnerable {
		t.Error("CATALINA_OPTS covered a runtime catalina.sh does not start")
	}

	// systemd: JAVA_OPTS does not reach a java ExecStart.
	unit := setting("/etc/systemd/system/a.service", "Environment=JAVA_OPTS=-XX:-UseBASE64Intrinsics\nExecStart=/opt/acme/jre/bin/java -jar /opt/acme/a.jar\n")
	in = Input{Libraries: []*jvm.Library{vulnLib(t, "/opt/acme/jre")}, Settings: []jvm.Setting{unit}}
	if s := status(in, "/opt/acme/jre"); s != Vulnerable {
		t.Errorf("JAVA_OPTS with a java ExecStart: %s", s)
	}
	// _JAVA_OPTIONS overrides the command line, wherever it is written.
	unit = setting("/etc/systemd/system/a.service", "Environment=_JAVA_OPTIONS=-XX:+UseBASE64Intrinsics\nExecStart=/opt/acme/jre/bin/java -XX:-UseBASE64Intrinsics -jar /opt/acme/a.jar\n")
	in.Settings = []jvm.Setting{unit}
	if s := status(in, "/opt/acme/jre"); s != Vulnerable {
		t.Errorf("_JAVA_OPTIONS in a unit: %s", s)
	}
	// A drop-in that resets JAVA_TOOL_OPTIONS undoes the unit's mitigation.
	base := setting("/usr/lib/systemd/system/a.service", "Environment=JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nExecStart=/opt/acme/bin/run.sh\n")
	drop := setting("/etc/systemd/system/a.service.d/override.conf", "[Service]\nEnvironment=JAVA_TOOL_OPTIONS=-Xmx1g\n")
	in.Settings = []jvm.Setting{base, drop}
	if s := status(in, "/opt/acme/jre"); s != Vulnerable {
		t.Errorf("drop-in reset: %s", s)
	}
	in.Settings = []jvm.Setting{base}
	if s := status(in, "/opt/acme/jre"); s != Mitigated {
		t.Errorf("unit without the drop-in: %s", s)
	}
	// A full unit in /etc replaces the one in /usr/lib.
	over := setting("/etc/systemd/system/a.service", "ExecStart=/opt/acme/bin/run.sh\n")
	in.Settings = []jvm.Setting{base, over}
	if s := status(in, "/opt/acme/jre"); s != Vulnerable {
		t.Errorf("/etc override: %s", s)
	}

	// /opt/app/jre belongs to /opt/app, never to /opt.
	if name, dir, ok := Product("/opt/app/jre"); ok && dir != "/opt/app" {
		t.Errorf("Product(/opt/app/jre) = %q %q", name, dir)
	}
	if _, _, ok := Product("/opt/jre"); ok {
		t.Error("/opt/jre taken for a product in /opt")
	}
	other := setting("/etc/systemd/system/other.service", "Environment=JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics\nExecStart=/opt/other/bin/run.sh\n")
	in = Input{Libraries: []*jvm.Library{vulnLib(t, "/opt/app/jre")}, Settings: []jvm.Setting{other}}
	if s := status(in, "/opt/app/jre"); s != Vulnerable {
		t.Errorf("another service's unit: %s", s)
	}

	// Settings files in general directories configure nothing by place.
	for _, p := range []string{"/etc/jvm.options", "/usr/local/bin/setenv.sh", "/opt/bin/setenv.sh"} {
		s := setting(p, "-XX:-UseBASE64Intrinsics\nX=\"-XX:-UseBASE64Intrinsics\"\n")
		in = Input{Libraries: []*jvm.Library{vulnLib(t, "/usr/local/openjdk-21")}, Settings: []jvm.Setting{s}}
		if st := status(in, "/usr/local/openjdk-21"); st != Vulnerable {
			t.Errorf("%s covered a runtime outside its product: %s", p, st)
		}
	}

	// A commented-out option is not set.
	s := setting("/opt/atlassian/jira/bin/setenv.sh", "JVM_SUPPORT_RECOMMENDED_ARGS=\"-Xmx2g\" # was: -XX:-UseBASE64Intrinsics\n")
	in = Input{Libraries: []*jvm.Library{vulnLib(t, "/opt/atlassian/jira/jre")}, Settings: []jvm.Setting{s}}
	if st := status(in, "/opt/atlassian/jira/jre"); st != Vulnerable {
		t.Errorf("commented option: %s", st)
	}
}
