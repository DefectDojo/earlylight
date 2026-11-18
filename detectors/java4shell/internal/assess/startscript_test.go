package assess

import (
	"strings"
	"testing"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/jvm"
)

// Final review B5: a mitigation is not reported when a start script the
// command reaches was not read, however the command reaches it (a shell
// text, a name looked up in PATH, a relative path, a script that another
// script runs), or when a script it reaches turns the decoder back on.
// The verdict is vulnerable either way; this is about the status.
func TestMitigationAndTheWaysToAStartScript(t *testing.T) {
	const big = "/app/start.sh" // not read
	entry := WordsOf([]byte("#!/bin/sh\ncd /app\nexec ./start.sh \"$@\"\n"))
	other := WordsOf([]byte("#!/bin/sh\nexec /usr/bin/something-else\n"))
	for _, c := range []struct {
		name    string
		cmd     []string
		scripts map[string]WordSet // read scripts
		unread  []string
		undo    map[string]string
		want    Status
		says    string
	}{
		{"the script itself", []string{big}, nil, []string{big}, nil, Vulnerable, big + " was not read"},
		{"a shell text", []string{"sh", "-c", "exec /app/start.sh"}, nil, []string{big}, nil, Vulnerable, "was not read"},
		{"a shell text with arguments", []string{"sh", "-c", "/app/start.sh --flag"}, nil, []string{big}, nil, Vulnerable, big},
		{"a relative path in a shell text", []string{"/bin/bash", "-c", "cd /app && ./start.sh"}, nil, []string{big}, nil, Vulnerable, big},
		{"a name looked up in PATH", []string{"tini", "--", "start.sh"}, nil, []string{big}, nil, Vulnerable, big},
		{"a script that a read script runs", []string{"/entry.sh"}, map[string]WordSet{"/entry.sh": entry}, []string{big}, nil, Vulnerable, big},
		{"two scripts deep", []string{"/init"}, map[string]WordSet{"/init": WordsOf([]byte("#!/bin/sh\nexec /entry.sh\n")), "/entry.sh": entry}, []string{big}, nil, Vulnerable, big},
		{"more scripts than recorded", []string{"/entry.sh"}, nil, nil, nil, Vulnerable, "more start scripts"},
		{"a read script that turns the decoder on", []string{big}, map[string]WordSet{big: entry}, nil, map[string]string{big: "-XX:+UseBASE64Intrinsics"}, Vulnerable, "passes -XX:+UseBASE64Intrinsics"},
		{"reached through another script", []string{"/entry.sh"}, map[string]WordSet{"/entry.sh": entry, big: other}, nil, map[string]string{big: "-XX:UseAVX=3"}, Vulnerable, "passes -XX:UseAVX=3"},
		// What the command does not reach changes nothing.
		{"an unread script nothing runs", []string{"/entry.sh"}, map[string]WordSet{"/entry.sh": other}, []string{big}, nil, Mitigated, ""},
		{"a script nothing runs turns the decoder on", []string{"/entry.sh"}, map[string]WordSet{"/entry.sh": other, big: other}, nil, map[string]string{big: "-XX:+UseBASE64Intrinsics"}, Mitigated, ""},
		{"java itself", []string{"java", "-jar", "/app/app.jar"}, nil, []string{big}, nil, Mitigated, ""},
	} {
		in := Input{Libraries: []*jvm.Library{vulnLib(t, temurin)}, Env: []string{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", "PATH=/app:/usr/bin"},
			Command: c.cmd, ScriptWords: c.scripts, UndoScripts: c.undo, UnreadScripts: map[string]bool{}}
		for _, u := range c.unread {
			in.UnreadScripts[u] = true
		}
		in.ScriptsOver = c.name == "more scripts than recorded"
		f := one(t, in)
		if f.Status != c.want || !strings.Contains(f.Reason, c.says) {
			t.Errorf("%s: %s, want %s saying %q (%s)", c.name, f.Status, c.want, c.says, f.Reason)
		}
	}
}

func TestWordSet(t *testing.T) {
	ws := WordsOf([]byte("#!/bin/sh\nexec \"$APP_HOME\"/bin/start-app.sh --port=8080 >>/var/log/app.log\n. ./lib/common.sh\n"))
	for _, w := range []string{"sh", "start-app.sh", "common.sh", "app.log", "exec"} {
		if !ws.Has(w) {
			t.Errorf("%q not in the set", w)
		}
	}
	if ws.Has("catalina.sh") || ws.Has("") {
		t.Error("a word that is not there")
	}
}
