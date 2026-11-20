package java4shell

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/testlib"
	"github.com/DefectDojo/earlylight/internal/engine"
)

// Final review B5, through an image: JAVA_TOOL_OPTIONS turns the decoder
// off, and the command reaches a start script that was not read (310 KiB),
// or one that turns it back on. No route to the script reports a
// mitigation.
func TestMitigationNeedsTheStartScript(t *testing.T) {
	lib := testlib.Build(testlib.Lib{Version: "21.0.13+9-LTS", VBMI: true})
	big := append([]byte("#!/bin/sh\n"), bytes.Repeat([]byte("# pad\n"), 310<<10/6)...)
	big = append(big, "exec java -XX:+UseBASE64Intrinsics -jar /app/app.jar\n"...)
	undoes := []byte("#!/bin/sh\nexec java -XX:+UseBASE64Intrinsics -jar /app/app.jar\n")
	plain := []byte("#!/bin/sh\nexec java -jar /app/app.jar\n")
	image := func(script []byte, cmd ...string) string {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for n, b := range map[string][]byte{"opt/jdk/lib/server/libjvm.so": lib, "app/start.sh": script, "entry.sh": []byte("#!/bin/sh\ncd /app && exec ./start.sh\n")} {
			tw.WriteHeader(&tar.Header{Name: n, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg})
			tw.Write(b)
		}
		tw.Close()
		b := buf.Bytes()
		l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
		if err != nil {
			t.Fatal(err)
		}
		img, err := mutate.AppendLayers(empty.Image, l)
		if err != nil {
			t.Fatal(err)
		}
		img, err = mutate.Config(img, v1.Config{Cmd: cmd, Env: []string{"JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics", "PATH=/app:/usr/bin"}})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "image.tar")
		if err := tarball.WriteToFile(p, name.MustParseReference("test/j:1"), img); err != nil {
			t.Fatal(err)
		}
		return "docker-archive:" + p
	}
	for _, c := range []struct {
		name   string
		script []byte
		cmd    []string
		want   string
	}{
		{"unread, run directly", big, []string{"/app/start.sh"}, "vulnerable"},
		{"unread, in a shell text", big, []string{"sh", "-c", "exec /app/start.sh"}, "vulnerable"},
		{"unread, in a shell text with a flag", big, []string{"sh", "-c", "/app/start.sh --flag"}, "vulnerable"},
		{"unread, by a relative path", big, []string{"/bin/bash", "-c", "cd /app && ./start.sh"}, "vulnerable"},
		{"unread, by a name in PATH", big, []string{"tini", "--", "start.sh"}, "vulnerable"},
		{"unread, run by a script that was read", big, []string{"/entry.sh"}, "vulnerable"},
		{"read, and it turns the decoder on", undoes, []string{"/app/start.sh"}, "vulnerable"},
		{"read, turns it on, run by another script", undoes, []string{"/entry.sh"}, "vulnerable"},
		{"read, and it passes nothing", plain, []string{"/app/start.sh"}, "mitigated"},
		{"read, passes nothing, in a shell text", plain, []string{"sh", "-c", "exec /app/start.sh"}, "mitigated"},
		{"unread, and the command is java", big, []string{"java", "-jar", "/app/app.jar"}, "mitigated"},
	} {
		tg := engine.ScanImage([]engine.Detector{&Detector{}}, image(c.script, c.cmd...), engine.Options{})
		if tg.Error != "" || len(tg.Findings) != 1 || tg.Findings[0].Verdict != engine.Vulnerable || tg.Findings[0].Facts["status"] != c.want {
			t.Errorf("%s: error %q findings %+v", c.name, tg.Error, tg.Findings)
		}
	}
}
