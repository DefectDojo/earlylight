package refs

import (
	"fmt"
	"testing"
)

func TestInstructions(t *testing.T) {
	df := "# escape=\\\nFROM debian:12 AS base\n" +
		"RUN apt-get update && \\\n    # a comment in a continuation\n\n    apt-get install -y openjdk-17-jdk\n" +
		"RUN\t[\"apt-get\", \"install\", \"-y\", \"x\"]\n" +
		"RUN --mount=type=bind,from=eclipse-temurin:21,target=/j cp -r /j /opt\n" +
		"RUN <<EOF\napt-get install -y a\necho done\nEOF\n" +
		"ONBUILD RUN apt-get install -y b\n" +
		"COPY --link --from=eclipse-temurin:21.0.13_9-jre /opt/java /opt/java\n"
	ins, err := Instructions([]byte(df))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, in := range ins {
		cmd := in.Cmd
		if in.Onbuild {
			cmd = "onbuild:" + cmd
		}
		got = append(got, fmt.Sprintf("%d %s %q %q %q %q", in.Line, cmd, in.Flags, in.Args, in.JSON, in.Heredocs))
	}
	want := []string{
		`2 from [] "debian:12 AS base" [] []`,
		`3 run [] "apt-get update &&     apt-get install -y openjdk-17-jdk" [] []`,
		`7 run [] "[\"apt-get\", \"install\", \"-y\", \"x\"]" ["apt-get" "install" "-y" "x"] []`,
		`8 run ["--mount=type=bind,from=eclipse-temurin:21,target=/j"] "cp -r /j /opt" [] []`,
		`9 run [] "<<EOF" [] ["apt-get install -y a\necho done\n"]`,
		`13 onbuild:run [] "apt-get install -y b" [] []`,
		`14 copy ["--link" "--from=eclipse-temurin:21.0.13_9-jre"] "/opt/java /opt/java" [] []`,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		for i := range got {
			if i >= len(want) || got[i] != want[i] {
				t.Errorf("instruction %d:\n got %s\nwant %v", i, got[i], want[min(i, len(want)-1)])
			}
		}
		if len(got) != len(want) {
			t.Errorf("%d instructions, want %d", len(got), len(want))
		}
	}
	bt := "# escape=`\nFROM x\nRUN apt-get update `\n && apt-get install -y openjdk-17-jdk\n"
	ins, err = Instructions([]byte(bt))
	if err != nil || len(ins) != 2 || ins[1].Args != "apt-get update  && apt-get install -y openjdk-17-jdk" {
		t.Errorf("backtick escape: %v %+v", err, ins)
	}
	if _, err := Instructions(make([]byte, MaxDockerfileSize+1)); err == nil {
		t.Error("a Dockerfile over MaxDockerfileSize was parsed")
	}
}
