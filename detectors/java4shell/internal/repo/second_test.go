package repo

import (
	"context"
	"strings"
	"testing"
)

// Second final review: a Compose build argument is a literal in the tree,
// so the FROM is judged with it. It is a gap only when the value cannot be
// read and the image could be a Java one, and only for the Dockerfile the
// service builds. Before, any Dockerfile that used an ARG of that name
// was marked not checked: a tree with no Java in it made fix exit 1.
func TestComposeBuildArgsAreJudged(t *testing.T) {
	const fixedDefault = "ARG TAG=21.0.13.1_2-jre\nFROM eclipse-temurin:${TAG}\n"
	compose := func(context, args string) string {
		return "services:\n  app:\n    build:\n      context: " + context + "\n      args:\n" + args
	}
	for name, c := range map[string]struct {
		files map[string]string
		want  string
	}{
		"no Java: nginx with a literal":                                   {map[string]string{"Dockerfile": "ARG NGINX=1.27\nFROM nginx:${NGINX}\n", "docker-compose.yml": compose(".", "        NGINX: 1.28\n")}, ""},
		"no Java: nginx with a variable":                                  {map[string]string{"Dockerfile": "ARG NGINX=1.27\nFROM nginx:${NGINX}\n", "docker-compose.yml": compose(".", "        NGINX: ${NGINX_VERSION}\n")}, ""},
		"a vulnerable tag over a fixed default":                           {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"the same as a list":                                              {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        - TAG=21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"a fixed tag over a fixed default":                                {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13.1_2-jdk\n")}, ""},
		"the default again":                                               {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13.1_2-jre\n")}, ""},
		"a fixed tag over a vulnerable default: the default still builds": {map[string]string{"Dockerfile": "ARG TAG=21.0.13_9-jre\nFROM eclipse-temurin:${TAG}\n", "docker-compose.yml": compose(".", "        TAG: 21.0.13.1_2-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"a value from the environment":                                    {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: ${JAVA_TAG}\n")}, "skip Dockerfile:2"},
		"a name with no value (taken from the environment)":               {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        - TAG\n")}, "skip Dockerfile:2"},
		"the whole image in the argument":                                 {map[string]string{"Dockerfile": "ARG BASE=debian:12\nFROM ${BASE}\n", "docker-compose.yml": compose(".", "        BASE: eclipse-temurin:21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"the whole image, not Java":                                       {map[string]string{"Dockerfile": "ARG BASE=debian:12\nFROM ${BASE}\n", "docker-compose.yml": compose(".", "        BASE: debian:13\n")}, ""},
		"the whole image from the environment":                            {map[string]string{"Dockerfile": "ARG BASE=debian:12\nFROM ${BASE}\n", "docker-compose.yml": compose(".", "        BASE: ${BASE_IMAGE}\n")}, "skip Dockerfile:2"},
		"two arguments, one set":                                          {map[string]string{"Dockerfile": "ARG REPO=eclipse-temurin\nARG TAG=21.0.13.1_2-jre\nFROM ${REPO}:${TAG}\n", "docker-compose.yml": compose(".", "        TAG: 21.0.13_9-jre\n")}, "skip Dockerfile:3"},
		"another service's Dockerfile is not marked":                      {map[string]string{"Dockerfile": fixedDefault, "svc/Dockerfile": "ARG TAG=3\nFROM alpine:3\n", "docker-compose.yml": compose("./svc", "        TAG: 21.0.13_9-jre\n")}, ""},
		"a Dockerfile named in a sub-directory":                           {map[string]string{"app/Dockerfile.prod": fixedDefault, "docker-compose.yml": "services:\n  a:\n    build:\n      context: ./app\n      dockerfile: Dockerfile.prod\n      args:\n        TAG: 21.0.13_9-jre\n"}, "app/Dockerfile.prod:2 image-pin vulnerable"},
		"a context the tree cannot place":                                 {map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose("${APP_DIR}", "        TAG: 21.0.13_9-jre\n")}, "Dockerfile:2 image-pin vulnerable"},
		"a Compose file in a sub-directory":                               {map[string]string{"deploy/Dockerfile": fixedDefault, "deploy/compose.yaml": compose(".", "        TAG: 21.0.13_9-jre\n")}, "deploy/Dockerfile:2 image-pin vulnerable"},
	} {
		if g := strings.Join(got(t, tree(t, c.files)), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
	// The finding names the Compose file and is not one fix edits.
	res := scanTree(t, map[string]string{"Dockerfile": fixedDefault, "docker-compose.yml": compose(".", "        TAG: 21.0.13_9-jre\n")})
	if len(res.Findings) != 1 || res.Findings[0].Fixable || !strings.Contains(res.Findings[0].Reason, "docker-compose.yml") {
		t.Errorf("the finding from a Compose build argument: %+v", res.Findings)
	}
}

// An unresolved reference is a java4shell gap only when it could be a
// Java image: its name says so, or a variable hides the name. A variable
// in the tag of an image that is plainly something else is not.
func TestUnresolvedReferenceThatIsNotJava(t *testing.T) {
	for name, c := range map[string]struct{ df, want string }{
		"a variable tag of another image":               {"FROM registry.example.com/acme/web:${VERSION}\n", ""},
		"a variable tag with a default-less brace form": {"FROM nginx:$NGINX\n", ""},
		"a variable tag of a Java image":                {"FROM eclipse-temurin:${VERSION}\n", "skip Dockerfile:1"},
		"a variable name":                               {"FROM ${BASE}:${VERSION}\n", "skip Dockerfile:1"},
		"a variable registry path":                      {"FROM registry.example.com/${TEAM}/app:1\n", "skip Dockerfile:1"},
	} {
		if g := strings.Join(got(t, tree(t, map[string]string{"Dockerfile": c.df})), ", "); g != c.want {
			t.Errorf("%s: [%s], want [%s]", name, g, c.want)
		}
	}
}

func scanTree(t *testing.T, files map[string]string) Result {
	t.Helper()
	res, err := Scan(context.Background(), tree(t, files), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}
