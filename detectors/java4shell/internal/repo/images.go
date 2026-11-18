package repo

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/DefectDojo/earlylight/detectors/java4shell/internal/knowledge"
)

// Family is a published Java runtime image whose tags name the Java
// release.
type Family struct {
	Repo   string // repository, without docker.io/ or library/
	Vendor string
	// OpenJ9 images run the OpenJ9 VM, which does not have the decoder.
	OpenJ9 bool
	// Prefix comes before the version in the tag ("open-" for Semeru).
	Prefix string
	// OpenJDKBuild is true when the build in the tag is OpenJDK's build
	// number (Temurin's "_9"); other vendors' tag builds are their own.
	OpenJDKBuild bool
	// exact reports whether the text after the version pins one release
	// (Temurin's "_9", Liberica's "-10", Zulu's "-21.52"), so the version
	// has no further numbers.
	exact *regexp.Regexp
}

var (
	temurinBuild  = regexp.MustCompile(`^_\d+`)
	libericaBuild = regexp.MustCompile(`^-\d+(?:-|$)`)
	zuluBuild     = regexp.MustCompile(`^-\d+\.\d+(?:\.\d+)*`)
)

// Families are the runtime images this detector reads tags of.
var Families = []Family{
	{Repo: "eclipse-temurin", Vendor: "Eclipse Temurin", exact: temurinBuild, OpenJDKBuild: true},
	{Repo: "amazoncorretto", Vendor: "Amazon Corretto"},
	{Repo: "openjdk", Vendor: "OpenJDK (the deprecated official image)"},
	{Repo: "sapmachine", Vendor: "SapMachine"},
	{Repo: "azul/zulu-openjdk", Vendor: "Azul Zulu", exact: zuluBuild},
	{Repo: "azul/zulu-openjdk-alpine", Vendor: "Azul Zulu", exact: zuluBuild},
	{Repo: "azul/zulu-openjdk-debian", Vendor: "Azul Zulu", exact: zuluBuild},
	{Repo: "azul/zulu-openjdk-centos", Vendor: "Azul Zulu", exact: zuluBuild},
	{Repo: "bellsoft/liberica-openjdk-debian", Vendor: "BellSoft Liberica", exact: libericaBuild},
	{Repo: "bellsoft/liberica-openjre-debian", Vendor: "BellSoft Liberica", exact: libericaBuild},
	{Repo: "bellsoft/liberica-openjdk-alpine", Vendor: "BellSoft Liberica", exact: libericaBuild},
	{Repo: "bellsoft/liberica-openjre-alpine", Vendor: "BellSoft Liberica", exact: libericaBuild},
	{Repo: "bellsoft/liberica-openjdk-alpine-musl", Vendor: "BellSoft Liberica", exact: libericaBuild},
	{Repo: "bellsoft/liberica-openjre-alpine-musl", Vendor: "BellSoft Liberica", exact: libericaBuild},
	{Repo: "bellsoft/liberica-runtime-container", Vendor: "BellSoft Liberica"},
	{Repo: "mcr.microsoft.com/openjdk/jdk", Vendor: "Microsoft Build of OpenJDK"},
	{Repo: "container-registry.oracle.com/java/openjdk", Vendor: "Oracle OpenJDK"},
	{Repo: "container-registry.oracle.com/java/jdk", Vendor: "Oracle JDK"},
	{Repo: "ibm-semeru-runtimes", Vendor: "IBM Semeru", OpenJ9: true, Prefix: "open-"},
	{Repo: "ibmjava", Vendor: "IBM Java", OpenJ9: true},
	{Repo: "icr.io/appcafe/ibm-semeru-runtimes", Vendor: "IBM Semeru", OpenJ9: true, Prefix: "open-"},
}

// repoName normalises an image name to a repository: docker.io and
// library/ removed, tag and digest removed.
func repoName(image string) (repo, tag string) {
	ref := image
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndexByte(ref, '/')
	if i := strings.LastIndexByte(ref, ':'); i > slash {
		ref, tag = ref[:i], ref[i+1:]
	}
	for _, p := range []string{"docker.io/", "index.docker.io/", "registry-1.docker.io/"} {
		ref = strings.TrimPrefix(ref, p)
	}
	ref = strings.TrimPrefix(ref, "library/")
	return ref, tag
}

// FamilyOf returns the runtime image family of an image reference.
func FamilyOf(image string) (Family, string, bool) {
	repo, tag := repoName(image)
	for _, f := range Families {
		if repo == f.Repo {
			return f, tag, true
		}
	}
	return Family{}, tag, false
}

var leadingVersion = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,9}){0,5})`)

// TagVersion is what a tag says about the Java release.
type TagVersion struct {
	Nums []int
	// Exact is true when the tag pins one release; otherwise it names every
	// release that starts with Nums (a moving tag such as "21" or "21-jre").
	Exact bool
	// Text is the version as written in the tag, Variant what follows it
	// (and its build), for finding the same variant of another release.
	Text, Build, Variant string
	// OpenJDKBuild is the OpenJDK build number the tag names, -1 when it
	// names none (a vendor's own build number, or no build).
	OpenJDKBuild int
}

// ParseTag reads the Java release a family's tag names. ok is false for a
// tag with no leading version ("latest", "jre", "alpine").
func (f Family) ParseTag(tag string) (TagVersion, bool) {
	t, ok := strings.CutPrefix(tag, f.Prefix)
	if !ok {
		return TagVersion{}, false
	}
	m := leadingVersion.FindString(t)
	if m == "" {
		return TagVersion{}, false
	}
	rest := t[len(m):]
	if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		return TagVersion{}, false
	}
	tv := TagVersion{Text: m, Variant: rest, OpenJDKBuild: -1}
	for _, p := range strings.Split(m, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return TagVersion{}, false
		}
		tv.Nums = append(tv.Nums, n)
	}
	if tv.Nums[0] < 8 || tv.Nums[0] > 99 {
		return TagVersion{}, false
	}
	if f.Repo == "amazoncorretto" && len(tv.Nums) >= 4 && tv.Nums[3] > 3 {
		// Corretto's own build number in the fourth place: the Java
		// version is the first three, exactly.
		tv.Nums, tv.Exact = tv.Nums[:3], true
	}
	if f.exact != nil {
		if b := f.exact.FindString(rest); b != "" {
			b = strings.TrimSuffix(b, "-")
			tv.Exact, tv.Build, tv.Variant = true, b, rest[len(b):]
			if f.OpenJDKBuild {
				n := 0
				fmt.Sscanf(strings.TrimLeft(b, "_-"), "%d", &n)
				tv.OpenJDKBuild = n
			}
		}
	}
	return tv, true
}

// JudgeTag says what a tag's version proves. A moving tag that could name
// both unfixed and fixed releases is Unknown: the image has to be read.
func JudgeTag(tv TagVersion) (knowledge.Status, string) {
	nums := tv.Nums
	feature := nums[0]
	what := "the tag names Java " + tv.Text
	if !tv.Exact {
		what = "the tag names the newest Java " + tv.Text + " release at build time"
	}
	if tv.Exact || feature < 17 {
		st, why := knowledge.Judge(knowledge.Version{Nums: nums, Build: tv.OpenJDKBuild})
		return st, what + ": " + why
	}
	l, ok := knowledge.LineOf(feature)
	if !ok {
		st, why := knowledge.Judge(knowledge.Version{Nums: nums, Build: -1})
		if st == knowledge.Vulnerable {
			return knowledge.Unknown, what + ", which the image has to show"
		}
		return st, what + ": " + why
	}
	if l.Introduced != nil {
		k := min(len(nums), len(l.Introduced))
		c := knowledge.Compare(nums[:k], l.Introduced[:k])
		if c < 0 {
			return knowledge.NotAffected, what + ", before " + join(l.Introduced) + ", the first update with the AVX-512 VBMI decoder"
		}
		if c == 0 && len(nums) < len(l.Introduced) {
			return knowledge.Unknown, what + ": which release that is decides it, so the image has to be read"
		}
	}
	if l.Fixed == nil {
		return knowledge.Vulnerable, what + ": " + l.Note
	}
	k := min(len(nums), len(l.Fixed))
	switch c := knowledge.Compare(nums[:k], l.Fixed[:k]); {
	case c < 0:
		return knowledge.Vulnerable, what + ", older than " + join(l.Fixed) + ", the first " + strconv.Itoa(feature) + " release with the fix"
	case c == 0 && len(nums) < len(l.Fixed):
		return knowledge.Unknown, what + ": the newest release it names may or may not have the fix (" + join(l.Fixed) + "), so the image has to be read"
	}
	st, why := knowledge.Judge(knowledge.Version{Nums: nums, Build: -1})
	return st, what + ": " + why
}

func join(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// javaish are words in an image name that suggest a Java runtime inside:
// images with them are pulled and read; others are not.
var javaish = []string{"java", "jdk", "jre", "temurin", "corretto", "zulu", "liberica", "sapmachine", "semeru", "openj9", "graalvm",
	"maven", "gradle", "tomcat", "jetty", "wildfly", "jboss", "keycloak", "jenkins", "atlassian", "jira", "confluence", "bitbucket",
	"bamboo", "elasticsearch", "logstash", "opensearch", "kafka", "zookeeper", "solr", "cassandra", "neo4j", "sonarqube", "sonatype",
	"nexus", "artifactory", "spring", "quarkus", "liberty", "payara", "glassfish", "flink", "spark", "hadoop", "hive", "trino", "presto",
	"druid", "pinot", "nifi", "activemq", "teamcity", "youtrack", "gerrit", "pingfederate", "pingidentity", "spinnaker", "struts", "minecraft", "openliberty", "websphere", "weblogic", "distroless/java"}

// Javaish reports an image whose name suggests a Java runtime.
func Javaish(image string) bool {
	repo, tag := repoName(image)
	s := strings.ToLower(repo + ":" + tag)
	for _, w := range javaish {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}
