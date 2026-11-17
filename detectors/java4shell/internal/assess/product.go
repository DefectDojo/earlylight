package assess

import (
	"path"
	"strings"
)

// standardPlaces are where Java runtimes are installed on their own (by a
// package, an image, an installer, a version manager or a CI runner). A
// runtime there is not part of another product.
var standardPlaces = []string{
	"/usr/lib/jvm/", "/usr/lib64/jvm/", "/usr/java/", "/opt/java/", "/usr/local/java/", "/usr/jdk/",
	"/usr/local/openjdk", "/opt/openjdk", "/opt/jdk", "/opt/hostedtoolcache/", "/Library/Java/JavaVirtualMachines/",
	"/System/Library/Java/", "/.sdkman/candidates/java/", "/.jdks/", "/.gradle/jdks/", "/.asdf/installs/java/",
	"/.local/share/mise/installs/java/", "/.m2/jdks/", "/usr/lib/jvm-", "/opt/ibm/java", "/opt/graalvm",
	"/Program Files/Java/", "/Program Files/Eclipse Adoptium/", "/Program Files/Eclipse Foundation/", "/Program Files/Zulu/",
	"/Program Files/Amazon Corretto/", "/Program Files/Microsoft/", "/Program Files/BellSoft/", "/Program Files/Semeru/",
	"/Program Files/SapMachine/", "/Program Files (x86)/Java/",
}

// runtimeDirs are the names products give the runtime they bundle.
var runtimeDirs = map[string]bool{"jre": true, "jdk": true, "jbr": true, "java": true, "runtime": true, "jre64": true, "openjdk": true,
	"jre-x64": true, "jdk-x64": true, "Home": true}

// products names well-known products by a piece of their install path.
var products = []struct{ part, name string }{
	{"/atlassian/jira", "Atlassian Jira"}, {"/atlassian/confluence", "Atlassian Confluence"}, {"/atlassian/bitbucket", "Atlassian Bitbucket"},
	{"/atlassian/bamboo", "Atlassian Bamboo"}, {"/atlassian/crowd", "Atlassian Crowd"}, {"/atlassian/", "Atlassian product"},
	{"/elasticsearch", "Elasticsearch"}, {"/logstash", "Logstash"}, {"/opensearch", "OpenSearch"}, {"/kibana", "Kibana"},
	{"/artifactory", "JFrog Artifactory"}, {"/jfrog/", "JFrog product"}, {"/sonatype/nexus", "Sonatype Nexus"}, {"/nexus", "Sonatype Nexus"},
	{"/teamcity", "JetBrains TeamCity"}, {"/youtrack", "JetBrains YouTrack"}, {"IntelliJ", "IntelliJ IDEA"}, {"/idea", "IntelliJ IDEA"},
	{"PyCharm", "PyCharm"}, {"/pycharm", "PyCharm"}, {"/android-studio", "Android Studio"}, {"Android Studio", "Android Studio"},
	{"/JetBrains/", "JetBrains IDE"}, {"/jetbrains", "JetBrains IDE"}, {"/sonarqube", "SonarQube"}, {"/keycloak", "Keycloak"},
	{"/jenkins", "Jenkins"}, {"/solr", "Apache Solr"}, {"/kafka", "Apache Kafka"}, {"/confluent", "Confluent Platform"},
	{"/BurpSuite", "Burp Suite"}, {"Burp Suite", "Burp Suite"}, {"/dbeaver", "DBeaver"}, {"DBeaver", "DBeaver"}, {"/eclipse", "Eclipse IDE"},
	{"/netbeans", "Apache NetBeans"}, {"/minecraft", "Minecraft"}, {"/tableau", "Tableau"}, {"/MATLAB", "MATLAB"},
	{"/cassandra", "Apache Cassandra"}, {"/neo4j", "Neo4j"}, {"/gitbucket", "GitBucket"}, {"/rundeck", "Rundeck"},
}

// notProduct are directories too general to be a product's install
// directory.
var notProduct = map[string]bool{"/": true, "/opt": true, "/usr": true, "/usr/local": true, "/usr/share": true, "/usr/lib": true,
	"/srv": true, "/home": true, "/root": true, "/app": true, "/var": true, "/var/lib": true, "/Applications": true, "C:/Program Files": true}

// standard reports a runtime installed on its own.
func standard(root string) bool {
	for _, p := range standardPlaces {
		if strings.Contains(root, p) {
			return true
		}
	}
	return false
}

// Product returns the product a runtime is bundled with: its name and
// install directory. ok is false for a runtime installed on its own.
func Product(root string) (name, dir string, ok bool) {
	if standard(root) {
		return "", "", false
	}
	dir = root
	// A macOS runtime: <product>.app/Contents/jbr/Contents/Home.
	dir = strings.TrimSuffix(dir, "/Contents/Home")
	if !runtimeDirs[path.Base(dir)] {
		// Products also nest it one level deeper (lib/runtime/jre,
		// app/third-party/java/<version>).
		parent := path.Base(path.Dir(dir))
		if !runtimeDirs[parent] && parent != "third-party" {
			return "", "", false
		}
		dir = path.Dir(dir)
	}
	dir = path.Dir(dir)
	// Only the layouts that put the runtime below such a directory.
	if path.Base(dir) == "third-party" {
		dir = path.Dir(dir)
		if path.Base(dir) == "app" {
			dir = path.Dir(dir)
		}
	}
	if b := path.Base(dir); b == "Contents" && strings.HasSuffix(path.Dir(dir), ".app") {
		dir = path.Dir(dir)
	}
	if notProduct[dir] || strings.Count(dir, "/") < 2 && !strings.Contains(dir, ":") {
		// /opt/jre, /app/jre, /usr/jre: a runtime in a general directory,
		// not part of a product.
		return "", "", false
	}
	for _, p := range products {
		if strings.Contains(dir, p.part) {
			return p.name, dir, true
		}
	}
	return path.Base(dir), dir, true
}
