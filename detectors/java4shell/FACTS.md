# Java4Shell (CVE-2026-114938): what is known, and from where

Checked 2026-11-17; the advisories and vendor status rechecked 2026-11-18. Every row names its source. "Not fixed yet" means the
source was read on that date and had no fixed release; it is not a guess
about the future. Rows marked **inferred** are reasoning from the sources,
not something a source states.

## The advisories (read by the lead in a browser, 2026-11-17 and 2026-11-18)

The research host cannot reach openjdk.org, oracle.com or access.redhat.com; the lead read these pages and relayed them.

| Fact | Source |
| --- | --- |
| "The affected versions are 27.0.1.0.3, 25.0.5.0.3, 21.0.13.0.3, 17.0.21.0.3, 11.0.33, 8u512, and earlier" (for the advisory's CVEs as a set). CVE-2026-114938: component **hotspot/compiler**, CVSS 3.1 **8.1**, affects the **17, 21, 25 and 27** lines only (not 8, not 11). Acknowledgements include Quang Luong (Calif). The page names no JDK bug ids. The advisory's other CVEs (CVE-2026-114939 to 114947) are not this detector's. Last updated 2026-11-17 17:44 UTC | [OpenJDK Vulnerability Advisory 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17) |
| CVE-2026-114938 in Oracle Java SE, **Oracle GraalVM for JDK** and **Oracle GraalVM Enterprise Edition**, component Compiler, CVSS 3.1 **8.1** (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H), remotely exploitable without authentication. Affected: Java SE 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3; GraalVM for JDK 17.0.21.0.3, 21.0.13.0.3; GraalVM Enterprise Edition 21.3.20.0.3. Note 1: exploitable by supplying data to APIs in the component without untrusted Web Start applications or applets, for example through a web service. Credit: Albert Yang; Quang Luong of Calif.io | [Oracle Critical Security Patch Update, November 2026](https://www.oracle.com/security-alerts/cspunov2026.html) |
| Scores: OpenJDK and Oracle **8.1** (the detector's score); Calif 9.2; Red Hat 9.8 | the two advisories above; Calif advisory; Red Hat CVE page |

## The flaw

| Fact | Source |
| --- | --- |
| The fix is JDK-8393212 "Base64 optimization improvements", 4 added lines in `generate_base64_decodeBlock()` in `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`: before the final 1 to 63 byte fragment of the AVX-512 VBMI path, `cmpl(length, 4); jcc(less, L_bruteForce)` ("A padded Base64 tail shorter than one complete block is handled by Java"). Authored 2026-10-13 by Tobias Hartmann, reviewed by rhalade, mschoene (the OpenJDK vulnerability group's reviewers), chagedorn, rcastanedalo | openjdk/jdk commit [`5177a70b385c16f26ede191fdac7aaba0bed0f8b`](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b), pushed 2026-11-16 |
| What the unfixed code does with a 1 to 3 byte tail that ends in `=`: `output_size` is 0, `L_padding` decrements it to -1, `bzhiq(output_mask, -1, output_size)` with an index of 255 keeps all 64 mask bits, and the masked `evmovdqub` stores 64 bytes at `dest + dp`: a write of up to 64 bytes past the output the caller sized. Read from the stub, and observed (next row); no vendor source states the impact in words | same file, lines around `L_finalBit` and `L_padding` |
| **Observed** on an AMD EPYC 9B14 (Zen 4, with avx512f, avx512bw, avx512vbmi and bmi2), 2026-11-17: after C2 compiles the decoder, `Base64.getDecoder().decode(src, dst)` of a malformed input that ends in a 1 to 3 character fragment with `=` (for example 64 valid characters then `A=`) writes bytes into `dst` past the decoded output. Seen on Temurin 18.0.2.1, 20.0.2, 17.0.6, 17.0.21, 21.0.2, 21.0.13 and 25.0.5; not seen on Temurin 17.0.5 or on SapMachine 21.0.13.1 (the fixed release); not seen on 21.0.13 started with `-XX:-UseBASE64Intrinsics` or with `-XX:UseAVX=2`. On 17.0.x to 20 the input has to be longer than 128 bytes, on 21 and later longer than 31 bytes: the 17u stub enters the AVX-512 path only above 128 bytes (`cmpl(length, 128)`), the 21u stub above 31. With an output array sized by `decode(byte[])` the write goes past the array into the heap. The test program is not in this repository | local run, `eclipse-temurin` images and the SapMachine 21.0.13.1 tarball (sha256 `6cb4df18…949ae9`, matching the GitHub release asset digest) |
| CVE-2026-114938 is listed with CVSS 8.1, component hotspot/compiler, in Amazon Corretto's changelogs of 2026-11-17 | [corretto-17 CHANGELOG 17.0.21.1.2](https://github.com/corretto/corretto-17/blob/17.0.21.1.2/CHANGELOG.md), [corretto-21 21.0.13.1.2](https://github.com/corretto/corretto-21/blob/21.0.13.1.2/CHANGELOG.md), [corretto-25 25.0.5.1.2](https://github.com/corretto/corretto-25/blob/25.0.5.1.2/CHANGELOG.md), [corretto-27 27.0.1.1.4](https://github.com/corretto/corretto-27/blob/27.0.1.1.4/CHANGELOG.md) |
| CVE-2026-114938 is JDK-8393212. Neither the Corretto changelogs (CVEs by component) nor the OpenJDK advisory (no JDK bug ids) state the mapping. The advisory does confirm what 8393212 fits: component hotspot/compiler, lines 17, 21, 25 and 27 (the lines with the AVX-512 VBMI decoder), and last affected releases just before the .1 releases that carry 8393212. The public writeups (lead's sources below) describe exactly the code 8393212 changes: the output mask computed from length and padding, `output_len` underflowing on a padding-only tail, `bzhiq(-1, output_len)` giving all ones and `evmovdqub` writing all 64 bytes. **Inferred from that match**, not stated by a source | Corretto changelogs; OpenJDK advisory; Calif and Semgrep writeups as relayed by the lead |
| The vulnerable path runs only when the CPU reports AVX-512 VBMI, AVX-512BW and BMI2 and HotSpot keeps them enabled: `if (VM_Version::supports_avx512_vbmi() && VM_Version::supports_avx512bw() && VM_Version::supports_bmi2())`. AVX-512 features need AVX-512F, so the four CPU flags are `avx512f avx512bw avx512vbmi bmi2` | stubGenerator_x86_64.cpp at the fix commit |
| MIME decoding (`isMIME`) skips the AVX-512 path; standard and URL-safe decoding use it | same function, `cmpl(isMIME, 0)` |
| `-XX:UseAVX=0/1/2` clears every AVX-512 feature, VBMI included, so the path is not generated | `src/hotspot/cpu/x86/vm_version_x86.cpp`, `if (UseAVX < 3)` block (jdk17u-dev and jdk HEAD) |
| `-XX:-UseBASE64Intrinsics` stops the stub being generated at all: `if (UseBASE64Intrinsics) { ... StubRoutines::_base64_decodeBlock = generate_base64_decodeBlock(); }` | stubGenerator_x86_64.cpp |
| Only x86-64 HotSpot has this stub. AArch64, PPC and RISC-V have their own decode intrinsics (8256245, 8248188, 8314124) with different code. 32-bit x86 (`stubGenerator_x86_32.cpp`) has no decode intrinsic | jdk17u-dev and jdk21u-dev trees; `git log --grep` in openjdk/jdk |
| OpenJ9 (IBM Semeru) does not contain HotSpot: its `lib/server/libjvm.so` is a 97 KB redirector and the VM is `libj9vm29.so`. Whether OpenJ9 has a comparable bug of its own is **not known** | `ibm-semeru-runtimes:open-21-jre` image, release file `JVM_VARIANT="Openj9"` |

## From the public writeups (relayed by the lead, 2026-11-17)

The lead read these; they could not be fetched from the research host. Facts here are as the lead reported them.

| Fact | Source |
| --- | --- |
| Named Java4Shell, credited to Calif. Calif scores it CVSS 9.2; OpenJDK, Oracle and Corretto 8.1, which the detector reports | [Calif advisory](https://calif.io/java4shell/), [Semgrep blog](https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability) |
| Trigger: 64 `A` then `=` (on 17: 128 `A` then `=`); a 65-byte input decoded into a 50-byte buffer is written 62 bytes past its end. Reached only after the intrinsic is JIT-compiled. Matches what was observed here (65 and 129 byte inputs) | same |
| Pre-authentication remote code execution shown on default configurations of Keycloak, Jira, Confluence, JFrog Artifactory, Jenkins and PingFederate; post-authentication on Kafka, Solr, Elasticsearch, Gerrit and Spinnaker; Struts and Spring Boot sample apps; and a client-side variant (a Java client opening TLS to a malicious server). Chain details withheld | same, and posts by Charles Carmakal (Mandiant) and Semgrep |
| Affected: OpenJDK 17.0.6 and later on x86-64 CPUs with avx512f, avx512bw, avx512vbmi and bmi2; ARM64 not affected; every distribution. Oracle Java SE builds named as affected: **8u511b33-perf**, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 (for 8, only the Performance Pack build). The 8u-perf build carries a backport of the decoder; **no fixed 8u-perf version is known**. The detector reports a Java 8 VM library that carries the decoder's stubs as vulnerable up to update 511 and unknown above it | same; Oracle CSPU November 2026 (above) |
| Oracle and OpenJDK released fixes on 2026-11-17 (the advisories above); neither page names the fixed versions per line. They are established below from the OpenJDK repositories and vendor releases | lead |
| Mitigations: `-XX:-UseBASE64Intrinsics` (preferred, for example through `JAVA_TOOL_OPTIONS`), or `-XX:UseAVX=2` on x86-64 only: **an ARM JVM refuses to start with it** | same |
| CPU check: `grep -m1 '^flags' /proc/cpuinfo \| tr ' ' '\n' \| grep -E '^(avx512f\|avx512bw\|avx512vbmi\|bmi2)$'` (all four needed); Kubernetes node label `feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI: "true"` (Node Feature Discovery) | Calif |
| Indicators (not proof): `hs_err_pid*.log` crash files and bursts of `IllegalArgumentException` from `java.util.Base64$Decoder`. No network signature or IOCs published | same |
| SCA and dependency scanners do not report it: it is in the JDK runtime, not a library | same |

## Where the vulnerable path came from

| Line | First release with the AVX-512 VBMI decode path | Source |
| --- | --- | --- |
| mainline | JDK 18 (8268276 "Base64 Decoding optimization for x86 using AVX-512", Scott Gibbons, 2021-06-25, after JDK 17 forked) | openjdk/jdk [`c37988d0793`](https://github.com/openjdk/jdk/commit/c37988d0793b24d98d285530dfda69999a227937); `jdk-18+36` contains it, `jdk-17+35` does not |
| 17 | 17.0.6 (backport 2022-11-09, first tag `jdk-17.0.6+3`, first GA `jdk-17.0.6-ga`). 17.0.0 to 17.0.5 have no x86 decode intrinsic | openjdk/jdk17u-dev `07050b000c` ("Backport-of: c37988d0793b") |
| 11 | never: jdk11u-dev has no Base64 decode intrinsic (only 8205528, AVX-512 encode) | openjdk/jdk11u-dev `git log --grep base64` |
| 8 | never: jdk8u-dev has no Base64 intrinsics | openjdk/jdk8u-dev `git log --grep base64` |
| vendor builds of 8, 11 or 17.0.0-17.0.5 | Oracle's Java 8 Performance Pack (8u511b33-perf) carries the decoder (see above); other vendor backports are **not known**. The detector checks the libjvm for the VBMI decode stubs' names: a Java 8 build that carries them is vulnerable up to update 511 and unknown above it; an 11 or 17.0.0-17.0.5 build that carries them is unknown | lead's sources |

## Fixed releases

| Line | Fixed in | Source |
| --- | --- | --- |
| OpenJDK 17 | **17.0.21.1** (`jdk-17.0.21.1+2`, `jdk-17.0.21.1-ga`, 2026-11-15) | openjdk/jdk17u branch `jdk17.0.21.1`, commit `8ea73158af` |
| OpenJDK 21 | **21.0.13.1** (`jdk-21.0.13.1+2`, `-ga`, 2026-11-15) | openjdk/jdk21u branch `jdk21.0.13.1`, commit `8e115fb5c7` |
| OpenJDK 25 | **25.0.5.1** (`jdk-25.0.5.1+2`, `-ga`, 2026-11-15) | openjdk/jdk25u branch `jdk25.0.5.1`, commit `25bb7d35dc` |
| OpenJDK 27 | **27.0.1.1** (`jdk-27.0.1.1+4`, `-ga`) | openjdk/jdk27u branch `jdk27.0.1.1`, commit `564fc7de7e`; master also has it. The `jdk27.0.2` branch does **not** have it yet |
| Builds of the fixed releases before the fix landed | **not fixed**: `jdk-17.0.21.1+0` (2026-10-27) and `+1` (2026-11-02), `jdk-21.0.13.1+0` and `+1`, `jdk-25.0.5.1+0` and `+1` do not contain the `cmpl(length, 4)` guard; `+2` (2026-11-15) does. `jdk-27.0.1.1+0` does not; `jdk-27.0.1.1+4` does (27u has no `+1` to `+3` tags). The detector's fixed build per line: 17.0.21.1+2, 21.0.13.1+2, 25.0.5.1+2, 27.0.1.1+4; a version named without its build (a GA tag, a version file) is taken as the GA build. Pre-release and self-built JDKs (`-ea`, `-beta`, `-internal`, `adhoc`) are never judged fixed | `git show <tag>:src/hotspot/cpu/x86/stubGenerator_x86_64.cpp` in openjdk/jdk17u, jdk21u, jdk25u, jdk27u, checked 2026-11-18 |
| OpenJDK 26 | **no fix**: last release 26.0.2.1 (2026-07), `jdk26u` master unchanged since 2026-08-18 and without the fix | openjdk/jdk26u |
| 18, 19, 20, 22, 23, 24 | **no fix** (end of life) | n/a |
| JDK 28 (early access) | fix pushed to mainline 2026-11-16; `jdk-28+24` does **not** have it; no later build tagged yet | openjdk/jdk tags |
| 17.0.22, 21.0.14, 25.0.6 (January 2027 updates) | **not known**: the -dev repositories (HEAD of 2026-11-17, tags up to `+2`) do not have the fix yet. Embargoed fixes usually reach -dev at the next release; that is an expectation, not a fact, so these versions are reported as unknown | openjdk/jdk17u-dev, jdk21u-dev, jdk25u-dev HEAD |
| 17.0.21.0.2 / .0.3, 21.0.13.0.2 / .0.3, 25.0.5.0.2 / .0.3, 27.0.1.0.2 / .0.3 | **not fixed**: these October 2026 out-of-band releases carry CA changes only (8395142, 8395690); the OpenJDK advisory and Oracle name the .0.3 releases as the last affected. Vendors ship them as five-part versions (Oracle and Debian sid 17.0.21.0.3, Microsoft 17.0.21.0.2 / 21.0.13.0.2 / 25.0.5.0.2, Temurin 27.0.1.0.2+1); the detector judges every one vulnerable, from the VM library, the release file, OS package pins, image tags and version files | -dev repo tags `jdk-*.0.3+*`; OpenJDK advisory; Oracle CSPU |

## Vendors and distributions (2026-11-17, rechecked 2026-11-18)

| Vendor | Status | Source |
| --- | --- | --- |
| Amazon Corretto | fixed: 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2, 27.0.1.1.4 (all 2026-11-17, each "Import jdk-…1+2/+4", CVE-2026-114938 listed). Corretto 8 and 11: no release after October (not affected). **Docker Hub, 2026-11-18:** Amazon republished the existing `amazoncorretto:21.0.13-*` and `17.0.21-*` tags with the fixed builds (the images report 21.0.13.1+2 and 17.0.21.1+2); there are no `.1` tags. A Corretto tag of the fixed update therefore names whichever build was pushed last, and the detector reads the image | GitHub releases API, CHANGELOG.md of each tag; images scanned by this detector (parity cases corretto-*) |
| SapMachine | releases 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 published 2026-11-17 (the release page names no CVE) | GitHub releases API, SAP/SapMachine |
| Eclipse Temurin | **not fixed** (2026-11-18): newest releases 17.0.21+9, 21.0.13+9-LTS, 25.0.5+8-LTS, 27.0.1.0.2+1; no 17.0.21.1, 21.0.13.1, 25.0.5.1 or 27.0.1.1 build on any line. Docker Hub `eclipse-temurin` newest tags 17.0.21_9, 21.0.13_9, 25.0.5_8, 27.0.1.0 | api.adoptium.net (lead, 2026-11-18); GitHub API, registry-1.docker.io tag list (2026-11-17) |
| Microsoft Build of OpenJDK | **not fixed** (2026-11-18): newest releases 17.0.21.0.2, 21.0.13.0.2, 25.0.5.0.2 (download page of 2026-11-04), which predate the fix. actions/setup-java's Microsoft version list (updated 2026-11-14) is older still: newest 17.0.19, 21.0.11, 25.0.5+0.2. Microsoft publishes no Java 27: the detector does not judge Microsoft packages or setup-java versions of lines it does not ship | learn.microsoft.com/java/openjdk release notes and download page (lead); actions/setup-java Microsoft manifest (reviewer, 2026-11-18) |
| Oracle Java SE | 8u511b33-perf, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 and earlier affected; the fixed Oracle version numbers were not relayed, so Oracle builds after .0.3 are judged by the OpenJDK fixed releases | Oracle CSPU November 2026 |
| Oracle GraalVM, GraalVM Community | GraalVM for JDK 17.0.21.0.3 and 21.0.13.0.3 and GraalVM Enterprise Edition 21.3.20.0.3 affected (Oracle). GraalVM Community: the newest release on graalvm/graalvm-ce-builds was published 2026-11-03, before the fix. **No fixed GraalVM build known** (2026-11-18). See "GraalVM" below | Oracle CSPU November 2026; [graalvm/graalvm-ce-builds releases](https://github.com/graalvm/graalvm-ce-builds/releases) (reviewer, 2026-11-18) |
| Azul Zulu, BellSoft Liberica | **not checked**: their pages could not be read (HTTP 403/404 for the lead; unreachable here). Docker Hub `azul/zulu-openjdk` and `bellsoft/liberica-openjdk-debian` newest tags were 27.0.1.0.3 / 21.0.13.0.3 on 2026-11-17 (not fixed) | registry-1.docker.io tag list |
| IBM Semeru | OpenJ9, not HotSpot (see above) | image inspection |
| Debian | **not fixed** (2026-11-18): the tracker lists every package vulnerable and unfixed: openjdk-17 bookworm-security 17.0.21+9-1~deb12u1, sid 17.0.21.0.3+1-1; openjdk-21 trixie-security 21.0.13+9-1~deb13u2, forky/sid 21.0.13.0.3+1-1; openjdk-25 trixie-security 25.0.5+8-1~deb13u1, sid 25.0.5.0.3+1-3; openjdk-27 sid 27.0.1.0.3+1-1 | [security-tracker.debian.org CVE-2026-114938](https://security-tracker.debian.org/tracker/CVE-2026-114938) (lead); deb.debian.org and security.debian.org pools |
| Ubuntu | **not fixed** (2026-11-18): newest sources openjdk-17 17.0.21.0.3+1-1 (17.0.21.0.3+1-1~XX.04.1 in the stable releases), openjdk-21 21.0.13.0.3+1-1, openjdk-25 25.0.5.0.3+1-3~XX.04.1; none is the fixed update or a backport. The Ubuntu CVE page could not be read | archive.ubuntu.com pool (2026-11-17; openjdk-21 and -17 reread by the reviewer 2026-11-18) |
| Alpine | **not fixed**: community openjdk17 17.0.21.0.3_p1-r0, openjdk21 21.0.13.0.3_p1-r0, openjdk25 25.0.5.0.3_p1-r0/-r1 (3.23, 3.24, edge); 3.21 and 3.22 carry older 17/21. The edge secdb had no entry for the CVE on 2026-11-18 | dl-cdn.alpinelinux.org APKINDEX; Alpine secdb (lead) |
| Red Hat (RHEL, UBI) | **no fixed build** (2026-11-18): affected "OpenJDK 17.0.6 and later" on x86-64 with AVX-512 VBMI; "exact upstream fixed version ... not yet confirmed by Oracle"; no fixed NVRs, no errata, no UBI tags. Bulletin RHSB-2026-018, Bugzilla 2574227, Red Hat CVSS 9.8. See "Red Hat" below | [access.redhat.com CVE-2026-114938](https://access.redhat.com/security/cve/CVE-2026-114938) (lead) |

## GraalVM

| Fact | Source |
| --- | --- |
| A GraalVM JDK is HotSpot with JVMCI: its `lib/server/libjvm.so` has HotSpot's version line with the JDK version and `-jvmci-` (`OpenJDK 64-Bit Server VM (17.0.6+10-jvmci-22.3-b13) for linux-amd64 JRE (17.0.6+10-jvmci-22.3-b13)`) and its release file has `GRAALVM_VERSION` and `IMPLEMENTOR="GraalVM Community"` | GraalVM CE images below |
| **Observed** 2026-11-18: GraalVM CE 22.3.0 for Java 17 is 17.0.5+8 and its libjvm has **no** decoder stubs; 22.3.1 for Java 17 is 17.0.6+10 **with** them; 22.3.1 for Java 11 is 11.0.18+10 without them; GraalVM CE for JDK 21 (GRAALVM_VERSION 23.1.2) is 21.0.2+13 with them | Docker Hub `findepi/graalvm` (a repackaging of the GraalVM CE release archives; registry ghcr.io/graalvm is unreachable here): `22.3.0-java17` sha256:b4460f6857d2…d9b373, `22.3.1-java17` sha256:a953392b9572…ada717, `22.3.1-java11` sha256:983c7f6640ca…66beed, `java21-native` sha256:19937684c9ef…8ed235 |
| GraalVM EE 21.3 builds: which Java lines exist (JDK 11 and 17 at least; a Java 8 build may exist too, and Oracle's Java 8 Performance Pack does carry the decoder) and which of them Oracle's listing of 21.3.20.0.3 covers are **not verified**. The detector judges a GraalVM JDK 17 build by its version (vulnerable today), a GraalVM JDK 8 or 11 runtime vulnerable when its libjvm carries the decoder stubs, and leaves 21.3.x for Java 8 or 11 named in a version file not checked | Oracle CSPU; **unverified** |
| No fixed GraalVM build is known, and GraalVM's fixed builds need not follow OpenJDK's numbering, so the detector judges a GraalVM build at or past the OpenJDK fixed release as **unknown**, never fixed, until a fixed GraalVM build is listed in `knowledge.GraalVMFixed` (empty). A row clears only what OpenJDK's data also judges fixed | lead and reviewer, 2026-11-18; graalvm/graalvm-ce-builds releases |
| sdkman and asdf name GraalVM releases in GraalVM's numbers (`22.3.1.r17-grl`, `graalvm-22.3.1+java17`). From the four images above (**inferred** for the releases not looked at): GraalVM Community 22.3.0 for 17, and Community releases for Java 8 to 16 other than 21.3.x, are not affected; 22.3.1 and later for 17, and any release for 18 and later, are vulnerable. Not checked: `22.3.r17` (no patch), 21.3.x for any line, malformed numbers, Java lines below 8, and Liberica NIK and Mandrel releases that would otherwise be cleared (their numbering is assumed to follow GraalVM's, not checked against their releases) | observations above; **inferred** |
| GraalVM Community's Innovation releases carry their own numbers: graal-25.5.5.0.3 is JDK 25.0.5.0.3, graal-25.1.3 is JDK 25.0.3. A number whose second field is not 0 (Java's has been 0 since JDK 10) is GraalVM's own and is never read as a Java version | [graalvm/graalvm-ce-builds releases](https://github.com/graalvm/graalvm-ce-builds/releases) (reviewer, 2026-11-18) |
| Whether GraalVM Native Image binaries (SubstrateVM, no libjvm) carry a port of the decoder is **not known**; the detector does not look at them | n/a |

## Red Hat

| Fact | Source |
| --- | --- |
| Red Hat backports fixes into the update it ships, so a fixed Red Hat build can keep the upstream version in its libjvm and differ only in the rpm release. The detector keeps a backport table, `knowledge.RedHatFixed` (package, dist tag such as el9_6, fixed EVR, advisory). A row speaks only to rpm releases of its own stream (a number and that dist tag: not Oracle Linux's 2.0.1.el9 or AlmaLinux's .alma; CentOS Stream's el9 cannot be told from RHEL's el9) and its own upstream update and build. It clears an installed runtime only when the libjvm is a released, non-GraalVM HotSpot of exactly that update and build and the release file names `Red Hat, Inc.`; the rpm itself is named by the install path, since the rpm database is not read, so a contradicting runtime is reported unknown. It is **empty**: Red Hat had published no fixed build on 2026-11-18 | Red Hat CVE page (lead) |
| RHEL 8/9 and UBI install the JDK in `/usr/lib/jvm/java-17-openjdk-<version>-<release>.<arch>` with `jre-17`, `jre` and `/etc/alternatives` symlinks into it; the rpm version appends the build to the update (17.0.21.0.9 is 17.0.21+9). **Not verified on a real image here**: registry.access.redhat.com and cdn-ubi.redhat.com (dnf in `redhat/ubi9`) are unreachable from the research host; the detector's tests use that layout | Red Hat packaging convention; unverified |
| UBI OpenJDK images (`registry.access.redhat.com/ubi9/openjdk-21`, `-runtime`, also on registry.redhat.io) are tagged by image release (1.20, 1.20-2.1729089285), not by Java update. With the table empty, the repo scan reports 21 and 25 (every release has the decoder) and 17 at `latest` as vulnerable, other 17 tags (older images could predate 17.0.6) as not checked and pulled. `openjdk-8` and `openjdk-11` are skipped by name, as `eclipse-temurin:11` is (**inferred**: OpenJDK 8 and 11 have no decode intrinsic; Red Hat's builds were not read). Any other line in the name is not checked and pulled | lead; **inferred** |

## Advisory links

The detector's catalog entry links only pages someone on this work could read: the OpenJDK advisory and Oracle's CSPU (read by the
lead on 2026-11-17/18 after they were unreadable on 2026-11-17), the Calif advisory and the Semgrep post (read by the lead), the
OpenJDK fix commit and Amazon Corretto's changelog.

## How the detector uses this

- The version that decides is the one inside the libjvm (`<VM name> (<version>) for <os>-<cpu> JRE (<version>)`), read from the binary, with the
  `release` file as a second witness; the CPU architecture comes from the ELF, PE or Mach-O header.
- A packaged JDK (apk, dpkg, rpm) is judged by the same upstream version: no distribution has published a fixed package or a backport
  statement yet. Red Hat's fixed builds, once published, go into the Red Hat backport table, which overrides the libjvm's version.
- A GraalVM JDK is judged by its JDK version, but never fixed until a fixed GraalVM build is listed.
- Findings carry CVSS 8.1, the OpenJDK and Oracle score.
- No marker in the binary separates fixed from unfixed code: the stub is generated at run time by C++ code, and the fix only adds a compare
  and a branch to that generator. The stubs' names (`lookup_lo_base64`, `pack_vec_base64`, `join_0_1_base64`) do show that the AVX-512
  decode path is present, which is how a vendor backport into an older line is caught.
