# Java4Shell (CVE-2026-114938): what is known, and from where

Checked 2026-11-17. Every row names its source. "Not fixed yet" means the
source was read on that date and had no fixed release; it is not a guess
about the future. Rows marked **inferred** are reasoning from the sources,
not something a source states.

## The flaw

| Fact | Source |
| --- | --- |
| The fix is JDK-8393212 "Base64 optimization improvements", 4 added lines in `generate_base64_decodeBlock()` in `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`: before the final 1 to 63 byte fragment of the AVX-512 VBMI path, `cmpl(length, 4); jcc(less, L_bruteForce)` ("A padded Base64 tail shorter than one complete block is handled by Java"). Authored 2026-10-13 by Tobias Hartmann, reviewed by rhalade, mschoene (the OpenJDK vulnerability group's reviewers), chagedorn, rcastanedalo | openjdk/jdk commit [`5177a70b385c16f26ede191fdac7aaba0bed0f8b`](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b), pushed 2026-11-16 |
| What the unfixed code does with a 1 to 3 byte tail that ends in `=`: `output_size` is 0, `L_padding` decrements it to -1, `bzhiq(output_mask, -1, output_size)` with an index of 255 keeps all 64 mask bits, and the masked `evmovdqub` stores 64 bytes at `dest + dp`: a write of up to 64 bytes past the output the caller sized. Read from the stub, and observed (next row); no vendor source states the impact in words | same file, lines around `L_finalBit` and `L_padding` |
| **Observed** on an AMD EPYC 9B14 (Zen 4, with avx512f, avx512bw, avx512vbmi and bmi2), 2026-11-17: after C2 compiles the decoder, `Base64.getDecoder().decode(src, dst)` of a malformed input that ends in a 1 to 3 character fragment with `=` (for example 64 valid characters then `A=`) writes bytes into `dst` past the decoded output. Seen on Temurin 18.0.2.1, 20.0.2, 17.0.6, 17.0.21, 21.0.2, 21.0.13 and 25.0.5; not seen on Temurin 17.0.5 or on SapMachine 21.0.13.1 (the fixed release); not seen on 21.0.13 started with `-XX:-UseBASE64Intrinsics` or with `-XX:UseAVX=2`. On 17.0.x to 20 the input has to be longer than 128 bytes, on 21 and later longer than 31 bytes: the 17u stub enters the AVX-512 path only above 128 bytes (`cmpl(length, 128)`), the 21u stub above 31. With an output array sized by `decode(byte[])` the write goes past the array into the heap. The test program is not in this repository | local run, `eclipse-temurin` images and the SapMachine 21.0.13.1 tarball (sha256 `6cb4df18…949ae9`, matching the GitHub release asset digest) |
| CVE-2026-114938 is listed with CVSS 8.1, component hotspot/compiler, in Amazon Corretto's changelogs of 2026-11-17 | [corretto-17 CHANGELOG 17.0.21.1.2](https://github.com/corretto/corretto-17/blob/17.0.21.1.2/CHANGELOG.md), [corretto-21 21.0.13.1.2](https://github.com/corretto/corretto-21/blob/21.0.13.1.2/CHANGELOG.md), [corretto-25 25.0.5.1.2](https://github.com/corretto/corretto-25/blob/25.0.5.1.2/CHANGELOG.md), [corretto-27 27.0.1.1.4](https://github.com/corretto/corretto-27/blob/27.0.1.1.4/CHANGELOG.md) |
| CVE-2026-114938 is JDK-8393212. The Corretto changelogs list CVEs by component, not by JDK bug, and the OpenJDK advisory that states the mapping could not be read (HTTP 403 for the lead, unreachable here). The public writeups (lead's sources below) describe exactly the code 8393212 changes: the output mask computed from length and padding, `output_len` underflowing on a padding-only tail, `bzhiq(-1, output_len)` giving all ones and `evmovdqub` writing all 64 bytes. **Inferred from that match**, not stated by a source | Corretto changelogs; Calif and Semgrep writeups as relayed by the lead |
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
| Named Java4Shell, credited to Calif. CVSS 9.2 (Corretto's changelogs list 8.1; the detector reports 9.2, the discoverer's score) | [Calif advisory](https://calif.io/java4shell/), [Semgrep blog](https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability) |
| Trigger: 64 `A` then `=` (on 17: 128 `A` then `=`); a 65-byte input decoded into a 50-byte buffer is written 62 bytes past its end. Reached only after the intrinsic is JIT-compiled. Matches what was observed here (65 and 129 byte inputs) | same |
| Pre-authentication remote code execution shown on default configurations of Keycloak, Jira, Confluence, JFrog Artifactory, Jenkins and PingFederate; post-authentication on Kafka, Solr, Elasticsearch, Gerrit and Spinnaker; Struts and Spring Boot sample apps; and a client-side variant (a Java client opening TLS to a malicious server). Chain details withheld | same, and posts by Charles Carmakal (Mandiant) and Semgrep |
| Affected: OpenJDK 17.0.6 and later on x86-64 CPUs with avx512f, avx512bw, avx512vbmi and bmi2; ARM64 not affected; every distribution. Oracle Java SE builds named as affected: **8u511b33-perf**, 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 (for 8, only the Performance Pack build). The 8u-perf build carries a backport of the decoder; **no fixed 8u-perf version is known**. The detector reports a Java 8 VM library that carries the decoder's stubs as vulnerable up to update 511 and unknown above it | same; Oracle alert cspunov2026 (403 for the lead) |
| Oracle and OpenJDK released fixes on 2026-11-17 (Oracle alert "cspunov2026"); the lead had no fixed versions per line. They are established above from the OpenJDK repositories and vendor releases | lead |
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
| 17.0.21.0.2 / .0.3, 21.0.13.0.2 / .0.3, 25.0.5.0.2 / .0.3, 27.0.1.0.2 / .0.3 | **not fixed**: these October 2026 out-of-band releases carry CA changes only (8395142, 8395690) | -dev repo tags `jdk-*.0.3+*` |

## Vendors and distributions (2026-11-17, rechecked 2026-11-18)

| Vendor | Status | Source |
| --- | --- | --- |
| Amazon Corretto | fixed: 17.0.21.1.2, 21.0.13.1.2, 25.0.5.1.2, 27.0.1.1.4 (all 2026-11-17, each "Import jdk-…1+2/+4", CVE-2026-114938 listed). Corretto 8 and 11: no release after October (not affected). **Docker Hub, 2026-11-18:** Amazon republished the existing `amazoncorretto:21.0.13-*` and `17.0.21-*` tags with the fixed builds (the images report 21.0.13.1+2 and 17.0.21.1+2); there are no `.1` tags. A Corretto tag of the fixed update therefore names whichever build was pushed last, and the detector reads the image | GitHub releases API, CHANGELOG.md of each tag; images scanned by this detector (parity cases corretto-*) |
| SapMachine | releases 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 published 2026-11-17 (the release page names no CVE) | GitHub releases API, SAP/SapMachine |
| Eclipse Temurin | **not fixed yet**: no `jdk-17.0.21.1+2`, `jdk-21.0.13.1+2`, `jdk-25.0.5.1+2` or `jdk-27.0.1.1+4` release in adoptium/temurinNN-binaries; Docker Hub `eclipse-temurin` newest tags are 17.0.21_9, 21.0.13_9, 25.0.5_8, 27.0.1.0 | GitHub API, registry-1.docker.io tag list |
| Azul Zulu, BellSoft Liberica, Microsoft, Oracle | **not checked**: their sites could not be reached from the research host. Docker Hub `azul/zulu-openjdk` and `bellsoft/liberica-openjdk-debian` newest tags are 27.0.1.0.3 / 21.0.13.0.3 (not fixed) | registry-1.docker.io tag list |
| IBM Semeru | OpenJ9, not HotSpot (see above) | image inspection |
| Debian | **not fixed yet**: newest sources openjdk-17 17.0.21.0.3+1-1, openjdk-21 21.0.13.0.3+1-1, openjdk-25 25.0.5.0.3+1-3; security.debian.org 17.0.21+9-1~deb12u1, 21.0.13+9-1~deb13u2, 25.0.5+8-1~deb13u1. The security tracker has no page for CVE-2026-114938 | deb.debian.org and security.debian.org pools, security-tracker.debian.org |
| Ubuntu | **not fixed yet**: newest sources openjdk-17 17.0.21.0.3+1-1~XX.04.1, openjdk-25 25.0.5.0.3+1-3~XX.04.1 (openjdk-21 listing timed out) | archive.ubuntu.com pool |
| Alpine | **not fixed yet**: community openjdk17 17.0.21.0.3_p1-r0, openjdk21 21.0.13.0.3_p1-r0, openjdk25 25.0.5.0.3_p1-r0/-r1 (3.23, 3.24, edge); 3.21 and 3.22 carry older 17/21 | dl-cdn.alpinelinux.org APKINDEX |
| Red Hat (RHEL, UBI) | **not checked**: access.redhat.com and registry.access.redhat.com unreachable | n/a |

## Advisory links

The detector's catalog entry links only pages someone on this work could read: the Calif advisory and the Semgrep post (read by
the lead), the OpenJDK fix commit and Amazon Corretto's changelog. **Not read by anyone (HTTP 403 or unreachable):** the OpenJDK
advisory https://openjdk.org/groups/vulnerability/advisories/2026-11-17 and Oracle's alert
https://www.oracle.com/security-alerts/cspunov2026.html; they are listed here only.

## How the detector uses this

- The version that decides is the one inside the libjvm (`<VM name> (<version>) for <os>-<cpu> JRE (<version>)`), read from the binary, with the
  `release` file as a second witness; the CPU architecture comes from the ELF, PE or Mach-O header.
- A packaged JDK (apk, dpkg, rpm) is judged by the same upstream version: no distribution has published a fixed package or a backport
  statement yet. When one does, its fixed package version goes into the knowledge table.
- No marker in the binary separates fixed from unfixed code: the stub is generated at run time by C++ code, and the fix only adds a compare
  and a branch to that generator. The stubs' names (`lookup_lo_base64`, `pack_vec_base64`, `join_0_1_base64`) do show that the AVX-512
  decode path is present, which is how a vendor backport into an older line is caught.
