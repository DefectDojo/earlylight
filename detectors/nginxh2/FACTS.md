# nginx HTTP/2 RCE pair (CVE-2026-123007, CVE-2026-123633): what is known, and from where

Checked 2026-11-18. Every row names its source. "Not fixed yet" means the source was read on that date and had no
fixed release; it is not a guess about the future. Rows marked **inferred** are reasoning from the sources, not
something a source states. Rows marked **lead** were read by the lead in a browser and relayed: the research host
cannot reach nginx.org, wiz.io, my.f5.com, access.redhat.com, ubuntu.com, openresty.org, angie.software,
registry.k8s.io, ghcr.io or quay.io.

## The advisories (lead, 2026-11-18)

| Fact | Source |
| --- | --- |
| Coordinated disclosure on 2026-11-18 with the F5 release. Wiz scores both CVEs CVSS 4.0 **9.2**; the detector reports 9.2 | [Wiz, "Unauthenticated Remote Code Execution in NGINX: CVE-2026-123633 and CVE-2026-123007"](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities) (lead) |
| **CVE-2026-123007**, "Memory corruption in HTTP/2 flow control", nginx.org severity major. Vulnerable **1.9.5 to 1.31.8**; not vulnerable **1.31.9+, 1.30.7+**. Credit Xint.io | [nginx.org security advisories](https://nginx.org/en/security_advisories.html), [F5 K000163926](https://my.f5.com/manage/s/article/K000163926) (lead) |
| **CVE-2026-123633**, "Use-after-free in HTTP/2", nginx.org severity medium. Vulnerable **1.19.7 to 1.31.8**; not vulnerable **1.31.9+, 1.30.7+**. Credit Albert of Vexera AI | nginx.org security advisories, [F5 K000163928](https://my.f5.com/manage/s/article/K000163928) (lead) |
| NGINX Plus: affected from R33 and 37.0.0; fixed **37.0.7.1 and 37.2.0.1** (CVE-2026-123633), **37.0.8.1 and 37.3.0.1** (CVE-2026-123007) | F5 K000163926, K000163928 (lead) |
| CVE-2026-123007 preconditions: HTTP/2 on, over TLS, a 64-bit build; plain static files reach it, no proxy or module needed. Wiz showed pre-authentication RCE with an ASLR bypass on the official 1.31.7 and 1.31.8 builds. No PoC released | Wiz (lead) |
| CVE-2026-123633 preconditions: HTTP/2 on, a reverse-proxy configuration, worker_connections nearly exhausted | Wiz (lead) |
| Interim mitigation, not a fix: turn HTTP/2 off (`http2 off;` from 1.25.1, and remove `http2` from every `listen`) | nginx.org, Wiz (lead) |
| Wiz detection hints: version check, HTTP/2 on in the config, worker crashes, long-lived HTTP/2 connections with many WINDOW_UPDATE frames. **No binary indicator or IOC** was published | Wiz (lead) |
| The same 1.31.9 / 1.30.7 releases also fix CVE-2026-121810 (HTTP/3), CVE-2026-123634 (resolver), CVE-2026-113425 (mail), CVE-2026-118899, CVE-2026-125283, CVE-2026-120967, CVE-2026-120993 and CVE-2026-123640. They are not this detector's | nginx.org (lead) |

## The fixes in the nginx source (github.com/nginx/nginx, read here)

| Fact | Source |
| --- | --- |
| CVE-2026-123007 fix: "HTTP/2: account for queued frames when validating WINDOW_UPDATE" (Roman Arutyunyan, 2026-10-29, "Reported by Xint.io"). Adds `h2c->send_queued`, counts queued DATA frames in it, and checks `window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window - h2c->send_queued` | [`e27f5fa84`](https://github.com/nginx/nginx/commit/e27f5fa84fe6e98505e70bc543b748747dad0a3b) on 1.31 (`release-1.31.9`), [`b89c4100b`](https://github.com/nginx/nginx/commit/b89c4100bf6762a45e4a6463eaf4b70368277c94) on `stable-1.30` (`release-1.30.7`) |
| CVE-2026-123633 fix: "HTTP/2: reset reusable connection status on stream creation" (Roman Arutyunyan, 2026-09-17, "Reported by Albert @ Vexera AI"): `ngx_reusable_connection(h2c->connection, 0)` in `ngx_http_v2_create_stream()`. The commit names the cause as 76672e650 ("HTTP/2: reuse of connections with incomplete frames", 2021-02-11), first released in **1.19.7** | [`2df48a501`](https://github.com/nginx/nginx/commit/2df48a501d0fb8212b7d39dffeeff5876332ba59) (1.31), [`0c87dd1db`](https://github.com/nginx/nginx/commit/0c87dd1db413e440a4e3ef7ee8acc518509e8809) (`stable-1.30`); `git tag --contains 76672e650` starts at `release-1.19.7` |
| HTTP/2 came in **1.9.5** ("The HTTP/2 implementation", ee37ff613, 2015-09-11; first tag `release-1.9.5`) | nginx/nginx history |
| Tags: `release-1.31.9` (c2c44702c, tagged 2026-11-06), `release-1.30.7` (2df4366ef, tagged 2026-11-11). The mainline branch was bumped to 1.31.10 on 2026-11-18 | nginx/nginx tags |
| **No binary marker.** The 123633 fix adds one call and no string; the 123007 fix changes a comparison and the arguments of an existing log message whose format string stays the same. A fixed build differs from an unfixed one of the same version in code only | the two diffs above |
| A build from the source tree between the "Version bump" to 1.31.9 (2026-10-22) and the fix commits also reports 1.31.9 without the fixes; release tarballs and packages do not. The detector takes a version string as the release's | nginx/nginx history; **inferred** |
| HTTP/2 is compiled in only with `./configure --with-http_v2_module` (it cannot be a dynamic module); a build that has it lists `ngx_http_v2_module` in its module names and in its configure arguments | `auto/options`, `auto/modules` |
| HTTP/2 is on for a connection when the listening socket has the `http2` parameter (deprecated, still honoured) or the server's `http2` directive is on (from **1.25.1**, aefd862ab). With TLS it is chosen by ALPN; without TLS by the client's HTTP/2 preface (prior knowledge) | `ngx_http_init_connection()` and `ngx_http_ssl_handshake_handler()` in `src/http/ngx_http_request.c` at `release-1.31.9` |
| The `ssl on;` directive (TLS on every listener of the server) was removed in **1.25.1** (d32f66f1e); before, it made a server's plain `listen` lines TLS | nginx/nginx history |

## How a binary says what it is (read from real binaries here)

| Build | What the binary carries | Source |
| --- | --- | --- |
| nginx (official image, nginx.org package) | `nginx version: nginx/1.31.8`, `nginx/1.31.8`, `configure arguments: --prefix=/etc/nginx ... --with-http_v2_module ...`, `ngx_http_v2_module`, help text `set configuration file (default: /etc/nginx/nginx.conf)` | `nginx:1.31.8` (index sha256:165ddde8751e…6aff76d82), `nginx:1.31.9` (index sha256:a7087e95bd21…8fb3581c), linux/amd64 |
| Debian | `nginx version: nginx/1.22.1`, prefix `/usr/share/nginx/`, conf `/etc/nginx/nginx.conf`; dpkg `nginx 1.22.1-9+deb12u10` owns `/usr/sbin/nginx` | `debian:12` + `apt-get install nginx`, 2026-11-18 |
| Ubuntu | `nginx version: nginx/1.24.0 (Ubuntu)` (built with `--build=Ubuntu`); dpkg `nginx 1.24.0-2ubuntu7.19` | `ubuntu:24.04` + `apt-get install nginx` |
| Alpine | `nginx version: nginx/1.30.6`, prefix `/var/lib/nginx/`; apk `nginx 1.30.6-r0` | `alpine:3.24` + `apk add nginx` |
| OpenResty | `nginx version: openresty/1.31.8.1`, `openresty/1.31.8.1`, the core `1.31.8` as its own string, prefix `/usr/local/openresty/nginx/` | `openresty/openresty:1.31.8.1-alpine` (sha256:fec9da11e7a9…4959b943) |
| Tengine | `Tengine version: Tengine/3.2.0` and `nginx version: nginx/1.31.5` (`TENGINE_VER_BUILD`, `NGINX_VER_BUILD`) | alibaba/tengine `src/core/nginx.c`, `nginx.h` (master, 2026-09-07) |
| Angie | `Angie version: Angie/1.13.0` and, for `-V`, `nginx version: nginx/1.31.3`: a compatibility number, not the code Angie carries | webserver-llc/angie `src/core/nginx.c`, `angie.h`, `nginx.h` (master, 2026-11-13) |
| NGINX Plus | `nginx version: nginx/1.x.y (nginx-plus-rNN)`, with `-pN` for a patch release. **Unverified here**: no Plus binary could be read, and how the 37.x.y.z numbers appear in a binary is not known | F5 naming convention; **unverified** |

## Fixed releases and downstream status (2026-11-18)

| Vendor / package | Status | Source |
| --- | --- | --- |
| nginx (upstream) | fixed in **1.31.9** (mainline) and **1.30.7** (stable). Lines 1.29 and older received no fix | tags above; nginx.org (lead) |
| nginx.org packages | `1.31.9-1~trixie` and `1.30.7-1~trixie` (Debian), `1.31.9-r1` / `1.30.7-r1` (Alpine) are what the official images install. nginx.org's package pages could not be read here | [nginx/docker-nginx](https://github.com/nginx/docker-nginx) `mainline/debian/Dockerfile`, `stable/alpine-slim/Dockerfile` at `a2a986d19a` (2026-11-18 16:17 UTC) |
| Docker official `nginx` | tags **1.31.9** and **1.30.7** exist with every variant of the line: (none), `-perl`, `-otel`, `-trixie`, `-trixie-perl`, `-trixie-otel`, `-alpine`, `-alpine-slim`, `-alpine-perl`, `-alpine-otel`, `-alpine3.24`, `-alpine3.24-slim`, `-alpine3.24-perl`, `-alpine3.24-otel`. The 1.30 and 1.31 lines have no `-bookworm` tags (1.29 and older do; they received no fix). **Observed 17:04 UTC:** `1.31.9` and `1.30.7` held linux/amd64 and linux/arm64 only (mainline, still 1.31.8-era, holds eight platforms), and `1.31.9-alpine`, `1.30.7-alpine` were empty indexes: the images were still being published. `fix` therefore checks that the target tag has every platform the current one has | registry-1.docker.io tag list and manifests, 2026-11-18 |
| nginxinc/nginx-unprivileged | **not fixed on Docker Hub** at 16:50 UTC (newest tag 1.31.7); the GitHub repository moved to 1.31.9 / 1.30.7 at 16:37 UTC, so the tags are expected (expected, not a fact) | registry tag list; [nginx/docker-nginx-unprivileged](https://github.com/nginx/docker-nginx-unprivileged) `bef9cb1f0c` |
| bitnami/nginx | only `latest` is public (Bitnami moved versioned tags out in 2025); `bitnamilegacy/nginx` stops at **1.29.1** and will receive no fix | registry tag lists |
| Debian | **not fixed**: the tracker lists nginx vulnerable and unfixed in bookworm (1.22.1-9+deb12u9, security 1.22.1-9+deb12u10), trixie (1.26.3-3+deb13u7, security 1.26.3-3+deb13u10), forky and sid (1.30.6-3), for both CVEs. bullseye (1.18.0-6.1+deb11u3) is not listed | [security-tracker.debian.org CVE-2026-123007](https://security-tracker.debian.org/tracker/CVE-2026-123007), [CVE-2026-123633](https://security-tracker.debian.org/tracker/CVE-2026-123633); deb.debian.org and security.debian.org pools |
| Ubuntu | **not fixed**: the newest sources are jammy 1.18.0-6ubuntu14.22, noble 1.24.0-2ubuntu7.19, questing 1.28.0-6ubuntu1.8, resolute 1.28.3-2ubuntu1.12, stonking 1.30.4-7ubuntu1.1 (security uploads of 2026-10-24 and 2026-06-19) and the development release 1.30.6-3ubuntu1 (2026-11-06); no changelog names either CVE. The Ubuntu CVE pages could not be read | archive.ubuntu.com pool, `debian/changelog` of each |
| Alpine | **not fixed**: main/nginx is 3.24 1.30.6-r0, edge 1.30.6-r1 (2026-11-08), 3.22 and 3.23 1.28.3-r7, 3.21 1.26.3-r3; the APKBUILD `secfixes` of every branch name neither CVE | dl-cdn.alpinelinux.org APKINDEX; alpinelinux/aports `main/nginx/APKBUILD` (GitHub mirror) |
| Red Hat (RHEL nginx module streams, UBI) | **not read**: access.redhat.com is unreachable from the research host and the fetch tool failed. The detector judges a Red Hat build by its version: vulnerable in range until a fixed build is known | n/a |
| OpenResty | **not fixed**: newest release 1.31.8.1 bundles nginx 1.31.8; its master (2026-11-07) carries `nginx-1.31.8-*.patch` files and none for these CVEs. OpenResty does backport nginx CVE fixes as patches without a new core (`nginx-1.31.8-CVE-2026-9256.patch`) | [openresty/openresty](https://github.com/openresty/openresty) `util/ver`, `patches/nginx/1.31.8`; Docker Hub `openresty/openresty` tags (newest 1.31.8.1) |
| Tengine | **not fixed**: newest 3.2.0-rc5 (2026-09-04), nginx core 1.31.5; master's `ngx_http_v2.c` has the unfixed WINDOW_UPDATE check and the `ngx_reusable_connection(c, 1)` with `h2c->state.incomplete` that 76672e650 added | [alibaba/tengine](https://github.com/alibaba/tengine) master; **inferred** affected from the source |
| Angie | **not fixed**: newest 1.12.4 (2026-10-16); master (2026-11-13, 1.13.0) has the same unfixed code | [webserver-llc/angie](https://github.com/webserver-llc/angie) master; **inferred** affected from the source |
| Kubernetes ingress-nginx | **no fix, ever**: the project was archived on 2026-03-23; last releases controller v1.15.1, v1.14.5, v1.13.9 (2026-03-19). Their build scripts use nginx **1.27.1**; v1.11 and v1.12 used 1.25.5, v1.5 to v1.10 1.21.6, v1.0.0 1.20.1 (all in both ranges). The chart turns HTTP/2 on by default (`use-http2: true`) and always proxies | kubernetes/ingress-nginx `images/nginx/rootfs/build.sh` and `NGINX_BASE` at each tag, `internal/ingress/controller/config/config.go` (`UseHTTP2: true`, `MaxWorkerConnections: 16384`) at v1.15.1. Built image versions **inferred** from the build scripts |
| F5 NGINX Ingress Controller (`nginx/nginx-ingress`) | **5.8.0** (2026-11-18) builds on nginx **1.31.9** and Plus R37.3; 5.7.1 used 1.31.8 | nginx/kubernetes-ingress `build/Dockerfile` (`ARG NGINX_OSS_VERSION`) at v5.8.0 and v5.7.1 |
| Traefik, Caddy, Envoy, HAProxy | not nginx: out of scope | n/a |

## Backports (a fixed package that keeps the nginx version)

| Downstream | Backports nginx security fixes without a new nginx version? | Source |
| --- | --- | --- |
| Debian | yes (`+debNNuN` releases carry patches) | Debian changelogs |
| Ubuntu | yes (`debian/patches/CVE-*.patch`, `ubuntuN.M` releases) | Ubuntu changelogs above |
| Alpine | yes (`secfixes` on `-rN` releases of the same version, such as 1.28.3-r6) | APKBUILD above |
| Red Hat | yes for other CVEs (module stream builds keep their upstream version); status for these CVEs not read | Red Hat convention; **not verified here** |
| OpenResty | yes (`nginx-<core>-CVE-*.patch`) | openresty/openresty patches |
| nginx.org, the Docker official image | no: they ship the fixed upstream release | docker-nginx |

The detector keeps a backport table (`knowledge.Backports`): distribution, release, source package, fixed version,
advisory. It is **empty**: no distribution had published a fixed package on 2026-11-18. A row clears a binary only
when the binary's own version is the upstream version of that package and the package database names it the owner
of the binary.

## How the detector uses this

- The version that decides is the one in the binary's `nginx version:` line (or `Angie version:`, `Tengine version:`);
  every other `nginx/x.y.z` string in it must agree, or the binary is unknown. A version from a package database, a
  file name or an image tag never clears a binary on its own.
- A build without a readable version (renamed, `server_tokens`-patched or stripped of the line) is unknown, never
  cleared. A build without HTTP/2 (no `ngx_http_v2_module` and no `--with-http_v2_module` in readable configure
  arguments) is not affected; one whose configure arguments cannot be read is not cleared on that ground.
- Each CVE is judged on its own: a binary below 1.19.7 can be vulnerable to CVE-2026-123007 and not affected by
  CVE-2026-123633.
- OpenResty is judged by its nginx core (the first three numbers of its version): a core at or past a fixed release
  is fixed; an OpenResty release newer than the newest known one (1.31.8.1) on an unfixed core is unknown, since
  OpenResty backports as patches. Tengine and Angie: releases up to the newest known (3.2.0, 1.12.4) are vulnerable,
  later ones unknown; Angie's `nginx/` compatibility number is never used. NGINX Plus is judged by its own release.
- The configuration decides **exposure**, never the verdict: HTTP/2 off everywhere is reported as "not exposed" on a
  finding that stays vulnerable, because the binary still needs the update. An include that cannot be read, a
  configuration generated at start (ingress-nginx) or not found makes exposure unknown, not off.
- Findings carry CVSS 9.2 (Wiz). A 32-bit build, HTTP/2 without TLS (CVE-2026-123007) and HTTP/2 without a proxy
  directive (CVE-2026-123633) are reported as facts that weaken the published exploit path; none clears a finding.
