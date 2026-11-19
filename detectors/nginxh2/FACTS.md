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
| nginx CHANGES for 1.31.9 is dated 18 Nov 2026 and credits Xint.io (CVE-2026-123007) and Albert of Vexera AI (CVE-2026-123633) | [nginx CHANGES](https://nginx.org/en/CHANGES) (lead, 2026-11-18) |
| **CVE-2026-123633**, "Use-after-free in HTTP/2", nginx.org severity medium. Vulnerable **1.19.7 to 1.31.8**; not vulnerable **1.31.9+, 1.30.7+**. Credit Albert of Vexera AI | nginx.org security advisories, [F5 K000163928](https://my.f5.com/manage/s/article/K000163928) (lead) |
| Red Hat scores CVE-2026-123007 CVSS 3.1 **8.1** (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H), CWE-787, Bugzilla 2575895, and lists no fixed products, NVRs or errata. Red Hat's page for CVE-2026-123633 returned 404 | [access.redhat.com CVE-2026-123007](https://access.redhat.com/security/cve/CVE-2026-123007), [CVE-2026-123633](https://access.redhat.com/security/cve/CVE-2026-123633) (lead, 2026-11-18) |
| Ubuntu gives CVE-2026-123007 priority **High**: vulnerable on 26.10, 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS, 18.04 LTS and 16.04 LTS, not affected on 14.04 (nginx 1.4.6, no HTTP/2); no fixed versions | [ubuntu.com/security CVE-2026-123007](https://ubuntu.com/security/CVE-2026-123007) (lead, 2026-11-18) |
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
| Docker official `nginx` | **fixed**: tags **1.31.9** and **1.30.7** exist with every variant of the line: (none), `-perl`, `-otel`, `-trixie`, `-trixie-perl`, `-trixie-otel`, `-alpine`, `-alpine-slim`, `-alpine-perl`, `-alpine-otel`, `-alpine3.24`, `-alpine3.24-slim`, `-alpine3.24-perl`, `-alpine3.24-otel`. The 1.30 and 1.31 lines have no `-bookworm` tags (1.29 and older do; they received no fix). **Observed 17:04 UTC:** `1.31.9` and `1.30.7` held linux/amd64 and linux/arm64 only (mainline, still 1.31.8-era, holds eight platforms), and `1.31.9-alpine`, `1.30.7-alpine` were empty indexes: the images were still being published. **17:40 UTC:** `1.31.9` and `1.30.7` had seven platforms but no linux/riscv64 (which `1.31.8` has); `1.30.7-alpine` had amd64, arm, arm64 and s390x but no linux/386. `fix` therefore checks that the target tag has every platform the tree builds (`--platform`), or else every platform the current tag has | registry-1.docker.io tag list and manifests, 2026-11-18 |
| nginxinc/nginx-unprivileged | **not fixed on Docker Hub** at 16:50 UTC (newest tag 1.31.7); the GitHub repository moved to 1.31.9 / 1.30.7 at 16:37 UTC, so the tags are expected (expected, not a fact) | registry tag list; [nginx/docker-nginx-unprivileged](https://github.com/nginx/docker-nginx-unprivileged) `bef9cb1f0c` |
| bitnami/nginx | only `latest` is public (Bitnami moved versioned tags out in 2025); `bitnamilegacy/nginx` stops at **1.29.1** and will receive no fix | registry tag lists |
| Debian | **not fixed** (rechecked 17:47 UTC): the tracker lists nginx vulnerable and unfixed in bookworm (1.22.1-9+deb12u9, security 1.22.1-9+deb12u10), trixie (1.26.3-3+deb13u7, security 1.26.3-3+deb13u10), forky and sid (1.30.6-3), for both CVEs. bullseye (1.18.0-6.1+deb11u3) is not listed. No DSA or DLA (lead, CVE-2026-123007 page, 2026-11-18) | [security-tracker.debian.org CVE-2026-123007](https://security-tracker.debian.org/tracker/CVE-2026-123007), [CVE-2026-123633](https://security-tracker.debian.org/tracker/CVE-2026-123633); deb.debian.org and security.debian.org pools |
| Ubuntu | **not fixed** (rechecked 17:47 UTC): the newest sources are jammy 1.18.0-6ubuntu14.22, noble 1.24.0-2ubuntu7.19, questing 1.28.0-6ubuntu1.8, resolute 1.28.3-2ubuntu1.12, stonking 1.30.4-7ubuntu1.1 (security uploads of 2026-10-24 and 2026-06-19) and the development release 1.30.6-3ubuntu1 (2026-11-06); no changelog names either CVE. Ubuntu's CVE-2026-123007 page lists 26.10, 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS, 18.04 LTS and 16.04 LTS as vulnerable with no fixed versions, and 14.04 (nginx 1.4.6) as not affected (lead) | archive.ubuntu.com pool, `debian/changelog` of each; [ubuntu.com/security CVE-2026-123007](https://ubuntu.com/security/CVE-2026-123007) (lead, 2026-11-18) |
| Alpine | **fixed on 3.24 and edge**: main/nginx **1.30.7-r0**, published 2026-11-18 17:06 UTC (v3.24) and 17:11 UTC (edge), an upgrade to the fixed upstream release (aports master and 3.24-stable `pkgver=1.30.7`). **Not fixed** on 3.23 and 3.22 (1.28.3-r7) or 3.21 (1.26.3-r3) at 17:47 UTC; their APKBUILD `secfixes` name neither CVE. (At 16:50 UTC every branch was still unfixed: 3.24 1.30.6-r0, edge 1.30.6-r1.) | dl-cdn.alpinelinux.org APKINDEX (rechecked 17:47 UTC); alpinelinux/aports `main/nginx/APKBUILD` (GitHub mirror) |
| Red Hat (RHEL nginx module streams, UBI) | **not fixed**: Red Hat's CVE-2026-123007 page lists no fixed products, NVRs or errata (CVSS 3.1 8.1, Bugzilla 2575895); its CVE-2026-123633 page returned 404. The detector judges a Red Hat build by its version: vulnerable in range until a fixed build is known | [access.redhat.com CVE-2026-123007](https://access.redhat.com/security/cve/CVE-2026-123007) (lead, 2026-11-18) |
| OpenResty | **not fixed**: newest release 1.31.8.1 bundles nginx 1.31.8; its master (2026-11-07) carries `nginx-1.31.8-*.patch` files and none for these CVEs. OpenResty does backport nginx CVE fixes as patches without a new core (`nginx-1.31.8-CVE-2026-9256.patch`) | [openresty/openresty](https://github.com/openresty/openresty) `util/ver`, `patches/nginx/1.31.8`; Docker Hub `openresty/openresty` tags (newest 1.31.8.1) |
| Tengine | **not fixed**: newest 3.2.0-rc5 (2026-09-04), nginx core 1.31.5; master's `ngx_http_v2.c` has the unfixed WINDOW_UPDATE check and the `ngx_reusable_connection(c, 1)` with `h2c->state.incomplete` that 76672e650 added | [alibaba/tengine](https://github.com/alibaba/tengine) master; **inferred** affected from the source |
| Angie | **not fixed**: newest 1.12.4 (2026-10-16); master (2026-11-13, 1.13.0) has the same unfixed code | [webserver-llc/angie](https://github.com/webserver-llc/angie) master; **inferred** affected from the source |
| Kubernetes ingress-nginx | **no fix, ever**: the project was archived on 2026-03-23; last releases controller v1.15.1, v1.14.5, v1.13.9 (2026-03-19). Their build scripts use nginx **1.27.1**; v1.11 and v1.12 used 1.25.5, v1.5 to v1.10 1.21.6, v1.0.0 1.20.1 (all in both ranges). The chart turns HTTP/2 on by default (`use-http2: true`) and always proxies | kubernetes/ingress-nginx `images/nginx/rootfs/build.sh` and `NGINX_BASE` at each tag, `internal/ingress/controller/config/config.go` (`UseHTTP2: true`, `MaxWorkerConnections: 16384`) at v1.15.1. Built image versions **inferred** from the build scripts |
| F5 NGINX Ingress Controller (`nginx/nginx-ingress`) | **5.8.0** (2026-11-18) builds on nginx **1.31.9** and Plus R37.3; 5.7.1 used 1.31.8. The images' binaries read 1.31.9 and 1.31.8 (parity cases f5-ingress-5.8.0, f5-ingress-5.7.1). The controller writes nginx.conf at start; its ConfigMap key `http2` decides HTTP/2 | nginx/kubernetes-ingress `build/Dockerfile` (`ARG NGINX_OSS_VERSION`) at v5.8.0 and v5.7.1; `nginx/nginx-ingress:5.8.0` sha256:57705208dfa8…6fec37aa, `5.7.1` sha256:b6a970b8fccb…80bb6b480 |
| Traefik, Caddy, Envoy, HAProxy | not nginx: out of scope | n/a |

## Backports (a fixed package that keeps the nginx version)

| Downstream | Backports nginx security fixes without a new nginx version? | Source |
| --- | --- | --- |
| Debian | yes (`+debNNuN` releases carry patches) | Debian changelogs |
| Ubuntu | yes (`debian/patches/CVE-*.patch`, `ubuntuN.M` releases) | Ubuntu changelogs above |
| Alpine | yes (`secfixes` on `-rN` releases of the same version, such as 1.28.3-r6) | APKBUILD above |
| Red Hat | yes for other CVEs (module stream builds keep their upstream version); no fix listed for CVE-2026-123007 on 2026-11-18, and no page for CVE-2026-123633 | Red Hat convention, **not verified here**; Red Hat CVE page (lead) |
| OpenResty | yes (`nginx-<core>-CVE-*.patch`) | openresty/openresty patches |
| nginx.org, the Docker official image | no: they ship the fixed upstream release | docker-nginx |

The detector keeps a backport table (`knowledge.Backports`): distribution, release, source package, fixed version,
advisory. It is **empty**: no distribution had published a backported fix on 2026-11-18 (Alpine's fix is the new
upstream release, which the binary's own version shows; `knowledge.AlpineFixed` lists it for the source-tree scan). A row clears a binary only
when the binary's own version is the upstream version of that package and the package database names it the owner
of the binary.

## How the detector uses this

- The version that decides is the one in the binary's `nginx version:` line (or `Angie version:`, `Tengine version:`);
  every other `nginx/x.y.z` string in it must agree, or the binary is unknown. A version from a package database, a
  file name or an image tag never clears a binary on its own. A version on a line newer than any known on the check
  date (above 1.31; above 37.3 for NGINX Plus's numbered releases) is unknown, never fixed: NGINX Plus now numbers
  its releases 37.x, and how they appear in a binary is not verified.
- A build without a readable version (renamed, `server_tokens`-patched or stripped of the line) is unknown, never
  cleared. A build is not affected for lack of HTTP/2 only when its configure arguments were read to their end and its
  module list (1.9.11 and later) is present, and neither has HTTP/2; a cut or missing witness leaves it unknown.
  HTTP/2 compiled into a core older than nginx's own (1.9.5) is a vendor backport: unknown (also when the witness of
  HTTP/2 is cut or missing on a Tengine or NGINX Plus build on such a core), except Tengine 2.1.2 to
  2.2.x (cores 1.6.2 and 1.8.1), whose source carries nginx's unfixed flow-control code and predates the reuse change
  (alibaba/tengine `src/http/v2` at `tengine-2.1.2` and `tengine-2.2.2`; the change reached Tengine in 2.4.0).
- Each CVE is judged on its own: a binary below 1.19.7 can be vulnerable to CVE-2026-123007 and not affected by
  CVE-2026-123633.
- OpenResty is judged by its nginx core (the first three numbers of its version): a core at or past a fixed release
  is fixed; an OpenResty release newer than the newest known one (1.31.8.1) on an unfixed core is unknown, since
  OpenResty backports as patches. Tengine and Angie: releases up to the newest known (3.2.0-rc5, 1.12.4) are
  vulnerable, later ones unknown; Angie's `nginx/` compatibility number is never used. NGINX Plus is judged by its own
  release.
- The configuration decides **exposure**, never the verdict: HTTP/2 off everywhere is reported as "not exposed" on a
  finding that stays vulnerable, because the binary still needs the update.
- Exposure reads "not exposed" only when all of this holds; anything else is unknown:
  - the command that starts nginx was read, and its nginx word resolves, by path and content the scan read, to the
    very binary judged (a relative path against the image's working directory, a bare name through its `PATH`, a
    `PATH` search stopping at a link as the runtime does); a base name alone is never trusted, and a binary the
    command does not start (`nginx-debug` in the official images) is unknown, or exposed when what it would load
    turns HTTP/2 on. Any word before nginx
    other than the official entrypoint is unknown: `tini`, `dumb-init`, `env` (with its `PATH` or `--chdir`), `exec`,
    `sh -c` and custom scripts included;
  - the official entrypoint is recognised by SHA-256 (every version in nginx/docker-nginx and
    docker-nginx-unprivileged), is given `nginx` or `nginx-debug` as its first argument, and every file reachable in
    `/docker-entrypoint.d` (any name, extension or size, with or without `#!`, through any link) was read and is that
    name's official script; a link out of the directory, or a file not read, is unknown. The templates are applied
    only then, as `20-envsubst-on-templates.sh` applies them, and only from a template directory the scan reads
    whole; `NGINX_ENVSUBST_FILTER` is unknown;
  - on a host, the command is the `ExecStart` of the systemd unit that runs that binary: the unit of the first
    directory that has it (`/etc`, `/run`, `/lib`, `/usr/lib`), links followed, every drop-in applied, read from disk
    below a system root. Its `Environment=` and `EnvironmentFile=` are read for the plain forms only (nginx.org's
    pkg-oss unit starts `nginx -c ${conffile} $cmdopts`): a specifier (`%`), a glob in an `EnvironmentFile=` path, a
    continued line, an environment file line with `export`, an escape, a variable or an inner quote, an environment
    file that is there but not read, more than one `ExecStart=`, an `@`, `|` or `:` prefix, and `PassEnvironment=`,
    `UnsetEnvironment=`, `RootDirectory=`, `RootImage=`, `MountImages=`, `ExtensionImages=`,
    `ExtensionDirectories=`, `BindPaths=`, `BindReadOnlyPaths=` or `TemporaryFileSystem=` are unknown. A variable
    the unit does not set is empty only when the manager's `system.conf` and its drop-ins were read and set no
    `DefaultEnvironment=` or `ManagerEnvironment=`, and no environment generator is installed; the kernel command
    line (`systemd.setenv=`) is not read. A unit, drop-in, unit directory or environment file not read is unknown.
    `ExecStartPre`, `ExecStartPost` and `ExecCondition` (each its own list) may only run `/bin/rm` or `/usr/bin/rm -f`
    of the pid file, or a test by the very binary `ExecStart` runs;
  - nginx's own option parsing is followed (`-qc file`, `-p`, `-g` whose includes are loaded); a command that only
    tests, shows or signals (`-t`, `-T`, `-v`, `-V`, `-s`, `-h`) serves nothing;
  - an include the walk could not read (the engine's not-scanned records), one that is not kept, a glob the scan does
    not read whole, a configuration generated at start (ingress-nginx, the F5 controller), a template variable left
    unset in `listen`, in `http2` or standing for a whole directive (not inside `map`, `geo`, `split_clients`,
    `types` or `charset_map`, whose keys may hold `$`), or more than the loader's budget across all includes
    (2 Mi tokens, 16 MiB; reading stops there) is unknown;
  - in a source tree, an image read from its registry under a deployment that sets its command, arguments,
    environment or mounts is unknown: a Compose service (with its override files, `extends` and `volumes_from`), a
    Kubernetes container, a GitLab CI service, Helm values whose chart templates (in any subdirectory) set them or are
    not in the tree, and a Dockerfile that builds on the image through any chain of stage aliases. What the tree
    cannot show is not checked either way: a Compose file merged only with `-f` (`docker-compose.prod.yml`) is not
    known to apply to a service, and a GitHub Actions service's `volumes` are not read, so an image read under those
    reports its own exposure.
- The configuration read is the one nginx loads: the compiled-in path (a relative one moved by `-p`), or the command's
  `-c`; the official image's templates with the image's environment put in as its entrypoint does, when it runs
  them. Globs follow glob(3) (`[!x]`, `[[:digit:]]`, no leading dots); symbolic and hard links are followed inside the
  target. Below a system root a glob is read from disk: a link that is matched is kept and followed, a linked
  directory on the way, or a directory that cannot be listed (`EACCES`), leaves it incomplete, so exposure unknown. nginx keeps
  one socket per port: `ssl` and `http2` on any `listen` of it, and the default server's `http2 on`, count for every
  server on it. Anything that opens upstream connections while a request is served (`*_pass`, Lua handlers, njs,
  `auth_request`, `mirror`, `perl`) counts as a proxy for CVE-2026-123633.
- Findings carry CVSS 9.2 (Wiz). A 32-bit build, HTTP/2 without TLS (CVE-2026-123007) and HTTP/2 without a proxy
  directive (CVE-2026-123633) are reported as facts that weaken the published exploit path; none clears a finding.
