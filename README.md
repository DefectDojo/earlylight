<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="brand/svg/lockup/earlylight-horizontal-dark.svg">
    <img alt="Early Light" src="brand/svg/lockup/earlylight-horizontal-light.svg" width="360">
  </picture>
</h1>

One engine for DefectDojo's emerging-vulnerability scanners. Each new vulnerability ships as a detector in this repo instead of as a new repo. The binary is `earlylight`.

## Detectors

| Detector | Finds | Targets |
| --- | --- | --- |
| `emudhra` | Trust in the eight eMudhra intermediate CA keys compromised in October 2026 ([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)): trust stores, bundles, keystores and binaries that still trust them, Go binaries without Go's blocklist (CVE-2026-111943), and servers presenting certificates the compromised keys signed | `fs`, `image`, `host` |
| `php2shell` | PHP runtimes vulnerable to CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell"), fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)). A packaged PHP is judged by its vendor's backport data, never by the version it reports. Also checks the images a source tree builds on and deploys, and can rewrite them to fixed images | `fs`, `image`, `repo`, `fix` |
| `brotli` | Brotli decoders vulnerable to CVE-2026-111497 ("Node2Shell", "Broccoli2Shell"), Brotli 1.0.3 through 1.2.0, fixed in 1.0.10, 1.1.1 and 1.2.1 ([GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)): system `libbrotlidec` and every copy bundled into other software (Node.js, .NET, Bun, Electron, Envoy and Istio, Python wheels such as Pillow, pyarrow, duckdb, pycurl and PyMuPDF, brotli4j, and more), on Linux, Windows and macOS. A decoder is judged first by the error code the fix added, so vendor backports are recognised without distribution data; a build that strips it by its own version stamp or by its code, which returns that error code only once fixed. In a source tree it finds the Node.js, .NET and Bun releases and the bundling packages a project pins, and `fix` moves each to the fixed release | `fs`, `image`, `repo`, `fix` |
| `sshole` | \*sshole, the OpenSSH password authentication bypass on musl libc fixed in OpenSSH 10.6p2 and in Alpine's openssh packages of November 5, 2026 ([release notes](https://www.openssh.org/releasenotes.html#10.6p2), [writeup](https://sshhole.com)). On musl, sshd from 7.3p1 to 10.6p1 compares an account's password field of `*` with the `*` that crypt returns when it fails, so a crafted password logs in to that account. It judges each installed sshd by its C library, its release and the apk database (Alpine backports keep the release number), then checks what the target's `sshd_config` (Include, Match, PasswordAuthentication, AuthenticationMethods, PermitRootLogin, AllowUsers and the rest) and account files make reachable, and reports the accounts. In an image it also reads the command (`sshd -o` and `-f`) and the startup scripts it runs (entrypoints, s6, cont-init.d), and reports a server as exposed when a startup script turns password logins on, sets a `*` field or sets passwords. OpenWrt's opkg database and its backports (23.05, 24.10, 25.12) count like Alpine's. PAM-checked builds (`UsePAM yes`) are not affected. On a live server it reads the banner and the offered methods and never sends a password. In a source tree it finds Dockerfiles that install an OpenSSH server on Alpine without the fix (package lists in `ARG` and `ENV` too), Ansible apk tasks, Buildroot, OpenWrt and Yocto configurations that build one on musl, and anything that sets a password field to `*`. It also pulls the images the tree references (through the guarded transport, with the command a Compose service or Kubernetes container sets) and judges them like `scan image`. `fix` adds the fixed release floor (in the variable when the list is one), moves an end-of-life Alpine base to a tag on the nearest fixed Alpine release (`alpine:3.14` to `3.16`, `python:3.9-alpine3.14` to `3.9-alpine3.16` after checking that image) as a labelled upgrade, adds upstream commit 4353fdc43 as a patch scoped to the OpenSSH versions it applies to (Buildroot `BR2_GLOBAL_PATCH_DIR`, a version-specific Yocto bbappend), sets Ansible tasks to `state: latest`, and changes `*` to `*NP*` | `fs`, `image`, `host`, `repo`, `fix` |
| `nginxh2` | The nginx HTTP/2 remote code execution pair disclosed on November 18, 2026: CVE-2026-123007, memory corruption in HTTP/2 flow control (nginx 1.9.5 to 1.31.8), and CVE-2026-123633, a use-after-free in HTTP/2 connection reuse (1.19.7 to 1.31.8), both fixed in nginx 1.31.9 and 1.30.7 ([fix](https://github.com/nginx/nginx/commit/e27f5fa84fe6e98505e70bc543b748747dad0a3b), [fix](https://github.com/nginx/nginx/commit/2df48a501d0fb8212b7d39dffeeff5876332ba59), [Wiz](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities), [knowledge table](detectors/nginxh2/FACTS.md)). CVSS 9.2 (Wiz). It finds nginx, OpenResty, Tengine, Angie and NGINX Plus binaries by what the binary carries (its version line, configure arguments and module list), and judges each CVE on each binary on its own: a build without HTTP/2 is not affected, a build whose version line is missing, renamed or disagrees with its other version strings is unknown and never cleared, and the fix leaves no marker in the binary, so the fix itself is judged by version. OpenResty is judged by its nginx core and its own release (it backports as patches), Tengine and Angie by their own releases (no fixed release yet), NGINX Plus by its release (fixed 37.0.8.1 and 37.3.0.1; 37.0.7.1 and 37.2.0.1 fix CVE-2026-123633 only). A distribution build is read through the package database (dpkg, apk) with a backport table that is empty today: Debian and Ubuntu had published no fixed package; Alpine 3.24 and edge have 1.30.7-r0. It then reads the configuration the binary loads (its compiled-in path or the image command's `-c`, includes at any level with globs and symbolic links, the official image's templates, `-g`) and reports exposure as a fact on a finding that stays vulnerable: HTTP/2 over TLS (CVE-2026-123007), HTTP/2 in front of `proxy_pass`, `grpc_pass` and the other proxies (CVE-2026-123633), `worker_connections`; HTTP/2 off everywhere is "not exposed", and an include it cannot read, a configuration the ingress-nginx or F5 controller writes at start, or none at all leaves exposure unknown, never off. In a source tree it judges nginx image tags (official image and variants, nginx-unprivileged, OpenResty, Bitnami, ingress-nginx and its Helm chart, the F5 NGINX Ingress Controller, Angie) in Dockerfiles, Compose, Kubernetes, Helm values and CI files, reads moving tags and digests from the registry on linux/amd64 and linux/arm64, judges the nginx packages a Dockerfile installs (apt, apk, dnf and yum, dnf module streams, through `sh -c`, subshells, xargs, heredocs, ARG and ENV) against each distribution's status, and reports the configurations that turn HTTP/2 on. `fix` moves a tag to the first fixed release of its line and variant (`1.31.8-alpine3.24-perl` to `1.31.9-alpine3.24-perl`, `1.30.6` to `1.30.7`) after reading the new image on each platform judged, checking that it is published for every platform the tree builds and stays on the same base OS, moves an Alpine 3.24 pin to 1.30.7-r0, declines everything without a published fix with the reason, and prints the `http2 off;` edit as an optional interim step it never applies | `fs`, `image`, `repo`, `fix` |

The detectors ported from standalone scanners also build as standalone binaries under the names people search for: `emudhra-scan` and `php2shell-scan`. They keep their original commands, flags and exit status rules. `brotli`, `sshole` and `nginxh2` were written here and run through `earlylight` (`--detector brotli`, `--detector sshole`, `--detector nginxh2`).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/DefectDojo/earlylight/main/install.sh | sh
brew install defectdojo/tap/earlylight
go install github.com/DefectDojo/earlylight/cmd/earlylight@latest
go install github.com/DefectDojo/earlylight/cmd/emudhra-scan@latest     # just the eMudhra detector
go install github.com/DefectDojo/earlylight/cmd/php2shell-scan@latest   # just the PHP2Shell detector
docker run --rm ghcr.io/defectdojo/earlylight scan image python:3.13-slim
```

`install.sh` checks each binary against the release's `checksums.txt`, and when `cosign` is installed it also verifies that file's Sigstore signature. Set `EARLYLIGHT_VERSION`, `EARLYLIGHT_BIN_DIR` or `EARLYLIGHT_BINARIES="earlylight php2shell-scan"` to change what it installs.

The static binary is the main way to run Early Light: it scans the machine it runs on, works the same on Linux, macOS and Windows, and needs nothing else. The container image is for CI systems that run steps in containers and for Kubernetes jobs; to scan a host from it, mount the host read-only and use `--as-root`: `docker run --rm -v /:/host:ro ghcr.io/defectdojo/earlylight scan fs --as-root /host`.

Release binaries for Linux, macOS and Windows are on the [releases page](https://github.com/DefectDojo/earlylight/releases), with `checksums.txt` signed by Sigstore (`cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp 'https://github.com/DefectDojo/earlylight/' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt`).

## Use

```bash
earlylight detectors                                   # list detectors
earlylight detectors --format json                     # the detector catalog, as each release's detectors.json
earlylight scan image php:8.3-fpm                      # every detector that scans images
earlylight scan image --detector php2shell php:8.3-fpm
earlylight scan image --detector brotli node:24.22.0-slim
earlylight scan repo --detector brotli .                # Node.js, .NET, Bun and bundling packages a source tree pins
earlylight fix --detector brotli --dry-run .            # the one-line moves to fixed releases
earlylight scan image --detector sshole myorg/sshd:prod  # OpenSSH servers on musl, their config and accounts
sudo earlylight scan fs --detector sshole /             # this machine's sshd
earlylight scan host --detector sshole bastion.example:22  # banner and offered methods; sends no password
earlylight scan repo --detector sshole .                # Dockerfiles, scripts and Ansible tasks
earlylight fix --detector sshole --dry-run .            # fixed apk floors, "*" to "*NP*"
earlylight scan image --detector nginxh2 --platform all nginx:1.31.8  # nginx binaries and the HTTP/2 their configuration turns on
sudo earlylight scan fs --detector nginxh2 /            # this machine's nginx, OpenResty, Angie
earlylight scan repo --detector nginxh2 .               # nginx images, packages and configurations a tree uses
earlylight fix --detector nginxh2 --dry-run --platform linux/amd64,linux/arm64 .  # verified moves to 1.31.9 / 1.30.7
earlylight scan image --platform all myorg/app:prod    # every platform the image has
sudo earlylight scan fs /                              # this machine
earlylight scan fs --as-root /host                     # a host mounted elsewhere
earlylight scan fs --root /host /host/usr/bin          # a directory below a system root
earlylight scan host example.com                       # live TLS servers
earlylight scan repo .                                 # the images a source tree builds on and deploys
earlylight fix --dry-run .                             # show the image updates that fix them
```

`emudhra-scan fs|image|host` and `php2shell-scan fs|image|repo|fix` work as they always did. `php2shell-scan fs --as-root DIR PATH` takes the system root as its value, like the original.

Exit status: `0` nothing vulnerable or unknown, `1` something vulnerable, `2` error (including "nothing was scanned"), `3` nothing vulnerable but something unknown, or with `--fail-on-skip`, something not scanned. Output is `--format text`, `json` or `sarif`. SARIF rule IDs are `<detector>/<kind>`.

Each release also attaches `detectors.json`, listed in the signed `checksums.txt`. It is the output of `earlylight detectors --format json` for that release: for every detector its ID, title, CVEs, advisories, disclosure date, the commands that run it (`fs`, `image`, `host`, `repo`, `fix`) and its finding kinds. Tools such as DefectDojo read it to tell which detectors a release contains without running a binary. `schema` changes only when a field is removed or changes meaning.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for upload-sarif
jobs:
  earlylight:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DefectDojo/earlylight@v0
        with:
          mode: repo            # fs, image, repo or host
          target: .
          upload-sarif: true    # findings in GitHub code scanning
          fail-on: vulnerable   # vulnerable, unknown or never
```

The action installs the release it is pinned to (checksum-verified), writes SARIF to `earlylight.sarif` for DefectDojo or code scanning, and puts a findings table in the job summary. Outputs: `sarif`, `exit-code`.

## Verdicts

| Verdict | Meaning | Counted |
| --- | --- | --- |
| `vulnerable` | Proven exposed | Yes, exit 1 |
| `unknown` | The evidence does not settle it. The reason says what to check | Yes, exit 3 |
| `fixed` | Proven to have the fix | No |
| `inactive` | Present but provably not used | No |
| `managed` | Another layer decides (an OS keychain, a browser's blocklist) | Listed, not counted |

The engine enforces one rule for every detector: a finding can only be `fixed`, `inactive` or `managed` with a reason attached. A detector that clears something without saying why gets `unknown` instead.

## Layout

| Path | What |
| --- | --- |
| `internal/engine` | Detector contract, registry, target walking, the evidence rule |
| `internal/source` | Directory and tar walker (merged from both scanners) |
| `internal/image` | Registry, `docker save` and platform handling (from php2shell-scan) |
| `internal/archive` | jar, whl, deb, rpm, compressed files, PyInstaller (from emudhra-scan) |
| `internal/host` | TLS certificate chain fetch (from emudhra-scan) |
| `internal/report` | Text, JSON, SARIF |
| `internal/cli` | Command line shared by every binary |
| `detectors/emudhra` | Adapter, plus `internal/` copied verbatim from emudhra-scan |
| `detectors/php2shell` | Adapter, `verbatim.go` from php2shell-scan's command line, and `internal/` copied verbatim from php2shell-scan |
| `detectors/brotli` | Adapter, plus `internal/fingerprint` (what a binary proves: the decoder's error table, its tables and code, exports and version stamps), `internal/assess` (the verdict and fix for one file) and `internal/pins` (pins and bundling packages in a source tree, and their verified edits), which know nothing about the engine |
| `detectors/sshole` | Adapter and live-host probe, plus `internal/assess` (what an sshd binary proves, musl's shadow lookup and crypt failures, sshd's salt choice, sshd_config with Include and Match, and the verdict) and `internal/repo` (Dockerfiles, scripts and YAML in a source tree, and their verified edits), which know nothing about the engine |
| `detectors/nginxh2` | Adapter, plus `internal/knowledge` (the release data and version judgement, sourced in `FACTS.md`), `internal/ngx` (what an nginx binary proves: product, version line, configure arguments, modules, word size), `internal/conf` (nginx's configuration grammar, includes and globs, and what it says about HTTP/2, TLS and proxying), `internal/pkgdb` (dpkg and apk owners and version order), `internal/assess` (each CVE's verdict on each binary, with its exposure) and `internal/repo` (nginx images, packages and configurations in a source tree, and their verified edits), which know nothing about the engine |
| `internal/refs` | Image references in Dockerfiles, Compose, Kubernetes, Helm values and CI files (moved from php2shell, unchanged, so every detector can read them) |
| `parity/` | Proves each port gives the same results as its standalone scanner |
| `brand/` | The Early Light logo, favicons, avatar and social preview |

`SNAPSHOT` records which emudhra-scan and php2shell-scan state each copy came from. The detection packages are verbatim copies with import paths rewritten, so re-syncing is a diff.

## Parity

Every port must give exactly the verdicts of the scanner it came from before it ships:

- `parity/parity.py` runs emudhra-scan and Early Light over emudhra-scan's public validation images, directories and live TLS servers ([RESULTS.md](parity/RESULTS.md)).
- `parity/brotli.py` has no standalone scanner to compare with, so it checks every decoder in 38 images against the vendor's own fix status: Node.js, .NET, Bun, Envoy and curl images before and after their October 2026 releases, distribution packages pinned to their exact unfixed and backported builds, and the Python wheels ([BROTLI-RESULTS.md](parity/BROTLI-RESULTS.md)).
- `parity/brotli_files.py` checks 73 release binaries and packages, unpacked and never run: Node.js, .NET and Bun for Windows and macOS, seven Electron releases, Envoy and Istio, and the packages that bundle the decoder ([BROTLI-FILES-RESULTS.md](parity/BROTLI-FILES-RESULTS.md)). A WebAssembly build of the decoder is the one case it cannot settle: it is reported as unknown.
- `parity/sshole.py` builds ten images from `parity/sshole/` (Alpine with the unfixed and the fixed package, password logins off, UsePAM on, root with PermitRootLogin, a Match on address, the current Alpine release, Debian, an entrypoint that turns password logins on at start, and `sshd -o` in the image command) and checks each verdict against the expected one ([SSHOLE-RESULTS.md](parity/SSHOLE-RESULTS.md)). The expected verdicts come from the upstream fix, musl's crypt and shadow code, and the Alpine package that shipped it.
- `parity/nginxh2.py` checks 39 cases against verdicts taken from [FACTS.md](detectors/nginxh2/FACTS.md): official images before and after the fix on both lines (Debian, Alpine, perl, otel; arm64 and 386), the 1.19.6 / 1.19.7 boundary, 1.18.0 and 1.10.3, nginx-unprivileged, OpenResty, Bitnami, ingress-nginx and the F5 NGINX Ingress Controller before and after 5.8.0, Debian, Ubuntu and Alpine packages (a filesystem export too), configurations that turn HTTP/2 on over TLS, without TLS, without a proxy, in a template, through `-c` and through a symbolic link, that turn it off, or that cannot be read in full (unreadable includes, loops, a 5 MB file), synthetic binaries without a version line, renamed, with only the version line edited to claim the fix, and without HTTP/2, a source tree, and `fix` offline and against the registry ([NGINXH2-RESULTS.md](parity/NGINXH2-RESULTS.md)).
- `parity/php.py` runs php2shell-scan, this repo's php2shell-scan and Early Light over php2shell-scan's validation matrix: official images, distribution packages, source builds and hostile images. Each finding's complete record is compared field by field. It also covers filesystem scans at and below a system root, repository scans, `fix --dry-run`, and every detector at once ([PHP-RESULTS.md](parity/PHP-RESULTS.md)).

## Adding a detector

1. Create `detectors/<id>/` with a type that implements `engine.Detector`: `Manifest`, `Load` (parse and check embedded data, refuse to run on contradiction) and `NewScan`.
2. `NewScan` returns a per-target `engine.Scan`. `Visit` sees every file the engine reads, plus archive members when the manifest sets `Archives`. Keep the few file contents your verdicts need. `Finish` gets a `TargetContext` (`Exists`, `Env`, `Aliases`, `Links`, `SystemRoot`, `Problem`, `Annotate`) and returns findings.
3. Implement `engine.Reader` (`Wants`) if you only need some files read in full, `engine.Prober` for live hosts, and `engine.RepoScanner` or `engine.Fixer` for source trees.
4. Register it in `init` and import it from `detectors/all`.
5. Ship a validation corpus and add it to `parity/` or its own harness. Run fuzz, race, vet and govulncheck.

## Checks

```bash
go vet ./... && go test -race ./...
go test ./internal/source -run '^$' -fuzz '^FuzzTar$' -fuzztime 60s
go test ./internal/archive -run '^$' -fuzz '^FuzzWalk$' -fuzztime 60s
go test ./detectors/emudhra/internal/detect -run '^$' -fuzz '^FuzzScan$' -fuzztime 60s
go test ./detectors/sshole/internal/assess -run '^$' -fuzz '^FuzzConfig$' -fuzztime 60s
go test ./detectors/sshole/internal/repo -run '^$' -fuzz '^FuzzScanText$' -fuzztime 60s
go test ./detectors/nginxh2/internal/conf -run '^$' -fuzz '^FuzzParse$' -fuzztime 60s
go test ./detectors/nginxh2/internal/ngx -run '^$' -fuzz '^FuzzInspect$' -fuzztime 60s
go test ./detectors/nginxh2/internal/ngx -run '^$' -fuzz '^FuzzVersions$' -fuzztime 60s
go test ./detectors/nginxh2/internal/repo -run '^$' -fuzz '^FuzzScanText$' -fuzztime 60s
go test ./detectors/nginxh2 -run '^$' -fuzz '^FuzzSource$' -fuzztime 60s
go test ./detectors/nginxh2/internal/assess -run '^$' -fuzz '^FuzzStart$' -fuzztime 60s
go test ./detectors/nginxh2/internal/pkgdb -run '^$' -fuzz '^FuzzDatabases$' -fuzztime 60s
govulncheck ./...
python3 parity/parity.py path/to/emudhra-scan path/to/earlylight
python3 parity/php.py path/to/php2shell-scan ./php2shell-scan ./earlylight path/to/emudhra-scan cases.json
python3 parity/nginxh2.py ./earlylight
```

## Privacy

Early Light runs entirely on your machine or CI runner. It has no telemetry, no analytics and no account, and it sends nothing to DefectDojo.

It only makes network connections when a scan needs them:

| What | Connects to |
| --- | --- |
| Installing (`install.sh` and the GitHub Action) | GitHub, to download the release and its `checksums.txt`. When `cosign` is installed, it also fetches Sigstore's public trust root to check the signature |
| `scan image` | The registry that hosts the image you name |
| `scan repo` and `fix` | The registries that host the images your source tree references (for `sshole`, the base images whose Alpine release a Dockerfile does not name). `--offline` turns this off, and `--public-registries-only` refuses private and internal addresses |
| `scan host` | The hosts you name: a TLS handshake, and for `sshole` an SSH handshake that asks which login methods the server offers (as user `earlylight-probe`) and stops before sending any password. The server logs it as a connection that did not authenticate |
| `scan fs` | Nothing |

Results stay where you put them: the SARIF file, the job summary and, when you set `upload-sarif: true`, GitHub code scanning in your own repository.

DefectDojo's privacy policy is at [defectdojo.com/privacy-policy](https://defectdojo.com/privacy-policy).

## License

BSD 3-Clause. The licenses of the Go standard library and the modules compiled into the binaries are in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt), which ships with every release and in the container image at `/licenses/`. After changing `go.mod`, run `scripts/third-party-notices.sh` and commit the result. CI fails when it is out of date.

Report security issues as described in [SECURITY.md](SECURITY.md).

Free and open source, from [DefectDojo](https://defectdojo.com).
