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

The detectors ported from standalone scanners also build as standalone binaries under the names people search for: `emudhra-scan` and `php2shell-scan`. They keep their original commands, flags and exit status rules. `brotli` was written here and runs through `earlylight` (`--detector brotli`).

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
earlylight scan image php:8.3-fpm                      # every detector that scans images
earlylight scan image --detector php2shell php:8.3-fpm
earlylight scan image --detector brotli node:24.22.0-slim
earlylight scan repo --detector brotli .                # Node.js, .NET, Bun and bundling packages a source tree pins
earlylight fix --detector brotli --dry-run .            # the one-line moves to fixed releases
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
| `internal/refs` | Image references in Dockerfiles, Compose, Kubernetes, Helm values and CI files (moved from php2shell, unchanged, so every detector can read them) |
| `parity/` | Proves each port gives the same results as its standalone scanner |
| `brand/` | The Early Light logo, favicons, avatar and social preview |

`SNAPSHOT` records which emudhra-scan and php2shell-scan state each copy came from. The detection packages are verbatim copies with import paths rewritten, so re-syncing is a diff.

## Parity

Every port must give exactly the verdicts of the scanner it came from before it ships:

- `parity/parity.py` runs emudhra-scan and Early Light over emudhra-scan's public validation images, directories and live TLS servers ([RESULTS.md](parity/RESULTS.md)).
- `parity/brotli.py` has no standalone scanner to compare with, so it checks every decoder in 38 images against the vendor's own fix status: Node.js, .NET, Bun, Envoy and curl images before and after their October 2026 releases, distribution packages pinned to their exact unfixed and backported builds, and the Python wheels ([BROTLI-RESULTS.md](parity/BROTLI-RESULTS.md)).
- `parity/brotli_files.py` checks 73 release binaries and packages, unpacked and never run: Node.js, .NET and Bun for Windows and macOS, seven Electron releases, Envoy and Istio, and the packages that bundle the decoder ([BROTLI-FILES-RESULTS.md](parity/BROTLI-FILES-RESULTS.md)). A WebAssembly build of the decoder is the one case it cannot settle: it is reported as unknown.
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
govulncheck ./...
python3 parity/parity.py path/to/emudhra-scan path/to/earlylight
python3 parity/php.py path/to/php2shell-scan ./php2shell-scan ./earlylight path/to/emudhra-scan cases.json
```

## Privacy

Early Light runs entirely on your machine or CI runner. It has no telemetry, no analytics and no account, and it sends nothing to DefectDojo.

It only makes network connections when a scan needs them:

| What | Connects to |
| --- | --- |
| Installing (`install.sh` and the GitHub Action) | GitHub, to download the release and its `checksums.txt`. When `cosign` is installed, it also fetches Sigstore's public trust root to check the signature |
| `scan image` | The registry that hosts the image you name |
| `scan repo` and `fix` | The registries that host the images your source tree references. `--offline` turns this off, and `--public-registries-only` refuses private and internal addresses |
| `scan host` | The hosts you name, for a TLS handshake |
| `scan fs` | Nothing |

Results stay where you put them: the SARIF file, the job summary and, when you set `upload-sarif: true`, GitHub code scanning in your own repository.

DefectDojo's privacy policy is at [defectdojo.com/privacy-policy](https://defectdojo.com/privacy-policy).

## License

BSD 3-Clause. The licenses of the Go standard library and the modules compiled into the binaries are in [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt), which ships with every release and in the container image at `/licenses/`. After changing `go.mod`, run `scripts/third-party-notices.sh` and commit the result. CI fails when it is out of date.

Report security issues as described in [SECURITY.md](SECURITY.md).

Free and open source, from [DefectDojo](https://defectdojo.com).
