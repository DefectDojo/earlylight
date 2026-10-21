# Early Light

One engine for DefectDojo's emerging-vulnerability scanners. Each new vulnerability ships as a detector in this repo instead of as a new repo. The binary is `earlylight`.

## Detectors

| Detector | Finds | Targets |
| --- | --- | --- |
| `emudhra` | Trust in the eight eMudhra intermediate CA keys compromised in October 2026 ([Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449)): trust stores, bundles, keystores and binaries that still trust them, Go binaries without Go's blocklist (CVE-2026-111943), and servers presenting certificates the compromised keys signed | `fs`, `image`, `host` |
| `php2shell` | PHP runtimes vulnerable to CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell"), fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 ([GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)). A packaged PHP is judged by its vendor's backport data, never by the version it reports. Also checks the images a source tree builds on and deploys, and can rewrite them to fixed images | `fs`, `image`, `repo`, `fix` |

Each detector also builds as a standalone binary under the name people search for: `emudhra-scan` and `php2shell-scan`. They keep their original commands, flags and exit status rules.

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
| `parity/` | Proves each port gives the same results as its standalone scanner |

`SNAPSHOT` records which emudhra-scan and php2shell-scan state each copy came from. The detection packages are verbatim copies with import paths rewritten, so re-syncing is a diff.

## Parity

Every port must give exactly the verdicts of the scanner it came from before it ships:

- `parity/parity.py` runs emudhra-scan and Early Light over emudhra-scan's public validation images, directories and live TLS servers ([RESULTS.md](parity/RESULTS.md)).
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

## License

BSD 3-Clause. Report security issues as described in [SECURITY.md](SECURITY.md).

Free and open source, from [DefectDojo](https://defectdojo.com).
