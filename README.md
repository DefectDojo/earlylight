# Early Light

One engine for DefectDojo's emerging-vulnerability scanners. Each new vulnerability ships as a detector in this repo instead of as a new repo. The binary is `earlylight`.

The first detector is `emudhra`, ported from emudhra-scan. php2shell follows once php2shell-scan has shipped on its own.

## Install

```bash
go install github.com/DefectDojo/earlylight/cmd/earlylight@latest
go install github.com/DefectDojo/earlylight/cmd/emudhra-scan@latest   # just the eMudhra detector
docker run --rm ghcr.io/defectdojo/earlylight scan image python:3.13-slim
```

Release binaries for Linux, macOS and Windows are on the [releases page](https://github.com/DefectDojo/earlylight/releases), with `checksums.txt` signed by Sigstore (`cosign verify-blob --bundle checksums.txt.sigstore.json --certificate-identity-regexp 'https://github.com/DefectDojo/earlylight/' --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt`).

## Use

```bash

earlylight detectors                                   # list detectors
earlylight scan image python:3.13-slim                 # every detector that scans images
earlylight scan image --detector emudhra python:3.13-slim
earlylight scan image --platform all myorg/app:prod    # every platform the image has
earlylight scan fs --as-root /host                     # a host mounted elsewhere
earlylight scan host example.com                       # live servers
```

`emudhra-scan` is the same engine with only the emudhra detector, under the name people search for. It keeps emudhra-scan's commands (`emudhra-scan fs|image|host`) and flags, including `--show-inactive`.

Exit status: `0` nothing vulnerable or unknown, `1` something vulnerable, `2` error (including "nothing was scanned"), `3` nothing vulnerable but something unknown, or with `--fail-on-skip`, something not scanned. Output is `--format text`, `json` or `sarif`. SARIF rule IDs are `<detector>/<kind>`.

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
| `parity/` | Proves the port gives the same results as the standalone scanner |

`SNAPSHOT` records which emudhra-scan and php2shell-scan state each copy came from. The emudhra detection packages are verbatim copies with import paths rewritten, so re-syncing is a diff.

## Adding a detector

1. Create `detectors/<id>/` with a type that implements `engine.Detector`: `Manifest`, `Load` (parse and check embedded data, refuse to run on contradiction) and `NewScan`.
2. `NewScan` returns a per-target `engine.Scan`. `Visit` sees every file the engine reads, plus archive members when the manifest sets `Archives`. Keep the few file contents your verdicts need. `Finish` gets a `TargetContext` (`Exists`, `Env`, `Aliases`) and returns findings.
3. Implement `engine.Reader` (`Wants`) if you only need some files read in full, and `engine.Prober` for live hosts.
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
```

## License

BSD 3-Clause. Report security issues as described in [SECURITY.md](SECURITY.md).

Free and open source, from [DefectDojo](https://defectdojo.com).
