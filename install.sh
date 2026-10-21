#!/bin/sh
# Install Early Light from a GitHub release, verifying the release checksum.
#
#   curl -fsSL https://raw.githubusercontent.com/DefectDojo/earlylight/main/install.sh | sh
#
# Environment:
#   EARLYLIGHT_VERSION   release tag to install (default: the latest release)
#   EARLYLIGHT_BIN_DIR   where to install (default: /usr/local/bin, or ~/.local/bin
#                        when /usr/local/bin is not writable)
#   EARLYLIGHT_BINARIES  which binaries (default: "earlylight"; also emudhra-scan,
#                        php2shell-scan)
#
# The binary is checked against checksums.txt from the same release. When cosign
# is installed, checksums.txt itself is verified against the release's Sigstore
# bundle, so the binary is tied to DefectDojo's release workflow.
set -eu

repo="DefectDojo/earlylight"
version="${EARLYLIGHT_VERSION:-}"
bins="${EARLYLIGHT_BINARIES:-earlylight}"

say() { printf '%s\n' "$*" >&2; }
fail() { say "earlylight install: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
need curl
need uname

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *) fail "unsupported OS $os; download a release from https://github.com/$repo/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

if [ -z "$version" ]; then
  # The latest release redirects to its tag; no API token needed.
  version=$(curl -fsSI "https://github.com/$repo/releases/latest" | tr -d '\r' | sed -n 's#^[Ll]ocation: .*/tag/\(v[0-9][^ ]*\)$#\1#p' | tail -1)
  [ -n "$version" ] || fail "could not find the latest release"
fi
case "$version" in
  v[0-9]*) ;;
  *) fail "EARLYLIGHT_VERSION must be a release tag like v0.2.0" ;;
esac

if [ -n "${EARLYLIGHT_BIN_DIR:-}" ]; then
  dir="$EARLYLIGHT_BIN_DIR"
elif [ -w /usr/local/bin ]; then
  dir=/usr/local/bin
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
base="https://github.com/$repo/releases/download/$version"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || fail "no checksums.txt in release $version"

if command -v cosign >/dev/null 2>&1; then
  curl -fsSL -o "$tmp/checksums.txt.sigstore.json" "$base/checksums.txt.sigstore.json" || fail "no signature bundle in release $version"
  cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$repo/.github/workflows/release.yml@refs/tags/v" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$tmp/checksums.txt" >/dev/null 2>&1 || fail "checksums.txt signature did not verify"
  say "verified checksums.txt signature (Sigstore)"
else
  say "cosign not found: checking checksums only (install cosign to also verify the signature)"
fi

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

for b in $bins; do
  case "$b" in
    earlylight | emudhra-scan | php2shell-scan) ;;
    *) fail "unknown binary $b" ;;
  esac
  file="${b}_${version}_${os}_${arch}"
  curl -fsSL -o "$tmp/$file" "$base/$file" || fail "no $file in release $version"
  want=$(awk -v f="$file" '$2 == f { print $1 }' "$tmp/checksums.txt")
  [ -n "$want" ] || fail "$file is not listed in checksums.txt"
  [ "$(sha "$tmp/$file")" = "$want" ] || fail "$file does not match checksums.txt"
  chmod +x "$tmp/$file"
  mv "$tmp/$file" "$dir/$b"
  say "installed $dir/$b ($version)"
done

case ":$PATH:" in
  *":$dir:"*) ;;
  *) say "add $dir to your PATH" ;;
esac
