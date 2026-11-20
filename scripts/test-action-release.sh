#!/bin/sh
# Check scripts/action-release.sh against a fixed `git ls-remote --tags`
# listing, under every awk on PATH (awk, gawk, mawk, busybox awk).
set -eu

dir=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

C=cccccccccccccccccccccccccccccccccccccccc   # commit of v0, v0.9.0 and v0.10.0
D=dddddddddddddddddddddddddddddddddddddddd   # commit of v0.8.0, and of v2 (no v2 release)
E=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee   # commit of v1 and v1.0.0-rc1 only
T=1111111111111111111111111111111111111111   # the v0.10.0 tag object, not a commit
cat > "$tmp/refs" <<EOF
$C	refs/tags/v0
2222222222222222222222222222222222222222	refs/tags/v0.9.0
$C	refs/tags/v0.9.0^{}
$T	refs/tags/v0.10.0
$C	refs/tags/v0.10.0^{}
$D	refs/tags/v0.8.0
$E	refs/tags/v1
$E	refs/tags/v1.0.0-rc1
$D	refs/tags/v2
EOF

# ref expected-release (empty: no release, install the latest)
cases="v0 v0.10.0
$C v0.10.0
$D v0.8.0
$T -
v1 -
v2 -
main -
v0.9.0 -
cccccccccc -"

fails=0 runs=0
for impl in awk gawk mawk "busybox awk"; do
  name=${impl%% *} sub=${impl#"$name"}
  # The shim is named awk and comes first on PATH, so it names the real one by path.
  bin=$(command -v "$name") || continue
  [ "$name" != busybox ] || "$bin" awk 'BEGIN{}' >/dev/null 2>&1 || continue
  shim=$tmp/$name
  mkdir -p "$shim"
  printf '#!/bin/sh\nexec %s%s "$@"\n' "$bin" "$sub" > "$shim/awk"
  chmod +x "$shim/awk"
  while read -r ref want; do
    [ "$want" = - ] && want=""
    got=$(PATH="$shim:$PATH" sh "$dir/action-release.sh" "$ref" < "$tmp/refs")
    runs=$((runs + 1))
    if [ "$got" != "$want" ]; then
      echo "FAIL ($impl) $ref: got '$got', want '$want'"
      fails=$((fails + 1))
    fi
  done <<EOF
$cases
EOF
done

[ "$runs" -gt 0 ] || { echo "no awk found"; exit 1; }
echo "action-release.sh: $((runs - fails))/$runs passed"
[ "$fails" -eq 0 ]
