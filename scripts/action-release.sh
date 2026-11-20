#!/bin/sh
# Print the release tag (v1.2.3) that a GitHub Action ref stands for, reading
# `git ls-remote --tags` output on stdin:
#
#   git ls-remote --tags https://github.com/DefectDojo/earlylight | sh action-release.sh v0
#
# REF is a major tag (v0: the highest v0.x.y release at the commit v0 points
# to) or a commit SHA (the highest release tagged at that commit). Prints
# nothing when no release matches, for example for a branch name.
set -eu

[ $# -eq 1 ] || { echo "usage: action-release.sh REF < ls-remote-output" >&2; exit 2; }

awk -v ref="$1" '
  {
    name = $2
    sub(/^refs\/tags\//, "", name)
    # An annotated tag is listed twice; the ^{} line holds the commit it points to.
    if (sub(/\^\{\}$/, "", name) || !(name in commit)) commit[name] = $1
  }
  function newer(a, b,   x, y, i) {
    split(substr(a, 2), x, "."); split(substr(b, 2), y, ".")
    for (i = 1; i <= 3; i++) if (x[i] + 0 != y[i] + 0) return x[i] + 0 > y[i] + 0
    return 0
  }
  END {
    if (ref ~ /^v[0-9]+$/) {
      if (!(ref in commit)) exit
      target = commit[ref]; prefix = ref "."
    } else if (length(ref) == 40 && ref ~ /^[0-9a-f]+$/) {
      target = ref; prefix = "v"
    } else exit
    best = ""
    for (n in commit)
      if (n ~ /^v[0-9]+\.[0-9]+\.[0-9]+$/ && index(n, prefix) == 1 && commit[n] == target)
        if (best == "" || newer(n, best)) best = n
    if (best != "") print best
  }
'
