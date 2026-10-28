#!/usr/bin/env python3
"""Validation: the brotli detector against real images with known fix status.

The brotli detector is native to Early Light (there is no standalone scanner to
compare with), so each case states the verdict every Brotli decoder in the image
must get, from the vendor's own advisory or package changelog:

  registry  official Node.js, .NET, Bun, Envoy and curl images before and after
            their October 2026 releases, on amd64 and arm64 (.NET 8 on arm64
            strips the decoder's error table, so it is judged by its version
            stamp instead).
  build     distribution packages pinned to the exact unfixed and backported
            builds (Debian, Ubuntu, RHEL/UBI, Fedora, Amazon Linux, Alpine) and
            the Brotli and brotlicffi Python wheels, built from brotli-images/
            and scanned from `docker save`.

A case passes when every expected decoder is found with the expected verdict and
nothing else is reported. An expectation's key matches any finding path that
contains it, so one case works on every architecture.

Usage: brotli.py EARLYLIGHT brotli-cases.json [CASE...]
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def image_ref(kind, ref, tmp):
    if kind == "registry":
        return ref
    tag = "earlylight-parity/brotli-" + ref
    code, _, err = run(["docker", "build", "-q", "-f", os.path.join(HERE, "brotli-images", ref + ".Dockerfile"), "-t", tag, os.path.join(HERE, "brotli-images")])
    if code != 0:
        raise RuntimeError("docker build " + ref + ": " + err.strip()[-400:])
    tar = os.path.join(tmp, ref + ".tar")
    code, _, err = run(["docker", "save", "-o", tar, tag])
    if code != 0:
        raise RuntimeError("docker save " + ref + ": " + err.strip()[-400:])
    return "docker-archive:" + tar


def check(el, case, tmp):
    name, kind, ref, platform, want = case
    target = image_ref(kind, ref, tmp)
    cmd = [el, "scan", "image", "--detector", "brotli", "--format", "json"]
    if platform:
        cmd += ["--platform", platform]
    code, out, err = run(cmd + [target])
    if code == 2:
        return name, "ERROR", [err.strip()[-300:]], code, []
    doc = json.loads(out)
    errors = [t["error"] for t in doc["targets"] if t.get("error")]
    if errors:
        return name, "ERROR", errors, code, []
    found = [f for t in doc["targets"] for f in t.get("findings") or []]
    problems = []
    matched = set()
    for key, verdict in want.items():
        hits = [f for f in found if key in f["path"]]
        if not hits:
            problems.append("no finding for " + key)
        for f in hits:
            matched.add(f["path"])
            if f["verdict"] != verdict:
                problems.append("%s: %s, want %s (%s)" % (f["path"], f["verdict"], verdict, f.get("reason", "")))
    for f in found:
        if f["path"] not in matched:
            problems.append("unexpected %s %s" % (f["verdict"], f["path"]))
    return name, "PASS" if not problems else "FAIL", problems, code, found


def main():
    el, cases_file = sys.argv[1], sys.argv[2]
    only = set(sys.argv[3:])
    with open(cases_file) as fh:
        cases = json.load(fh)
    rows, failed = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for case in cases:
            if only and case[0] not in only:
                continue
            try:
                name, verdict, problems, code, found = check(el, case, tmp)
            except RuntimeError as e:
                name, verdict, problems, code, found = case[0], "ERROR", [str(e)], 2, []
            failed += verdict != "PASS"
            methods = sorted({f.get("method", "") for f in found})
            counts = {v: sum(f["verdict"] == v for f in found) for v in ("vulnerable", "fixed", "unknown")}
            rows.append("| %s | %s | %d | %d | %d | %d | %s | %s |" % (
                name, verdict, len(found), counts["vulnerable"], counts["fixed"], counts["unknown"], code,
                ", ".join(m for m in methods if m)))
            print(name, verdict, *problems, sep="\n  " if problems else " ", flush=True)
    with open(os.path.join(HERE, "BROTLI-RESULTS.md"), "w") as fh:
        fh.write("# Validation: brotli detector against images with known fix status\n\n")
        fh.write("Each case states the verdict every Brotli decoder in the image must get. See brotli.py for how it is checked.\n\n")
        fh.write("| case | verdict | decoders | vulnerable | fixed | unknown | exit | evidence |\n|---|---|---|---|---|---|---|---|\n")
        fh.write("\n".join(rows) + "\n")
    print("%d of %d failed" % (failed, len(rows)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
