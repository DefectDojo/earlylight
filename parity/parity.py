#!/usr/bin/env python3
"""Parity check: the engine's emudhra detector against standalone emudhra-scan.

Both scanners scan the same targets: the public images in emudhra-scan's
validation matrix, a few directories, and a few live TLS servers. A case passes when both
give the same exit status, scan the same number of files, skip the same paths,
and report the same findings with the same verdict and reason. Registry images
are pinned to the digest the standalone scan resolved, so a moving tag cannot
make the two runs see different images.

Usage: parity.py OLD_BINARY NEW_BINARY [CASE...]
  OLD_BINARY  emudhra-scan built from its own repo
  NEW_BINARY  the engine binary (run as: scan MODE --detector emudhra ...)
"""
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS = {"active": "vulnerable", "inactive": "inactive", "platform": "managed"}

# The validation matrix from emudhra-scan's validation/run.py: name, kind, ref.
# Docker Hub images are pulled through Google's mirror (mirror.gcr.io), as
# php2shell-scan's validation does, to stay clear of Hub's anonymous rate limit.
# "local" images were built by that harness and are scanned from `docker save`.
IMAGES = [
    ("python-3.13-slim", "registry", "mirror.gcr.io/library/python@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f"),
    ("python-3.13-slim-latest", "registry", "mirror.gcr.io/library/python:3.13-slim"),
    ("node-22-slim", "registry", "mirror.gcr.io/library/node:22-slim"),
    ("node-openssl-ca", "local", "emudhra-validate/node-openssl-ca"),
    ("temurin-21-jdk", "registry", "mirror.gcr.io/library/eclipse-temurin:21-jdk"),
    ("temurin-patched", "local", "emudhra-validate/temurin-patched"),
    ("golang-1.27.2", "registry", "mirror.gcr.io/library/golang:1.27.2"),
    ("golang-1.27.3", "registry", "mirror.gcr.io/library/golang:1.27.3"),
    ("alpine-3.23-curl", "local", "emudhra-validate/alpine-old-curl"),
    ("alpine-patched", "local", "emudhra-validate/alpine-patched"),
    ("wolfi-r2", "registry", "cgr.dev/chainguard/wolfi-base@sha256:d68b2b10db0ddb2c6d9cb3a7720ecab5ca19b4b430fd592cd07c23d7da971b56"),
    ("wolfi-latest", "registry", "cgr.dev/chainguard/wolfi-base:latest"),
    ("ubuntu-24.04", "registry", "mirror.gcr.io/library/ubuntu:24.04"),
    ("ubuntu-patched", "local", "emudhra-validate/ubuntu-patched"),
    ("ubuntu-patched-requests", "local", "emudhra-validate/ubuntu-patched-requests"),
    ("debian12-requests", "local", "emudhra-validate/debian12-requests"),
    ("ubi9-minimal", "registry", "registry.access.redhat.com/ubi9/ubi-minimal:latest"),
    ("ubi9-blocklisted", "local", "emudhra-validate/ubi9-blocklisted"),
    ("opensuse-leap-15.6", "registry", "mirror.gcr.io/opensuse/leap:15.6"),
    ("opensuse-workaround", "local", "emudhra-validate/opensuse-workaround"),
    ("opensuse-advisory-literal", "local", "emudhra-validate/opensuse-advisory-literal"),
    ("corretto-21", "registry", "mirror.gcr.io/library/amazoncorretto:21"),
    ("corretto-patched", "local", "emudhra-validate/corretto-patched"),
    ("ruby-3.3-slim", "registry", "mirror.gcr.io/library/ruby:3.3-slim"),
    ("php-8.3-cli", "registry", "mirror.gcr.io/library/php:8.3-cli"),
    ("composer-2", "registry", "mirror.gcr.io/library/composer:2"),
    ("jar-truststore", "local", "emudhra-validate/jar-truststore"),
    ("pyinstaller-app", "local", "emudhra-validate/pyinstaller-app"),
    ("distroless-debian12", "registry", "gcr.io/distroless/static-debian12:nonroot"),
    ("distroless-debian13", "registry", "gcr.io/distroless/static-debian13:nonroot"),
]

EMUDHRA_REPO = os.path.join(os.path.dirname(os.path.dirname(HERE)), "emudhra-scan")
OTHER = [
    ("fs-emudhra-repo", "fs", EMUDHRA_REPO, []),
    ("fs-etc", "fs", "/etc", []),
    ("fs-goroot", "fs", subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip(), []),
    ("fs-as-root", "fs", os.path.join(EMUDHRA_REPO, "validation"), ["--as-root"]),
    ("host-google", "host", "www.google.com", []),
    ("host-github", "host", "https://github.com/", []),
]


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        doc = None
    return p.returncode, doc, p.stderr[-2000:]


def norm_old(doc):
    out = []
    for t in doc["targets"]:
        fs = sorted(
            (r["path"], r["kind"], r.get("spki_sha256", ""), r.get("cert_sha256", ""), STATUS.get(r["status"], "?" + r["status"]), r.get("status_reason", ""), r["detail"])
            for r in t["results"]
        )
        out.append({"name": t["target"], "digest": t.get("digest", ""), "files": t["files_scanned"], "error": t.get("error", ""),
                    "skipped": sorted((s["path"], s["reason"]) for s in t["skipped"]), "findings": fs})
    return out


def norm_new(doc):
    out = []
    for t in doc["targets"]:
        fs = sorted(
            (f["path"], f["kind"], f.get("facts", {}).get("spki_sha256", ""), f.get("facts", {}).get("cert_sha256", ""), f["verdict"], f.get("reason", ""), f["message"])
            for f in t["findings"]
        )
        out.append({"name": t["target"], "digest": t.get("digest", ""), "files": t["files_scanned"], "read": t.get("files_read", t["files_scanned"]),
                    "error": t.get("error", ""), "skipped": sorted((s["path"], s["reason"]) for s in t["skipped"]), "findings": fs})
    return out


def compare(old, new):
    diffs = []
    if len(old) != len(new):
        return [f"target count {len(old)} vs {len(new)}"]
    for a, b in zip(old, new):
        # emudhra-scan counted files it read; the engine reports files examined
        # (files_scanned, as php2shell-scan does) and files read (files_read).
        if a["files"] != b["read"]:
            diffs.append(f"files read: {a['files']!r} vs {b['read']!r}")
        if a["error"] != b["error"]:
            diffs.append(f"error: {a['error']!r} vs {b['error']!r}")
        # Exclusion wording names each tool, so compare skipped paths, and reasons
        # only for skips that are not deliberate exclusions.
        sa = {(p, r if not r.startswith("excluded:") else "excluded") for p, r in a["skipped"]}
        sb = {(p, r if not r.startswith("excluded:") else "excluded") for p, r in b["skipped"]}
        if sa != sb:
            diffs.append(f"skipped: only old {sorted(sa - sb)[:5]}, only new {sorted(sb - sa)[:5]}")
        fa, fb = set(a["findings"]), set(b["findings"])
        if fa != fb:
            diffs.append(f"findings: {len(fa - fb)} only in old {sorted(fa - fb)[:3]}, {len(fb - fa)} only in new {sorted(fb - fa)[:3]}")
    return diffs


def case(old_bin, new_bin, tmp, name, mode, ref, extra):
    tarball = None
    if mode == "local":
        tarball = os.path.join(tmp, name + ".tar")
        subprocess.run(["docker", "save", "-o", tarball, ref], check=True, capture_output=True)
        ref, mode = "docker-archive:" + tarball, "image"
    elif mode == "registry":
        mode = "image"
    try:
        oc, od, oe = run([old_bin, mode, "--format", "json", *extra, ref])
        if od is None:
            return name, "ERROR", [f"standalone produced no JSON (exit {oc}): {oe}"], {}
        new_ref = ref
        if mode == "image" and not ref.startswith("docker-archive:") and od["targets"][0].get("digest"):
            repo = ref.split("@")[0]
            if ":" in repo.split("/")[-1]:
                repo = repo.rsplit(":", 1)[0]  # drop the tag
            new_ref = repo + "@" + od["targets"][0]["digest"]
        nc, nd, ne = run([new_bin, "scan", mode, "--detector", "emudhra", "--format", "json", *extra, new_ref])
        if nd is None:
            return name, "ERROR", [f"engine produced no JSON (exit {nc}): {ne}"], {}
        o, n = norm_old(od), norm_new(nd)
        if new_ref != ref:
            for t in n:
                t["name"] = o[0]["name"]
        diffs = compare(o, n)
        if oc != nc:
            diffs.insert(0, f"exit status {oc} vs {nc}")
        if o[0]["error"]:
            # Both failing the same way proves nothing about detection.
            return name, "ERROR", [f"scan failed: {o[0]['error'][:200]}"] + diffs, {}
        stats = {"files": o[0]["files"], "findings": len(o[0]["findings"]),
                 "vulnerable": sum(1 for f in o[0]["findings"] if f[4] == "vulnerable"), "exit": oc}
        return name, "PASS" if not diffs else "FAIL", diffs, stats
    finally:
        if tarball and os.path.exists(tarball):
            os.remove(tarball)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    old_bin, new_bin, only = sys.argv[1], sys.argv[2], set(sys.argv[3:])
    cases = [(n, k, r, []) for n, k, r in IMAGES] + OTHER
    if only:
        cases = [c for c in cases if c[0] in only]
    results = {}
    with tempfile.TemporaryDirectory(dir=os.environ.get("PARITY_TMP")) as tmp, cf.ThreadPoolExecutor(3) as ex:
        futs = [ex.submit(case, old_bin, new_bin, tmp, *c) for c in cases]
        for f in cf.as_completed(futs):
            name, verdict, diffs, stats = f.result()
            results[name] = (verdict, diffs, stats)
            print(f"{verdict:5} {name} {stats}", flush=True)
            for d in diffs:
                print("      " + d, flush=True)
    order = [c[0] for c in cases]
    lines = ["# Parity: engine emudhra detector vs standalone emudhra-scan", "",
             "| case | verdict | files | findings | vulnerable | exit |", "|---|---|---|---|---|---|"]
    for n in order:
        v, d, s = results[n]
        lines.append(f"| {n} | {v} | {s.get('files', '')} | {s.get('findings', '')} | {s.get('vulnerable', '')} | {s.get('exit', '')} |")
    fails = [n for n in order if results[n][0] != "PASS"]
    lines += ["", f"{len(order) - len(fails)} of {len(order)} cases identical."]
    for n in fails:
        lines += ["", f"## {n}", *("- " + d for d in results[n][1])]
    with open(os.path.join(HERE, "RESULTS.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
