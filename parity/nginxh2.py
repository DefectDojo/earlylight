#!/usr/bin/env python3
"""Check the nginxh2 detector against nginx builds whose status is known.

usage: python3 parity/nginxh2.py path/to/earlylight [case ...]

With case names, only those run and only their rows of the results file
change (a registry's pull limit can stop a full run part way).

Needs Docker and registry access. Cases are in parity/nginxh2/cases.json:
published images scanned from Docker Hub by digest (one pull each), images
built from parity/nginxh2/*.Dockerfile with the classic builder on images
already pulled (no pulls) and scanned from `docker save` archives, one built
image exported and scanned as a filesystem, a source tree scanned offline,
and fix --dry-run on a small tree, offline and against the registry. Each
case's findings are compared with the expected rows, which come from
FACTS.md (fixed releases, the releases that introduced each flaw, what a
configuration turns on), not from earlier runs. Writes
parity/NGINXH2-RESULTS.md.
"""
import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "nginxh2")


def run(tool, args):
    out = subprocess.run([tool] + args, capture_output=True, text=True)
    return out


def scan(tool, args):
    # Flags go before the target: the command line stops reading flags there.
    out = run(tool, args[:2] + ["--detector", "nginxh2", "--format", "json", "--show-cleared"] + args[2:])
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return {"targets": [{"error": (out.stderr or out.stdout).strip()[:300]}]}


def rows(report, repo=False, platform=None):
    got, notes = [], []
    for t in report.get("targets", []):
        if t.get("error"):
            got.append(["error", t["error"][:120], "", "", "", ""])
        if t.get("digest"):
            notes.append(t.get("platform", "") + " " + t["digest"])
        for f in t.get("findings", []):
            facts = f.get("facts", {})
            if repo:
                got.append([f["path"] + ":" + str(f.get("line", 0)), f["kind"], f["verdict"]])
            else:
                got.append([platform or t.get("platform", ""), f["path"], f["kind"], f["verdict"], facts.get("status", ""), facts.get("exposure", "")])
                if facts.get("bits") == "32" and "32-bit" not in notes:
                    notes.append("32-bit")
    return got, notes


def safe_extract(tar, dest):
    for m in tar.getmembers():
        p = os.path.realpath(os.path.join(dest, m.name))
        if not p.startswith(os.path.realpath(dest) + os.sep) or m.isdev():
            continue
        try:
            tar.extract(m, dest, set_attrs=False, filter="fully_trusted")
        except (OSError, tarfile.TarError):
            pass


def build(c):
    tag = "earlylight-parity-nginxh2:" + c["name"].replace("-fs", "")
    env = dict(os.environ, DOCKER_BUILDKIT="0")  # the classic builder uses the local base images: no pulls
    subprocess.run(["docker", "build", "-q", "--platform", "linux/amd64", "-t", tag, "-f", os.path.join(CASES, c["dockerfile"]), CASES],
                   check=True, stdout=subprocess.DEVNULL, env=env)
    return tag


def fix_lines(out):
    got = []
    for l in out.stdout.splitlines():
        if l.startswith(" "):
            continue
        parts = l.split()
        if len(parts) >= 2 and parts[0] in ("fixed", "would", "not", "note", "incomplete"):
            verb = parts[0]
            rest = parts[1:]
            if verb in ("would", "not"):
                verb += " " + parts[1]
                rest = parts[2:]
            got.append([verb, rest[0] if rest else ""])
    got.append(["exit", str(out.returncode)])
    return got


def run_case(tool, c, tmp):
    kind = c["mode"]
    if kind == "registry":
        args = ["scan", "image"]
        if c.get("platform"):
            args += ["--platform", c["platform"]]
        return rows(scan(tool, args + [c["ref"]]))
    if kind == "repo":
        return rows(scan(tool, ["scan", "repo", "--offline", os.path.join(CASES, c["dir"])]), repo=True)
    if kind == "fix":
        args = ["fix", "--detector", "nginxh2", "--dry-run"] + c.get("args", []) + [os.path.join(CASES, c["dir"])]
        return fix_lines(run(tool, args)), []
    tag = build(c)
    if kind == "build":
        tar = os.path.join(tmp, c["name"] + ".tar")
        subprocess.run(["docker", "save", tag, "-o", tar], check=True)
        return rows(scan(tool, ["scan", "image", "docker-archive:" + tar]))
    # kind == "fs": export the container filesystem and scan it as a system root.
    cid = subprocess.run(["docker", "create", "--platform", "linux/amd64", tag], check=True, capture_output=True, text=True).stdout.strip()
    try:
        tar = os.path.join(tmp, c["name"] + "-fs.tar")
        subprocess.run(["docker", "export", cid, "-o", tar], check=True)
    finally:
        subprocess.run(["docker", "rm", cid], check=True, stdout=subprocess.DEVNULL)
    root = os.path.join(tmp, c["name"] + "-root")
    os.makedirs(root)
    with tarfile.open(tar) as t:
        safe_extract(t, root)
    return rows(scan(tool, ["scan", "fs", "--as-root", root]), platform="fs")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    tool = os.path.abspath(sys.argv[1])
    only = set(sys.argv[2:])
    cases = json.load(open(os.path.join(CASES, "cases.json")))
    results, failed = [], 0
    with tempfile.TemporaryDirectory() as tmp:
        for c in cases:
            if only and c["name"] not in only:
                continue
            got, notes = run_case(tool, c, tmp)
            want = c["expected"]
            ok = sorted(got) == sorted(want)
            failed += not ok
            results.append((c, ok, got, want, notes))
            print(("pass " if ok else "FAIL ") + c["name"], flush=True)
    path = os.path.join(HERE, "NGINXH2-RESULTS.md")
    lines = {}
    if only and os.path.exists(path):
        for l in open(path):
            if l.startswith("| ") and not l.startswith("| Case") and not l.startswith("| ---"):
                lines[l.split(" | ")[0][2:]] = l
    for c, ok, got, want, notes in results:
        cell = "<br>".join(" ".join(str(x) for x in g if x) for g in sorted(got)) or "none"
        what = c["what"]
        if c.get("ref"):
            what += "<br>`" + c["ref"] + "`" + "".join("<br>" + d for d in notes)
        lines[c["name"]] = f"| {c['name']} | {what} | {'pass' if ok else 'FAIL (want ' + json.dumps(want) + ')'} | {cell} |\n"
    order = [c["name"] for c in cases if c["name"] in lines]
    passed = sum(1 for n in order if lines[n].split(" | ")[2] == "pass")
    with open(path, "w") as f:
        f.write("# nginx HTTP/2 pair (nginxh2) fixture results\n\nGenerated by `parity/nginxh2.py`. Each row's expected findings come from "
                "[FACTS.md](../detectors/nginxh2/FACTS.md). Registry images are scanned by digest; the image digest scanned is listed. "
                "Image rows are platform, path, kind, verdict, status, exposure; source-tree rows are file:line, kind, verdict; "
                "fix rows are what fix printed for each place, and its exit status.\n\n"
                "| Case | What | Result | Findings |\n| --- | --- | --- | --- |\n")
        for n in order:
            f.write(lines[n])
        f.write(f"\n{passed}/{len(order)} cases match.\n")
    print(f"{passed}/{len(order)} cases match")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
