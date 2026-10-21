#!/usr/bin/env python3
"""Parity check: the engine's php2shell detector against standalone php2shell-scan.

Every case runs three binaries on the same input:
  OLD   php2shell-scan built from the commit the detector was copied from
  THIN  this repo's php2shell-scan (the engine with only php2shell)
  ENG   this repo's earlylight, run as `scan ... --detector php2shell`

A case passes when THIN and ENG report exactly what OLD reports: the same
files examined, the same skipped paths and reasons, the same package-database
problems and OS release, and for every PHP runtime or image reference the same
complete record (path, version, SAPI, status, severity, reason, per-CVE
verdicts, owning package, fix advice), compared field by field. THIN must also
give OLD's exit status. For `fix --dry-run` the printed plan must be identical.

Cases:
  image  php2shell-scan's validation matrix: official images, distribution
         packages (Debian, Ubuntu, Alpine, RHEL/UBI, Amazon Linux, SUSE, Fedora,
         Remi, sury), source builds, and hostile images (forged banners, UPX,
         a packaged binary overwritten). Local cases are built from its
         Dockerfiles and scanned from `docker save`.
  fs     some of those images exported to a directory and scanned as a system
         root, and a subdirectory of one scanned below its root (the package
         databases are then read from the root).
  repo   a source tree naming PHP images in a Dockerfile, Compose, Kubernetes
         and Helm, online and --offline, plus `fix --dry-run` on it.
  both   `earlylight scan image` with every detector at once: each detector's
         findings must equal its own standalone scanner's, so running them
         together changes nothing.

The case list is php-cases.json (copied from php2shell-scan's validation
matrix) and the local images are built from php-images/ first:
    cd parity/php-images && docker build --platform linux/arm64 \
        -f debian12-php82-vuln.Dockerfile -t earlylight-parity/debian12-php82-vuln:arm64 .
(one per "build" case, tagged earlylight-parity/<dockerfile>:<arch>).

Usage: php.py OLD_PHP THIN_PHP EARLYLIGHT OLD_EMUDHRA php-cases.json [CASE...]
"""
import concurrent.futures as cf
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS = {"vulnerable": "vulnerable", "fixed": "fixed", "unknown": "unknown"}
EMUDHRA = {"active": "vulnerable", "inactive": "inactive", "platform": "managed"}
FS_CASES = ["debian12-php82-vuln", "alpine322-php", "ubi9-php", "ubuntu-replaced", "php-8.3.35-fpm"]
BOTH = ["php-8.3.35-fpm", "wordpress-latest", "alpine322-php", "debian12-php82-vuln", "ubi9-php"]

REPO = {
    "Dockerfile": "FROM mirror.gcr.io/library/php:8.3.35-fpm AS base\nRUN echo build\nFROM mirror.gcr.io/library/php:8.3.36-cli\nCOPY --from=base /usr/local /usr/local\n",
    "docker/Dockerfile.worker": "ARG PHP=8.2.34\nFROM mirror.gcr.io/library/php:${PHP}-cli-alpine\n",
    "compose.yaml": "services:\n  web:\n    image: mirror.gcr.io/library/wordpress:6.8.1-php8.3-apache\n  db:\n    image: mirror.gcr.io/library/mariadb:11\n",
    "k8s/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: mirror.gcr.io/library/php:8.4.26-fpm\n",
    "chart/values.yaml": "image:\n  repository: mirror.gcr.io/library/php\n  tag: 8.5.11-apache\n",
    ".github/workflows/ci.yml": "jobs:\n  test:\n    runs-on: ubuntu-latest\n    container: mirror.gcr.io/library/php:8.3.35-cli\n    steps:\n      - run: php -v\n",
}


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        doc = None
    return p.returncode, doc, p.stdout, p.stderr[-2000:]


def canon(x):
    return json.dumps(x, sort_keys=True)


def norm_old(doc):
    out = []
    for t in doc["targets"]:
        recs = sorted(canon(f) for f in t.get("findings") or []) + sorted(canon(r) for r in t.get("references") or [])
        out.append({
            "files": t.get("references_checked", t["files_scanned"]) if t["type"] == "repository" else t["files_scanned"],
            "error": t.get("error", ""), "incomplete": t.get("incomplete", ""),
            "problems": sorted(t.get("problems") or []), "os": canon(t.get("os")),
            "skipped": sorted((s["path"], "excluded" if s.get("excluded") else s["reason"]) for s in t.get("skipped") or []),
            "records": recs,
            "verdicts": sorted((f["path"], STATUS[f["status"]]) for f in t.get("findings") or [])
                        + sorted((r["file"], STATUS[r["status"]]) for r in t.get("references") or []),
        })
    return out


def norm_new(doc, detector="php2shell"):
    out = []
    for t in doc["targets"]:
        fs = [f for f in t.get("findings") or [] if f["detector"] == detector]
        out.append({
            "files": t["files_scanned"], "error": t.get("error", ""), "incomplete": t.get("incomplete", ""),
            "problems": sorted(t.get("problems") or []), "os": canon((t.get("annotations") or {}).get("os")),
            "skipped": sorted((s["path"], "excluded" if s.get("excluded") else s["reason"]) for s in t.get("skipped") or []
                              if not s.get("detector_failed")),
            "records": sorted(canon(f["details"]) for f in fs if f["kind"] != "php-image")
                       + sorted(canon(f["details"]) for f in fs if f["kind"] == "php-image"),
            "verdicts": sorted((f["path"], f["verdict"]) for f in fs if f["kind"] != "php-image")
                        + sorted((f["path"], f["verdict"]) for f in fs if f["kind"] == "php-image"),
        })
    return out


def compare(old, new, label, skips=True):
    diffs = []
    if len(old) != len(new):
        return [f"{label}: target count {len(old)} vs {len(new)}"]
    for a, b in zip(old, new):
        for k in ("files", "error", "incomplete", "problems", "os", "verdicts") + (("skipped",) if skips else ()):
            if a[k] != b[k]:
                diffs.append(f"{label} {k}: {str(a[k])[:300]} vs {str(b[k])[:300]}")
        ra, rb = set(a["records"]), set(b["records"])
        if ra != rb:
            diffs.append(f"{label} records: {len(ra - rb)} only in OLD {sorted(ra - rb)[:2]}, {len(rb - ra)} only in new {sorted(rb - ra)[:2]}")
    return diffs


def three(bins, args_old, args_eng, label, skips=True):
    old_bin, thin_bin, eng_bin = bins
    oc, od, _, oe = run([old_bin, *args_old])
    if od is None:
        return [f"{label}: OLD produced no JSON (exit {oc}): {oe}"], oc, None
    tc, td, _, te = run([thin_bin, *args_old])
    ec, ed, _, ee = run([eng_bin, *args_eng])
    diffs = []
    if td is None:
        diffs.append(f"{label}: THIN produced no JSON (exit {tc}): {te}")
    if ed is None:
        diffs.append(f"{label}: ENG produced no JSON (exit {ec}): {ee}")
    if diffs:
        return diffs, oc, od
    if oc != tc:
        diffs.append(f"{label}: exit OLD {oc} vs THIN {tc}")
    o = norm_old(od)
    diffs += compare(o, norm_new(td), label + " THIN", skips)
    diffs += compare(o, norm_new(ed), label + " ENG", skips)
    return diffs, oc, od


def pin(ref, doc):
    d = doc["targets"][0].get("digest")
    if not d or ref.startswith("docker-archive:"):
        return ref
    repo = ref.split("@")[0]
    if ":" in repo.split("/")[-1]:
        repo = repo.rsplit(":", 1)[0]
    return repo + "@" + d


def image_case(bins, emudhra_old, tmp, name, kind, ref, plat):
    tarball = None
    plat_args = ["--platform", plat]
    if kind == "build":
        tag = "earlylight-parity/%s:%s" % (ref, plat.split("/")[1])
        tarball = os.path.join(tmp, name + ".tar")
        r = subprocess.run(["docker", "save", "-o", tarball, tag], capture_output=True, text=True)
        if r.returncode != 0:
            return name, "ERROR", [f"docker save {tag}: {r.stderr[-300:]}"], {}
        ref, plat_args = "docker-archive:" + tarball, []
    try:
        oc, od, _, oe = run([bins[0], "image", "--format", "json", *plat_args, ref])
        if od is None:
            return name, "ERROR", [f"OLD produced no JSON (exit {oc}): {oe}"], {}
        ref = pin(ref, od)
        diffs, oc, od = three(bins, ["image", "--format", "json", *plat_args, ref],
                              ["scan", "image", "--detector", "php2shell", "--format", "json", *plat_args, ref], "image")
        err = ((od or {}).get("targets") or [{}])[0].get("error")
        if err:
            # Both failing the same way proves nothing about detection.
            return name, "ERROR", [f"scan failed: {err[:200]}"] + diffs, {}
        if name in BOTH and od is not None:
            diffs += both_case(bins[2], emudhra_old, ref, plat_args, od)
        if name in FS_CASES:
            diffs += fs_case(bins, tmp, name, ref, plat_args)
        f = (od or {}).get("targets", [{}])[0].get("findings") or []
        stats = {"runtimes": len(f), "vulnerable": sum(1 for x in f if x["status"] == "vulnerable"),
                 "unknown": sum(1 for x in f if x["status"] == "unknown"), "exit": oc}
        return name, "PASS" if not diffs else "FAIL", diffs, stats
    finally:
        if tarball and os.path.exists(tarball):
            os.remove(tarball)


def both_case(eng_bin, emudhra_old, ref, plat_args, php_doc):
    """All detectors at once: each detector's part equals its standalone scan."""
    ec, ed, _, ee = run([eng_bin, "scan", "image", "--format", "json", *plat_args, ref])
    if ed is None:
        return [f"both: ENG produced no JSON (exit {ec}): {ee}"]
    diffs = compare(norm_old(php_doc), norm_new(ed), "both php2shell", skips=False)
    mc, md, _, me = run([emudhra_old, "image", "--format", "json", *plat_args, ref])
    if md is None:
        return diffs + [f"both: emudhra-scan produced no JSON (exit {mc}): {me}"]
    want = sorted((r["path"], r["kind"], r.get("spki_sha256", ""), EMUDHRA[r["status"]], r.get("status_reason", "")) for r in md["targets"][0]["results"])
    got = sorted((f["path"], f["kind"], (f.get("facts") or {}).get("spki_sha256", ""), f["verdict"], f.get("reason", ""))
                 for f in ed["targets"][0]["findings"] if f["detector"] == "emudhra")
    if want != got:
        diffs.append(f"both emudhra: {len(set(want) - set(got))} only standalone, {len(set(got) - set(want))} only combined {sorted(set(want) ^ set(got))[:3]}")
    if md["targets"][0]["files_scanned"] != ed["targets"][0].get("files_read"):
        diffs.append(f"both emudhra files read: {md['targets'][0]['files_scanned']} vs {ed['targets'][0].get('files_read')}")
    return diffs


def export_rootfs(tmp, name, ref, plat_args):
    """docker export of the image's filesystem, extracted to a directory."""
    root = os.path.join(tmp, name + "-rootfs")
    if ref.startswith("docker-archive:"):
        r = subprocess.run(["docker", "load", "-q", "-i", ref.split(":", 1)[1]], capture_output=True, text=True)
        img = r.stdout.strip().split(": ", 1)[-1]
    else:
        img = ref
        subprocess.run(["docker", "pull", "-q", *plat_args, img], capture_output=True)
    cid = subprocess.run(["docker", "create", *plat_args, img], capture_output=True, text=True).stdout.strip()
    if not cid:
        return None
    try:
        tarpath = root + ".tar"
        subprocess.run(["docker", "export", "-o", tarpath, cid], check=True, capture_output=True)
        os.makedirs(root)
        with tarfile.open(tarpath) as tf:
            members = [m for m in tf.getmembers() if m.isreg() or m.isdir() or m.issym() or m.islnk()]
            tf.extractall(root, members=members, filter="tar")
        os.remove(tarpath)
    finally:
        subprocess.run(["docker", "rm", cid], capture_output=True)
    return root


def fs_case(bins, tmp, name, ref, plat_args):
    root = export_rootfs(tmp, name, ref, plat_args)
    if root is None:
        return [f"fs: could not export {ref}"]
    try:
        diffs, _, _ = three(bins, ["fs", "--format", "json", "--as-root", root, root],
                            ["scan", "fs", "--detector", "php2shell", "--format", "json", "--root", root, root], "fs root")
        sub = os.path.join(root, "usr")
        if os.path.isdir(sub):
            d2, _, _ = three(bins, ["fs", "--format", "json", "--as-root", root, sub],
                             ["scan", "fs", "--detector", "php2shell", "--format", "json", "--root", root, sub], "fs subdir")
            diffs += d2
        return diffs
    finally:
        shutil.rmtree(root, ignore_errors=True)


def repo_case(bins, tmp):
    d = os.path.join(tmp, "repo")
    for p, body in REPO.items():
        os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True)
        with open(os.path.join(d, p), "w") as fh:
            fh.write(body)
    diffs = []
    # One docker.io reference too, judged offline (exact official tags need no lookup).
    with open(os.path.join(d, "Dockerfile.offline"), "w") as fh:
        fh.write("FROM php:8.3.35-fpm\n")
    for extra in ([], ["--offline"], ["--platform", "linux/arm64"]):
        dd, _, _ = three(bins, ["repo", "--format", "json", *extra, d],
                         ["scan", "repo", "--detector", "php2shell", "--format", "json", *extra, d], "repo " + " ".join(extra))
        diffs += dd
    outs = []
    for cmd in ([bins[0], "fix", "--dry-run", d], [bins[1], "fix", "--dry-run", d], [bins[2], "fix", "--detector", "php2shell", "--dry-run", d]):
        p = subprocess.run(cmd, capture_output=True, text=True)
        outs.append((p.returncode, p.stdout.replace(d, "<repo>")))
    if outs[0] != outs[1]:
        diffs.append(f"fix --dry-run THIN differs: {outs[0]!r} vs {outs[1]!r}")
    if outs[0] != outs[2]:
        diffs.append(f"fix --dry-run ENG differs: {outs[0]!r} vs {outs[2]!r}")
    return "repo", "PASS" if not diffs else "FAIL", diffs, {"fix_plan_lines": outs[0][1].count("\n"), "exit": outs[0][0]}


def main():
    if len(sys.argv) < 6:
        print(__doc__)
        return 2
    bins = tuple(sys.argv[1:4])
    emudhra_old, cases_json, only = sys.argv[4], sys.argv[5], set(sys.argv[6:])
    cases = [c for c in json.load(open(cases_json)) if not only or c[0] in only]
    results = {}
    with tempfile.TemporaryDirectory(dir=os.environ.get("PARITY_TMP")) as tmp, cf.ThreadPoolExecutor(3) as ex:
        futs = [ex.submit(image_case, bins, emudhra_old, tmp, n, k, r, p) for n, k, r, p, _ in cases]
        if not only or "repo" in only:
            futs.append(ex.submit(repo_case, bins, tmp))
        for f in cf.as_completed(futs):
            name, verdict, diffs, stats = f.result()
            results[name] = (verdict, diffs, stats)
            print(f"{verdict:5} {name} {stats}", flush=True)
            for d in diffs:
                print("      " + d, flush=True)
    order = [c[0] for c in cases] + (["repo"] if "repo" in results else [])
    lines = ["# Parity: engine php2shell detector vs standalone php2shell-scan", "",
             "Each case compares php2shell-scan (built from the commit in SNAPSHOT), this repo's php2shell-scan and "
             "`earlylight scan --detector php2shell`. See php.py for exactly what is compared.", "",
             "| case | verdict | runtimes | vulnerable | unknown | exit | also checked |", "|---|---|---|---|---|---|---|"]
    for n in order:
        v, d, s = results[n]
        extra = ", ".join(x for x, on in (("fs root + subdir", n in FS_CASES), ("all detectors at once", n in BOTH)) if on)
        if n == "repo":
            extra = f"online, --offline, --platform; fix --dry-run ({s.get('fix_plan_lines')} plan lines)"
        lines.append(f"| {n} | {v} | {s.get('runtimes', '')} | {s.get('vulnerable', '')} | {s.get('unknown', '')} | {s.get('exit', '')} | {extra} |")
    fails = [n for n in order if results[n][0] != "PASS"]
    lines += ["", f"{len(order) - len(fails)} of {len(order)} cases identical."]
    for n in fails:
        lines += ["", f"## {n}", *("- " + d for d in results[n][1])]
    with open(os.path.join(HERE, "PHP-RESULTS.md"), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
