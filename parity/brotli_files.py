#!/usr/bin/env python3
"""Validation: the brotli detector on release binaries for Windows, macOS and
Linux, Electron, Envoy and Istio, and packages that bundle the C decoder.

Each case is a directory of one release's files, unpacked (never run), and the
verdict its Brotli decoder must get: from the vendor's advisory or release
notes, and for builds that carry no readable table or version, from whether
the decoder's source has the fix (see brotli-files.json). The scan must find
exactly one verdict for the case; a case with "none" must report nothing.

Usage: brotli_files.py EARLYLIGHT brotli-files.json DIR
  DIR holds one subdirectory per case, named as in the JSON.
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    el, cases_file, root = sys.argv[1:4]
    with open(cases_file) as fh:
        cases = json.load(fh)
    rows, failed = [], 0
    for name, want in sorted(cases.items()):
        d = os.path.join(root, name)
        if not os.path.isdir(d):
            rows.append("| %s | MISSING | | | |" % name)
            failed += 1
            continue
        p = subprocess.run([el, "scan", "fs", "--detector", "brotli", "--format", "json", "--show-cleared", d], capture_output=True, text=True)
        doc = json.loads(p.stdout)
        fs = [f for t in doc["targets"] for f in t.get("findings") or []]
        verdicts = sorted({f["verdict"] for f in fs}) or ["none"]
        ok = verdicts == [want]
        failed += not ok
        f0 = fs[0] if fs else None
        digest = ""
        if f0 and "!/" not in f0["path"] and os.path.isfile(f0["path"]):
            with open(f0["path"], "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()[:16]
        rows.append("| %s | %s | %s | %s | %s |" % (name, "PASS" if ok else "FAIL want " + want, ", ".join(verdicts),
                                                     f0.get("method", "") if f0 else "", digest))
        print(name, rows[-1].split("|")[2].strip(), flush=True)
    with open(os.path.join(HERE, "BROTLI-FILES-RESULTS.md"), "w") as fh:
        fh.write("# Validation: brotli detector on release binaries and bundling packages\n\n")
        fh.write("Each case is one release's files, unpacked and never run. See brotli_files.py and brotli-files.json.\n\n")
        fh.write("| case | result | verdict | evidence | sha256 (first 16) |\n|---|---|---|---|---|\n")
        fh.write("\n".join(rows) + "\n")
    print("%d of %d failed" % (failed, len(rows)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
