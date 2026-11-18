"""Validate a FRESH tree (extracted via `git archive` = the exact pushed bytes).
  (a) sha256 of each manifest-listed file == manifest value (direct file hash; these ARE the LF blobs)
  (b) every runner reproduces; epi_pqc_v0 highlighted
Usage: python _validate_fresh.py <tree_dir>
"""
import hashlib
import json
import os
import subprocess
import sys

TREE = sys.argv[1]


def file_sha(p):
    return "sha256:" + hashlib.sha256(open(p, "rb").read()).hexdigest()


def main() -> int:
    m = json.load(open(os.path.join(TREE, "manifest.json"), encoding="utf-8"))
    print(f"== validating FRESH (git-archive) tree: {TREE} ==")
    print(f"== manifest version {m['version']} ==\n")

    hf = ht = 0
    crlf = 0
    print("(a) per-file sha256 (direct hash of the pushed bytes) == manifest:")
    for grp in ("anchor_sets", "interop_sets", "proposal_sets"):
        for s in m.get(grp, []):
            if "sha256" not in s:
                continue
            ht += 1
            p = os.path.join(TREE, "vectors", s["name"], s["primary_file"])
            if not os.path.exists(p):
                print(f"   MISSING {s['name']}"); hf += 1; continue
            if b"\r\n" in open(p, "rb").read():
                crlf += 1
            got = file_sha(p)
            tag = "" if grp != "proposal_sets" else "   <-- NEW"
            if got != s["sha256"]:
                hf += 1
                print(f"   FAIL {s['name']}: manifest={s['sha256'][:22]} file={got[:22]}{tag}")
            elif tag:
                print(f"   PASS {s['name']}  {got[:30]}…{tag}")
    print(f"   -> {ht - hf}/{ht} hashes match; {crlf} files contain CRLF (expect 0 in pushed bytes)\n")

    print("(b) runners reproduce:")
    by_primary = {s["name"]: s.get("primary_file") for g in ("anchor_sets", "interop_sets", "proposal_sets") for s in m.get(g, [])}
    rf = 0
    runners = sorted(r for r in (os.path.join(dp, "runner_python.py") for dp, _, fs in os.walk(os.path.join(TREE, "vectors")) for f in fs if f == "runner_python.py"))
    for r in runners:
        d = os.path.dirname(r); name = os.path.basename(d)
        prim = by_primary.get(name)
        res = subprocess.run([sys.executable, "runner_python.py"] + ([prim] if prim else []), cwd=d, capture_output=True, text=True)
        if res.returncode != 0 and prim:
            res = subprocess.run([sys.executable, "runner_python.py"], cwd=d, capture_output=True, text=True)
        tail = (res.stdout.strip().splitlines() or [(res.stderr.strip().splitlines() or ['(no output)'])[-1]])[-1]
        mark = "   <-- NEW" if name == "epi_pqc_v0" else ""
        print(f"   [{'PASS' if res.returncode == 0 else 'FAIL'}] {name:<30} {tail[:52]}{mark}")
        if res.returncode != 0:
            rf += 1
    print(f"   -> {len(runners) - rf}/{len(runners)} runners reproduce")

    bytewise_ok = hf == 0 and crlf == 0
    print()
    print("==== BYTE-FOR-BYTE (pushed bytes vs manifest):", "100% VALID" if bytewise_ok else "MISMATCH", "====")
    return 0 if (hf == 0 and rf == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
