"""Authoritative full-corpus validator (NOT committed).
  (a) every manifest sha256 == git-blob (LF) hash — what a fresh checkout/push reproduces
  (b) every runner reproduces (run in its own dir, with the primary_file arg if it takes one)
Run: python algovoi-records-vault/epi/_validate_corpus.py
"""
import hashlib
import json
import os
import subprocess
import sys

REPO = "C:/algo/algovoi-jcs-conformance-vectors"


def git_blob_sha(relpath: str) -> str | None:
    r = subprocess.run(["git", "-C", REPO, "show", f"HEAD:{relpath}"], capture_output=True)
    if r.returncode != 0:
        return None
    # raw git-blob bytes (what a fresh checkout/push reproduces) — no normalization
    return "sha256:" + hashlib.sha256(r.stdout).hexdigest()


def main() -> int:
    m = json.load(open(os.path.join(REPO, "manifest.json"), encoding="utf-8"))
    hf = ht = 0
    print("== (a) manifest sha256 == git-blob LF hash (fresh-checkout reproduction) ==")
    for grp in ("anchor_sets", "interop_sets", "proposal_sets"):
        for s in m.get(grp, []):
            if "sha256" not in s:
                continue
            ht += 1
            rel = f"vectors/{s['name']}/{s['primary_file']}"
            got = git_blob_sha(rel)
            ok = got == s["sha256"]
            if not ok:
                hf += 1
                print(f"  FAIL {s['name']}: manifest={s['sha256'][:22]} blob={(got or 'MISSING')[:22]}")
    print(f"  {ht - hf}/{ht} file hashes match the manifest")

    print("\n== (b) runners reproduce (own dir; primary_file arg if needed) ==")
    rf = 0
    by_dir = {}
    for grp in ("anchor_sets", "interop_sets", "proposal_sets"):
        for s in m.get(grp, []):
            by_dir[s["name"]] = s.get("primary_file")
    runners = []
    for root, _d, files in os.walk(os.path.join(REPO, "vectors")):
        if "runner_python.py" in files:
            runners.append(root)
    runners.sort()
    for d in runners:
        name = os.path.basename(d)
        primary = by_dir.get(name)
        cmd = [sys.executable, "runner_python.py"] + ([primary] if primary else [])
        res = subprocess.run(cmd, cwd=d, capture_output=True, text=True)
        if res.returncode != 0 and primary:  # maybe it takes no arg
            res = subprocess.run([sys.executable, "runner_python.py"], cwd=d, capture_output=True, text=True)
        tail = (res.stdout.strip().splitlines() or [res.stderr.strip().splitlines()[-1] if res.stderr.strip() else "(no output)"])[-1]
        print(f"  [{'PASS' if res.returncode == 0 else 'FAIL'}] {name:<34} {tail[:60]}")
        if res.returncode != 0:
            rf += 1
    print(f"  {len(runners) - rf}/{len(runners)} runners reproduce")

    ok = hf == 0 and rf == 0
    print("\n==== CORPUS", "BYTE-FOR-BYTE VALID" if ok else "VALIDATION FAILED", "====")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
