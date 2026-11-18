#!/usr/bin/env python3
"""epi_verify — offline verifier for an AlgoVoi `.epi` portable-evidence artifact.

You were given a `.epi` artifact and this verifier so you can confirm it yourself — offline, with no
AlgoVoi software, service, or account. Its entire trust base is two public, audited-primitive
libraries:

    pip install pqcrypto rfc8785

Run it against the `.epi` directory you were given:

    python epi_verify.py <path-to-.epi-directory> [<expected_kid>]

It re-derives the Falcon-1024 (FN-DSA-1024) manifest signature and every SHA-256 hash itself, from the
public key inside the artifact. If a single byte was changed, the relevant check fails.

**The key travels inside the artifact**, so the five checks prove it is internally consistent and
unaltered, not who signed it: anyone can generate a keypair and build a wholly fabricated .epi that
passes all five. To prove authenticity, pin the signer's `kid` fingerprint out-of-band and pass it as
`<expected_kid>`, exactly as you would anchor any signer (X.509 included).

Exit codes:
    0  verified AND anchored to the expected kid
    1  verification failed (bad signature, broken chain, or kid mismatch)
    2  usage error
    3  cryptographically intact, but the key is self-asserted — no expected kid was supplied

The five checks (the AlgoVoi PQC profile of the `.epi` portable-compliance-evidence format):
  1. Structure   — manifest.json + steps.jsonl + public_key.b64 are present and well-formed.
  2. Hashes      — every file listed in the manifest matches its recorded SHA-256.
  3. Signature   — the manifest is Falcon-1024-signed by the key whose kid it declares.
  4. Chain       — steps.jsonl is an unbroken hash-linked chain matching the manifest head/count.
  5. Anchored    — optional transparency anchor, if present.

Licensed redistributable component — see LICENSE.txt. Not for publication to public package indexes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

try:
    import rfc8785
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
except Exception as exc:  # noqa: BLE001
    print(f"This verifier needs two public libraries: pip install pqcrypto rfc8785  ({exc})")
    raise SystemExit(2)


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _jcs(payload) -> bytes:
    return rfc8785.dumps(payload)


def _kid(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:16]


def _falcon_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(_falcon_verify(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


def _anchor(kid: str, expected: str | None, ok_all: bool) -> tuple[str, int]:
    """Resolve the trust half of the artifact into a (result line, exit code).

    The five checks prove integrity. They say nothing about *who* signed, because the key came
    from inside the artifact, so an unanchored run must never be reported as fully verified.
    """
    if not ok_all:
        return ".epi VERIFICATION FAILED", 1
    if expected is None:
        return (f".epi INTACT, KEY NOT ANCHORED — signed by kid {kid}, which this artifact supplied "
                f"itself. Re-run with the kid you pinned out-of-band to prove authenticity.", 3)
    if kid != expected:
        return f".epi VERIFICATION FAILED — kid {kid} does not match expected {expected}", 1
    return f".epi VERIFIED AND ANCHORED to kid {kid}", 0


def verify_epi(epi_dir: str, expected_kid: str | None = None) -> int:
    """Verify a `.epi` artifact (AlgoVoi PQC / Falcon-1024 profile) with the spec's five checks.

    `expected_kid` is the signer fingerprint pinned out-of-band. Without it the five checks still
    run, but the key came from inside the artifact, so the result is intact-not-authentic (exit 3).
    """
    def path(n: str) -> str:
        return os.path.join(epi_dir, n)

    print("=" * 70)
    print("AlgoVoi .epi verifier — offline, public key only, no AlgoVoi software")
    print(f"  artifact: {epi_dir}")
    print("=" * 70)
    results: list[tuple[str, bool, str]] = []

    # 1. Structure valid
    needed = ["manifest.json", "steps.jsonl", "public_key.b64"]
    structure_ok = all(os.path.exists(path(n)) for n in needed)
    manifest: dict = {}
    if structure_ok:
        try:
            manifest = json.load(open(path("manifest.json"), encoding="utf-8"))
        except Exception:  # noqa: BLE001
            structure_ok = False
    results.append(("Structure valid", structure_ok, "manifest.json + steps.jsonl + public_key.b64"))

    pk = base64.b64decode(open(path("public_key.b64"), encoding="utf-8").read().strip()) if structure_ok else b""

    # 2. Hashes match — every file in manifest.files matches its recorded sha256
    hashes_ok = structure_ok
    bad: list[str] = []
    for f in (manifest.get("files") or []):
        try:
            h = hashlib.sha256(open(path(f["name"]), "rb").read()).hexdigest()
        except Exception:  # noqa: BLE001
            h = None
        if h != f.get("sha256"):
            hashes_ok = False
            bad.append(f.get("name"))
    results.append(("Hashes match", hashes_ok,
                    ("mismatch: " + ", ".join(bad)) if bad else f"{len(manifest.get('files') or [])} files"))

    # 3. Signature valid — Falcon-1024 over JCS(manifest sans signature)
    sig_ok = False
    detail = "no signature"
    sig = manifest.get("signature", "")
    if structure_ok and sig.count(":") >= 2:
        suite, kid, b64 = sig.split(":", 2)
        body = {k: v for k, v in manifest.items() if k != "signature"}
        if suite == "falcon1024":
            sig_ok = (kid == manifest.get("kid") == _kid(pk)) and _falcon_ok(pk, _jcs(body), _b64u(b64))
            detail = f"falcon1024 / kid {kid}"
        else:
            detail = f"unsupported suite {suite!r} (this verifier supports falcon1024)"
    results.append(("Signature valid", sig_ok, detail))

    # 4. Chain intact — steps.jsonl hash-links + steps_head / steps_count
    chain_ok = structure_ok
    cdetail = ""
    if structure_ok:
        prev = None
        n = 0
        head = None
        for line in open(path("steps.jsonl"), encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            step = json.loads(line)
            if step.get("prev") != prev:
                chain_ok = False
                cdetail = f"chain_break@{n}"
                break
            prev = "sha256:" + hashlib.sha256(_jcs(step)).hexdigest()
            head = prev
            n += 1
        if chain_ok:
            if manifest.get("steps_count") != n:
                chain_ok, cdetail = False, f"steps_count {manifest.get('steps_count')} != {n}"
            elif manifest.get("steps_head") != head:
                chain_ok, cdetail = False, "steps_head mismatch"
            else:
                cdetail = f"{n} steps linked"
    results.append(("Chain intact", chain_ok, cdetail))

    # 5. Anchored (optional transparency receipt)
    anchored = manifest.get("scitt_receipt") is not None
    results.append(("Anchored", True, "present" if anchored else "not anchored (optional)"))

    for name, ok, det in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:<16} {det}")
    ok_all = all(ok for _, ok, _ in results)
    print("=" * 70)
    line, code = _anchor(_kid(pk) if pk else "?", expected_kid, ok_all)
    print("RESULT:", line)
    print("=" * 70)
    return code


def main(argv: list[str]) -> int:
    if len(argv) not in (1, 2):
        print(__doc__)
        return 2
    return verify_epi(argv[0], argv[1] if len(argv) == 2 else None)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
