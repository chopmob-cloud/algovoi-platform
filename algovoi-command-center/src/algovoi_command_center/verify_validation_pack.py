#!/usr/bin/env python3
"""Standalone offline verifier for an AlgoVoi System Validation Evidence Pack.

This script depends on **nothing from AlgoVoi**. It needs only two public
libraries, ``pqcrypto`` for Falcon-1024 verification and ``rfc8785`` for JCS
canonicalisation, plus the **published public key** shipped inside the pack.
There is no secret key, no running service and no network access. A sceptical
third party, an FDA investigator, a notified body, a customer's quality team,
can confirm the validation evidence is genuine and unaltered without trusting
AlgoVoi at all.

It verifies, in order:
  1. the manifest carries a Falcon-1024 signature that is valid, under the
     published public key, over the JCS bytes of the manifest with its own
     ``signature`` field removed;
  2. every file listed in the manifest is present and its SHA-256 matches the
     value the signature commits to (so no section can be swapped or edited);
  3. the IQ, OQ and PQ sections are well formed, and it prints their summary
     and the regulatory control coverage the pack claims.

Run:  pip install pqcrypto rfc8785
      python verify_validation_pack.py [pack_dir]   (default: this file's directory)
Exit: 0 iff the manifest signature and every file hash verify; non-zero otherwise.
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


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _falcon_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(_falcon_verify(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


def main(pack: str) -> int:
    def path(name: str) -> str:
        return os.path.join(pack, name)

    with open(path("public_key.b64"), encoding="utf-8") as fh:
        pk = base64.b64decode(fh.read().strip())
    with open(path("manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)

    print("=" * 74)
    print("AlgoVoi System Validation Evidence Pack, offline verification")
    print(f"  pack          : {pack}")
    print(f"  schema        : {manifest.get('schema_version')}")
    print(f"  generated     : {manifest.get('created_at')}  by {manifest.get('generator')}")
    print(f"  public key kid: {hashlib.sha256(pk).hexdigest()[:16]}  (Falcon-1024, {len(pk)} bytes)")
    print(f"  verifier deps : pqcrypto + rfc8785 only, NO AlgoVoi code, NO secret, NO service")
    print("=" * 74)

    ok_all = True

    # 1. Manifest signature over JCS(manifest sans signature).
    sig_field = manifest.get("signature", "")
    try:
        _suite, _kid, sig_b64u = sig_field.split(":", 2)
        sig = _b64u(sig_b64u)
    except ValueError:
        print("  [FAIL] manifest signature   malformed signature field")
        return 1
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    sig_ok = _falcon_ok(pk, rfc8785.dumps(unsigned), sig)
    print(f"  [{'PASS' if sig_ok else 'FAIL'}] manifest signature   Falcon-1024 over JCS(manifest sans signature)")
    ok_all &= sig_ok

    # 2. Every committed file present with a matching SHA-256.
    files = manifest.get("files", [])
    files_ok = True
    for entry in files:
        name, want = entry.get("name"), entry.get("sha256")
        if not os.path.exists(path(name)):
            print(f"  [FAIL] file present        {name} is missing")
            files_ok = False
            continue
        got = _sha256_file(path(name))
        if got != want:
            print(f"  [FAIL] file hash           {name} sha256 != manifest")
            files_ok = False
    if files_ok:
        print(f"  [PASS] file hashes         {len(files)} files, every SHA-256 matches the signed manifest")
    ok_all &= files_ok

    # 3. Section summary and control coverage (reporting; integrity comes from 1 and 2).
    def load(name: str):
        with open(path(name), encoding="utf-8") as fh:
            return json.load(fh)

    if sig_ok and files_ok:
        try:
            iq, oq, pq = load("iq.json"), load("oq.json"), load("pq.json")
            print("-" * 74)
            print("  IQ  installation qualification")
            for k, v in (iq.get("component_versions") or {}).items():
                print(f"        {k}: {v}")
            if iq.get("sbom_ref"):
                print(f"        sbom: {iq['sbom_ref']}")
            print("  OQ  operational qualification")
            for s in oq.get("suites", []):
                print(f"        {s.get('name')}: {s.get('passed')}/{s.get('total')} passed "
                      f"(failed {s.get('failed')})  run {s.get('run_at')}")
            print("  PQ  performance qualification")
            ia = pq.get("integrity_attestation") or {}
            print(f"        integrity chain '{ia.get('chain')}' head {str(ia.get('head'))[:24]}... "
                  f"rows {ia.get('rows')}")
            print("-" * 74)
            print("  Control coverage claimed by this pack:")
            for m in load("control_mapping.json").get("mappings", []):
                print(f"        [{m.get('section'):<5}] {m.get('framework')} {m.get('requirement_id')}: "
                      f"{m.get('coverage')}")
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] section summary unavailable: {exc}")

    print("=" * 74)
    print("RESULT:", "VALIDATION EVIDENCE VERIFIED OFFLINE (public key only)" if ok_all
          else "VERIFICATION FAILED, the pack is altered or inconsistent")
    print("=" * 74)
    return 0 if ok_all else 1


if __name__ == "__main__":
    pack_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    raise SystemExit(main(pack_dir))
