"""
Section 8 — retention chain substrate + verify_signed_chain_link.

8a. retention_chain_v0 + retention_chain_v1 (JCS corpus vectors)
    Re-computes each retention_chain_ref with substrate2.retention_chain.retention_chain_ref
    and asserts it matches the published expected_chain_ref.

8b. retention-chain-rfc9421-v1 (package vectors)
    Runs verify_signed_chain_link for each vector and checks signature_valid,
    chain_ref_valid, and valid against the published expect block.
"""
from __future__ import annotations

import json
from pathlib import Path

from .._paths import JCS_VECTORS_DIR, RETENTION_RFC9421_VECTORS

_RFC9421_VECTORS = RETENTION_RFC9421_VECTORS


# ---------------------------------------------------------------------------
# 8a — chain_ref primitive vectors
# ---------------------------------------------------------------------------

def _section_8a() -> tuple[bool, str]:
    from substrate2.retention_chain import retention_chain_ref

    fails: list[str] = []
    passed = total = 0

    for set_name in ("retention_chain_v0", "retention_chain_v1"):
        primary = JCS_VECTORS_DIR / set_name / f"{set_name}.json"
        if not primary.exists():
            fails.append(f"{set_name}: primary file not found")
            continue
        data = json.loads(primary.read_text(encoding="utf-8"))
        for vec in data.get("vectors", []):
            vid = vec.get("vector_id", "?")
            expected = vec.get("expected_chain_ref")
            if not expected:
                continue
            total += 1
            try:
                actual = retention_chain_ref(
                    prev_receipt_hash=vec["prev_receipt_hash"],
                    receipt_hash=vec["receipt_hash"],
                    chain_seq=vec["chain_seq"],
                    issuer_id=vec["issuer_id"],
                )
            except Exception as exc:
                fails.append(f"{set_name}/{vid}: {type(exc).__name__}: {exc}")
                continue
            if actual != expected:
                fails.append(f"{set_name}/{vid}: chain_ref mismatch (got {actual[:24]}...)")
            else:
                passed += 1

    ok = not fails
    detail = f"{passed}/{total} chain_ref hashes match (v0 + v1)"
    if fails:
        detail += " | FAIL: " + "; ".join(fails)
    return ok, detail


# ---------------------------------------------------------------------------
# 8b — RFC 9421 signed chain link vectors
# ---------------------------------------------------------------------------

def _section_8b() -> tuple[bool, str]:
    from substrate2.retention_chain import verify_signed_chain_link

    if not _RFC9421_VECTORS.exists():
        return False, f"vector file not found: {_RFC9421_VECTORS}"

    data = json.loads(_RFC9421_VECTORS.read_text(encoding="utf-8"))
    fails: list[str] = []
    passed = total = 0

    for i, vec in enumerate(data.get("vectors", [])):
        vid = vec.get("description", f"vec-{i}")
        expect = vec.get("expect", {})
        http = vec["http"]
        kp = vec["keypair"]
        total += 1
        try:
            result = verify_signed_chain_link(
                method=http["method"],
                authority=http["authority"],
                path=http["path"],
                headers=http["headers"],
                body=bytes.fromhex(http["body_hex"]),
                public_key=kp["public_key_hex"],
                chain_ref=vec["retention_chain_ref"],
                prev_receipt_hash=vec["prev_receipt_hash"],
                receipt_hash=vec["receipt_hash"],
                chain_seq=vec["chain_seq"],
                issuer_id=vec["issuer_id"],
            )
        except Exception as exc:
            fails.append(f"{vid}: raised {type(exc).__name__}: {exc}")
            continue

        ok_vec = True
        for field in ("signature_valid", "chain_ref_valid", "valid"):
            expected_val = expect.get(field)
            actual_val = getattr(result, field)
            if expected_val is not None and actual_val != expected_val:
                fails.append(f"{vid}: {field} expected {expected_val}, got {actual_val}")
                ok_vec = False
        if ok_vec:
            passed += 1

    ok = not fails
    detail = f"{passed}/{total} RFC 9421 signed chain links verified"
    if fails:
        detail += " | FAIL: " + "; ".join(fails)
    return ok, detail


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> tuple[bool, str]:
    ok8a, d8a = _section_8a()
    ok8b, d8b = _section_8b()
    ok = ok8a and ok8b
    detail = f"8a {d8a}  ||  8b {d8b}"
    return ok, detail
