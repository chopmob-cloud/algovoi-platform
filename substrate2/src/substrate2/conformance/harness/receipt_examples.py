"""
Section 4 — every receipt builder reproduces its published vectors byte-exact.

Drives substrate2's compliance / settlement / refund / cancellation / composite-trust-query
builders, the action_ref primitive, and the Payment Evidence Frame from the corresponding
*_v1 / *_v0 vector sets, asserting canonical bytes == expected and sha256_jcs == expected
hash. Also reproduces the published schemas/examples/receipt-*.json compliance examples.
"""
from __future__ import annotations

import base64
import json

from .._paths import JCS_SCHEMA_EXAMPLES, JCS_VECTORS_DIR

_COMPLIANCE_FIELDS = (
    "payer_ref", "screen_result", "screen_timestamp_ms",
    "screen_provider_did", "jurisdiction_flags", "canon_version",
)


def _b64_to_bytes(s: str) -> bytes:
    s2 = s.replace("-", "+").replace("_", "/")
    s2 += "=" * ((-len(s2)) % 4)
    return base64.b64decode(s2)


def _load(set_name, primary):
    path = JCS_VECTORS_DIR / set_name / primary
    return json.loads(path.read_bytes()) if path.exists() else None


def run():
    from substrate2.canon import canonicalize_bytes
    from substrate2.digest import sha256_jcs
    from substrate2.action import action_ref, action_ref_object
    from substrate2.pef import build_pef
    from substrate2.receipts.compliance import build_compliance_receipt
    from substrate2.receipts.settlement import build_settlement_attestation
    from substrate2.receipts.refund import build_refund_receipt
    from substrate2.receipts.cancellation import build_cancellation_receipt
    from substrate2.receipts.ctq import build_ctq_response

    fails: list[str] = []
    checked = 0

    # (a) published compliance examples, byte-for-byte
    for ex in sorted(JCS_SCHEMA_EXAMPLES.glob("receipt-*.json")):
        obj = json.loads(ex.read_text(encoding="utf-8"))
        if not all(f in obj for f in _COMPLIANCE_FIELDS):
            continue
        checked += 1
        built = build_compliance_receipt(**{f: obj[f] for f in _COMPLIANCE_FIELDS})
        if canonicalize_bytes(built) != canonicalize_bytes(obj):
            fails.append(f"{ex.name}: not byte-identical")

    # (b) receipt builders against their vector sets (object keys == builder kwargs)
    builders = [
        ("compliance_receipt_v1", "compliance_receipt_v1.json", "receipt", build_compliance_receipt, "expected_content_hash"),
        ("settlement_attestation_v1", "settlement_attestation_v1.json", "receipt", build_settlement_attestation, "expected_content_hash"),
        ("refund_receipt_v1", "refund_receipt_v1.json", "receipt", build_refund_receipt, "expected_content_hash"),
        ("cancellation_receipt_v1", "cancellation_receipt_v1.json", "receipt", build_cancellation_receipt, "expected_content_hash"),
        ("composite_trust_query_v1", "composite_trust_query_v1.json", "response", build_ctq_response, "expected_content_hash"),
    ]
    for set_name, primary, obj_key, build_fn, hash_key in builders:
        data = _load(set_name, primary)
        if data is None:
            fails.append(f"{set_name}: missing vectors")
            continue
        for vec in data.get("vectors", []):
            obj = vec.get(obj_key)
            if not isinstance(obj, dict):
                continue
            checked += 1
            vid = vec.get("vector_id", "?")
            try:
                built = build_fn(**obj)
            except Exception as exc:
                fails.append(f"{set_name}/{vid}: build error {type(exc).__name__}: {exc}")
                continue
            if canonicalize_bytes(built) != _b64_to_bytes(vec["expected_jcs_bytes_b64"]):
                fails.append(f"{set_name}/{vid}: JCS bytes != expected")
            elif sha256_jcs(built) != vec[hash_key].split(":")[-1]:
                fails.append(f"{set_name}/{vid}: hash != expected")

    # (c) action_ref primitive + transactional transition hashes
    from substrate2.transactional import transition_hash, transition_preimage
    for set_name in ("action_ref_namespace_v0", "action_ref_transactional_v0"):
        data = _load(set_name, f"{set_name}.json")
        if data is None:
            continue
        for vec in data.get("vectors", []):
            pre = vec.get("preimage")
            if not isinstance(pre, dict):
                continue
            vid = vec.get("vector_id", "?")
            if "expected_action_ref" in vec and "agent_id" in pre:
                checked += 1
                if canonicalize_bytes(action_ref_object(**pre)) != _b64_to_bytes(vec["expected_jcs_bytes_b64"]):
                    fails.append(f"{set_name}/{vid}: action_ref JCS != expected")
                elif action_ref(**pre) != vec["expected_action_ref"].split(":")[-1]:
                    fails.append(f"{set_name}/{vid}: action_ref hash != expected")
            elif "expected_transition_hash" in vec:
                checked += 1
                if canonicalize_bytes(transition_preimage(**pre)) != _b64_to_bytes(vec["expected_jcs_bytes_b64"]):
                    fails.append(f"{set_name}/{vid}: transition JCS != expected")
                elif transition_hash(**pre) != vec["expected_transition_hash"].split(":")[-1]:
                    fails.append(f"{set_name}/{vid}: transition_hash != expected")

    # (e) audit chain rows (wire form {prev_hash, receipt_content_hash, row_number}) + linkage
    cdata = _load("compliance_receipt_v1", "compliance_receipt_v1.json")
    if cdata is not None:
        prev_expected = "0" * 64
        for vec in cdata.get("vectors", []):
            row = vec.get("row")
            if not isinstance(row, dict):
                continue
            checked += 1
            vid = vec.get("vector_id", "?")
            if canonicalize_bytes(row) != _b64_to_bytes(vec["expected_jcs_bytes_b64"]):
                fails.append(f"audit/{vid}: row JCS != expected")
                continue
            row_content_hash = sha256_jcs(row)
            if row_content_hash != vec["expected_row_content_hash"].split(":")[-1]:
                fails.append(f"audit/{vid}: row_content_hash != expected")
                continue
            if row["prev_hash"] != prev_expected:
                fails.append(f"audit/{vid}: prev_hash linkage break")
            prev_expected = row_content_hash

    # (d) Payment Evidence Frame
    data = _load("pef_v1", "pef_v1.json")
    if data is not None:
        for vec in data.get("vectors", []):
            pre = vec.get("preimage")
            if not isinstance(pre, dict):
                continue
            checked += 1
            vid = vec.get("vector_id", "?")
            frame = build_pef(
                claim_type=pre["claim_type"],
                receipt=pre["receipt"],
                frame_provider_did=pre["frame_provider_did"],
                frame_timestamp_ms=pre["frame_timestamp_ms"],
            )
            preimage = {k: v for k, v in frame.items() if k not in ("frame_id", "signature")}
            if canonicalize_bytes(preimage) != _b64_to_bytes(vec["expected_preimage_jcs_bytes_b64"]):
                fails.append(f"pef/{vid}: preimage JCS != expected")
            elif frame["frame_id"] != vec["expected_frame_id"]:
                fails.append(f"pef/{vid}: frame_id != expected")
            elif sha256_jcs(pre["receipt"]) != vec["expected_receipt_hash"].split(":")[-1]:
                fails.append(f"pef/{vid}: receipt_hash != expected")

    ok = (not fails) and checked > 0
    detail = f"{checked} build-checks (examples + 5 receipts + action_ref + transitions + PEF + audit chain)"
    if fails:
        detail += f" | {len(fails)} FAIL: " + "; ".join(fails[:6])
    return ok, detail
