#!/usr/bin/env python3
"""Exhaustive byte-for-byte validation of substrate2.

Emits a fully deterministic report: for every canonicalisation and digest surface in the
package, the exact canonical bytes (base64) and their SHA-256. Nothing in the report depends
on the clock, the platform, the filesystem or the interpreter build, so the SAME source must
produce the SAME report on any machine. The whole report is itself reduced to one
`report_digest`, which is the value to compare across hosts.

Sections:
  A  source integrity      sha256 of every shipped .py, LF-normalised
  B  bundled vectors       every vector in every bundled set, RECOMPUTED not read back
  C  primitive surfaces    every deterministic ref/hash function over fixed inputs
  D  receipt builders      all five builders, plus the additive CAIP variants
  E  identifier verdicts   all 102 caip_edge_v1 accept/reject decisions
  F  signed-token anchors  jws_anchor_v1 anchors and invariants

Deliberately excluded: anything keyed or random (keypair generation, signing, range proofs,
federation tokens). Those cannot be byte-stable by construction, and including them would
make the report differ for reasons that mean nothing. Verification of FIXED signed fixtures
IS included, because that is deterministic.

Usage:  python byte_parity.py [--full]     (--full prints the whole report, not just digests)
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

import substrate2
from substrate2.canon import canonicalize_bytes

PKG = pathlib.Path(substrate2.__file__).parent

# Fixed inputs. Every value here is a literal: no clock, no randomness, no environment.
H = {c: c * 64 for c in "abcdef"}
R = {c: "sha256:" + c * 64 for c in "abcdef"}
T = 1721030000000
DID = "did:web:algovoi.co.uk"
FLAGS = ["UK", "EU"]
AMOUNT = {"amount_minor": "1000000", "asset_id": "USDC"}


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def record(obj) -> dict:
    """Canonical bytes + digest of any JCS-canonicalisable object."""
    raw = canonicalize_bytes(obj)
    return {"jcs_b64": b64(raw), "sha256": hashlib.sha256(raw).hexdigest(), "len": len(raw)}


def scalar(value) -> dict:
    """A returned ref/hash string, recorded as-is."""
    return {"value": value}


# ── A. source integrity ───────────────────────────────────────────────────────────────

def section_source() -> dict:
    """LF-normalised so a CRLF checkout and an LF checkout of the same source agree."""
    out = {}
    for p in sorted(PKG.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        raw = p.read_bytes().replace(b"\r\n", b"\n")
        out[str(p.relative_to(PKG)).replace("\\", "/")] = hashlib.sha256(raw).hexdigest()
    return out


# ── B. bundled vectors, recomputed ────────────────────────────────────────────────────

def section_vectors() -> dict:
    from substrate2.conformance._paths import JCS_MANIFEST, JCS_VECTORS_DIR
    from substrate2.conformance.harness.jcs_vectors import _expected_bytes, _find_input

    manifest = json.loads(JCS_MANIFEST.read_text(encoding="utf-8"))
    out = {"_manifest_version": manifest.get("version")}
    for aset in manifest.get("anchor_sets", []):
        name = aset["name"]
        path = JCS_VECTORS_DIR / name / aset["primary_file"]
        if not path.exists():
            out[name] = {"_error": "primary_file missing"}
            continue
        raw = path.read_bytes().replace(b"\r\n", b"\n")
        entry = {"_file_sha256_lf": hashlib.sha256(raw).hexdigest()}
        if not aset.get("fixture_type"):
            data = json.loads(raw)
            for vec in data.get("vectors", []) or []:
                key, inp = _find_input(vec)
                if inp is None or _expected_bytes(vec, key) is None:
                    continue
                vid = vec.get("vector_id") or vec.get("name") or "?"
                entry[vid] = record(inp)
        out[name] = entry
    return out


# ── C. primitive surfaces ─────────────────────────────────────────────────────────────

def section_primitives() -> dict:
    import importlib
    # `from substrate2 import compliance_basis` binds the FUNCTION, not the module: the
    # package re-exports a callable of the same name. importlib is unambiguous.
    _m = lambda n: importlib.import_module("substrate2." + n)
    action, audit, caip = _m("action"), _m("audit"), _m("caip")
    ctq, cb, digest = _m("composite_trust_query"), _m("compliance_basis"), _m("digest")
    execution, ee = _m("execution"), _m("execution_evidence")
    kx, ks, pef = _m("keystone_exports"), _m("keystone_secure"), _m("pef")
    pb, rc, sb = _m("policy_binding"), _m("retention_chain"), _m("settlement_binding")
    tap, tx, zkp = _m("tap"), _m("transactional"), _m("zkp")

    o = {}

    # canonicalisation itself, over shapes that separate conformant implementations
    o["canon.empty_object"] = record({})
    o["canon.empty_array"] = record([])
    o["canon.nested"] = record({"b": [1, {"z": None, "a": True}], "a": "x"})
    o["canon.integral_float"] = record({"v": 1.0})
    # U+2028 / U+2029 built via chr() so no raw control byte sits in this file.
    o["canon.line_separator"] = record({"s": "line" + chr(0x2028) + "sep" + chr(0x2029) + "para"})
    o["canon.non_bmp_keys"] = record({chr(0x1F600): 1, chr(0xFFFF): 2, "a": 3})
    o["canon.unicode_escapes"] = record({"s": " " + chr(0x22) + chr(0x5C) + "/" + chr(8) + chr(12) + chr(10) + chr(13) + chr(9)})
    o["canon.big_int"] = record({"n": 9007199254740991})
    o["canon.neg_zero"] = record({"n": 0})

    o["digest.sha256_jcs"] = scalar(digest.sha256_jcs({"a": 1}))
    o["digest.sha256_jcs_prefixed"] = scalar(digest.sha256_jcs_prefixed({"a": 1}))
    # sha256_hex is an ALIAS of sha256_jcs (not a bytes digest); pinned so that stays true.
    o["digest.sha256_hex_is_alias"] = scalar(digest.sha256_hex is digest.sha256_jcs)
    o["digest.sha256_hex"] = scalar(digest.sha256_hex({"a": 1}))

    o["action.action_ref_object"] = record(action.action_ref_object("agent-1", "transfer", "eu", T))
    o["action.action_ref"] = scalar(action.action_ref("agent-1", "transfer", "eu", T))

    o["execution.execution_ref_object"] = record(
        execution.execution_ref_object(R["a"], "transfer", "eu", "COMMITTED", T))
    o["execution.execution_ref"] = scalar(execution.execution_ref(R["a"], "transfer", "eu", "COMMITTED", T))
    o["execution.screen_binding_ref"] = scalar(execution.screen_binding_ref(R["a"], R["b"]))

    o["execution_evidence.core"] = record(ee.execution_evidence_core(R["a"], "transfer", "eu", "COMMITTED", T))

    row1 = audit.append_to_chain(payload={"event": "one"}, prev_row=None)
    row2 = audit.append_to_chain(payload={"event": "two"}, prev_row=row1)
    o["audit.row1"] = scalar(row1.row_hash if hasattr(row1, "row_hash") else str(row1))
    o["audit.row2"] = scalar(row2.row_hash if hasattr(row2, "row_hash") else str(row2))

    o["transactional.preimage"] = record(tx.transition_preimage(H["a"], "COMMITTED", T, T, T))
    o["transactional.transition_hash"] = scalar(tx.transition_hash(H["a"], "COMMITTED", T, T, T))

    o["ctq.hash"] = scalar(ctq.composite_trust_query_hash(
        [{"source_id": "src-b", "subject_ref": R["b"], "outcome": "UNTRUSTED"},
         {"source_id": "src-a", "subject_ref": R["a"], "outcome": "TRUSTED"}]))  # unsorted on purpose

    # genesis (seq 0) and a linked position (seq 7): both arms of the chain rule
    o["retention.chain_ref_genesis"] = scalar(rc.retention_chain_ref(
        prev_receipt_hash="", receipt_hash=R["b"], chain_seq=0, issuer_id=DID))
    o["retention.chain_ref_linked"] = scalar(rc.retention_chain_ref(
        prev_receipt_hash=R["a"], receipt_hash=R["b"], chain_seq=7, issuer_id=DID))

    policy = {"id": "pol-1", "rules": [{"allow": True, "scope": "eu"}]}
    o["policy.policy_ref"] = scalar(pb.policy_ref(policy))
    o["policy.policy_bound_ref"] = scalar(pb.policy_bound_ref(R["a"], pb.policy_ref(policy)))

    frame = pef.build_pef(claim_type="payment_settlement", receipt={"canon_version": "jcs-rfc8785-v1", "x": 1},
                          frame_provider_did=DID, frame_timestamp_ms=T)
    o["pef.frame"] = record(frame)
    o["pef.frame_id"] = scalar(pef.pef_frame_id(frame))

    o["tap.preimage"] = record(tap.tap_receipt_preimage(
        authorization_ref=R["a"], transaction_hash=H["b"], outcome="SETTLED",
        timestamp_ms=T, sequence=1, settlement_ref=R["c"]))

    o["keystone.execution_binding_ref"] = scalar(kx.execution_binding_ref(R["a"], R["b"], R["c"]))

    o["keystone_secure.decision_audit_ref"] = scalar(ks.decision_audit_ref(
        R["a"], passport_credential_ref=R["b"], mandate_ref=R["c"], policy_bound_ref=R["d"]))
    o["keystone_secure.guard_context_ref"] = scalar(ks.guard_context_ref(
        guard_timestamp_ms=T, policy_ref=R["a"], mandate_ref=R["b"], passport_credential_ref=R["c"]))
    o["keystone_secure.revocation_ref"] = scalar(ks.revocation_ref(
        subject_ref=R["a"], revoked_at_ms=T, reason_code="KEY_COMPROMISE", issuer_did=DID,
        prev_status="active", new_status="revoked", seq=1, prev_revocation_ref=None))

    basis = cb.compliance_basis(
        reason_codes=["CLEAR"], obligations=["TRAVEL_RULE_FILING"],
        checks=[cb.check_entry(check="sanctions", result="ALLOW", provider_did=DID,
                               reason_code="CLEAR", risk_score=0, geo_ref=R["e"])])
    o["compliance_basis.basis"] = record(basis)
    o["compliance_basis.basis_ref"] = scalar(cb.basis_ref(basis))
    o["compliance_basis.basis_binding_ref"] = scalar(cb.basis_binding_ref(screen_ref=R["a"], basis_ref=cb.basis_ref(basis)))

    o["settlement_binding.preimage"] = record(dict(sb.settlement_binding_preimage(H["a"], H["b"], H["c"], R["d"])))
    o["settlement_binding.ref"] = scalar(sb.settlement_action_binding(H["a"], H["b"], H["c"], R["d"]))

    o["zkp.receipt_payload"] = record(zkp.build_zkp_receipt_payload(
        {"payment_id": "pay-1", "chain": "eip155:1", "amount_microusd": 1000000,
         "recipient": "0xAb16", "tx_id": "0xdead", "settled_at": "2026-01-01T00:00:00Z"},
        "Y29tbWl0", "cHJvb2Y",
        1000, DID, "2027-01-01T00:00:00Z", "2026-01-01T00:00:00Z"))

    o["caip.caip10_of"] = scalar(caip.caip10_of("eip155:1", "0xAb16"))
    o["caip.caip19_slip44"] = scalar(caip.caip19_slip44("eip155:1", 60))
    o["caip.registered_count"] = scalar(len(caip.registered_namespaces()))

    return o


# ── D. receipt builders ───────────────────────────────────────────────────────────────

def section_receipts() -> dict:
    from substrate2.receipts import cancellation, compliance, ctq, refund, settlement

    o = {}
    o["settlement.no_caip"] = record(settlement.build_settlement_attestation(
        settled_payment_ref=R["a"], settlement_result="SETTLED", settlement_timestamp_ms=T,
        settlement_provider_did=DID, settlement_amount=AMOUNT, settlement_chain="algorand",
        jurisdiction_flags=FLAGS))
    # the three ad-hoc spellings, pinned so the divergence they cause is visible in the report
    for sp in ("algorand_mainnet", "algo", "eip155:1"):
        o[f"settlement.chain_{sp}"] = record(settlement.build_settlement_attestation(
            settled_payment_ref=R["a"], settlement_result="SETTLED", settlement_timestamp_ms=T,
            settlement_provider_did=DID, settlement_amount=AMOUNT, settlement_chain=sp,
            jurisdiction_flags=FLAGS))
    o["settlement.with_caip"] = record(settlement.build_settlement_attestation(
        settled_payment_ref=R["a"], settlement_result="SETTLED", settlement_timestamp_ms=T,
        settlement_provider_did=DID, settlement_amount=AMOUNT, settlement_chain="algorand",
        settlement_chain_caip="eip155:1", jurisdiction_flags=FLAGS))

    o["refund"] = record(refund.build_refund_receipt(
        original_payment_ref=R["a"], refund_result="FULL", refund_timestamp_ms=T,
        refund_provider_did=DID, refund_amount=AMOUNT, jurisdiction_flags=FLAGS))
    o["cancellation"] = record(cancellation.build_cancellation_receipt(
        cancellation_reason="USER_REQUESTED", cancellation_timestamp_ms=T, effective_from_ms=T,
        cancellation_provider_did=DID, mandate_ref=R["a"], jurisdiction_flags=FLAGS))
    o["ctq"] = record(ctq.build_ctq_response(
        trust_outcome="TRUSTED", chain_ref=R["c"], query_ref=R["b"], ctq_timestamp_ms=T,
        verifier_did=DID, jurisdiction_flags=FLAGS))
    o["compliance"] = record(dict(compliance.build_compliance_receipt(
        payer_ref=R["a"], screen_result="ALLOW", screen_timestamp_ms=T,
        screen_provider_did=DID, jurisdiction_flags=FLAGS)))
    return o


# ── E / F. conformance verdicts ───────────────────────────────────────────────────────

def section_verdicts() -> dict:
    from substrate2.conformance.harness import caip_vectors, jws_anchor

    ok9, d9 = caip_vectors.run()
    ok10, d10 = jws_anchor.run()
    return {"caip_edge_v1": {"ok": ok9, "detail": d9},
            "jws_anchor_v1": {"ok": ok10, "detail": d10}}


# ── G. byte-identity against the open substrate ───────────────────────────────────────

def section_byte_identity() -> dict:
    """substrate2's output must be BYTE-IDENTICAL to the open Apache-2.0 substrate.

    This is the commercial guarantee, not a nicety. A customer replacing the open package
    with substrate2 must find every digest they have already anchored still recomputes; if a
    single byte differs, every historical record they hold becomes unverifiable under the
    engine they just paid for.

    It is checkable as an absolute because the open estate is FROZEN: the compatibility
    target no longer moves, so this is a permanent property rather than a running
    maintenance burden.

    Coverage is deliberately not a handful of samples. Every input object in every bundled
    vector set is pushed through BOTH canonicalisers and compared byte-for-byte, plus each
    primitive whose signature is shared. `open_version` is recorded so the report states
    exactly which release the guarantee was proven against.
    """
    try:
        import algovoi_substrate as open_pkg
    except ImportError:
        return {"_status": "OPEN_PACKAGE_ABSENT",
                "_note": "byte-identity UNPROVEN in this run; GA requires it present"}

    from substrate2.canon import canonicalize_bytes as s2_canon
    from substrate2.conformance._paths import JCS_MANIFEST, JCS_VECTORS_DIR
    from substrate2.conformance.harness.jcs_vectors import _expected_bytes, _find_input

    open_canon = open_pkg.canonicalize_bytes
    out = {"_open_version": getattr(open_pkg, "__version__", "?")}

    # 1) every bundled vector input, through both engines
    compared = mismatched = 0
    mismatch_ids = []
    manifest = json.loads(JCS_MANIFEST.read_text(encoding="utf-8"))
    for aset in manifest.get("anchor_sets", []):
        if aset.get("fixture_type"):
            continue
        path = JCS_VECTORS_DIR / aset["name"] / aset["primary_file"]
        if not path.exists():
            continue
        data = json.loads(path.read_bytes().replace(b"\r\n", b"\n"))
        for vec in data.get("vectors", []) or []:
            key, inp = _find_input(vec)
            if inp is None or _expected_bytes(vec, key) is None:
                continue
            compared += 1
            if s2_canon(inp) != open_canon(inp):
                mismatched += 1
                mismatch_ids.append(f"{aset['name']}/{vec.get('vector_id', '?')}")
    out["vector_inputs_compared"] = compared
    out["vector_inputs_mismatched"] = mismatched
    if mismatch_ids:
        out["vector_mismatches"] = sorted(mismatch_ids)[:20]

    # 2) the canonicalisation edge shapes, where implementations usually part company
    edges = {
        "empty_object": {},
        "empty_array": [],
        "integral_float": {"v": 1.0},
        "line_separator": {"s": "line" + chr(0x2028) + "sep" + chr(0x2029) + "para"},
        "non_bmp_keys": {chr(0x1F600): 1, chr(0xFFFF): 2, "a": 3},
        "big_int": {"n": 9007199254740991},
        "nested": {"b": [1, {"z": None, "a": True}], "a": "x"},
    }
    out["edge_shapes"] = {
        name: (s2_canon(obj) == open_canon(obj)) for name, obj in sorted(edges.items())
    }

    # 3) shared-signature primitives: same inputs must yield the same ref string
    prims = {}
    prims["action_ref"] = (
        __import__("substrate2.action", fromlist=["action"]).action_ref("agent-1", "transfer", "eu", T)
        == open_pkg.action_ref("agent-1", "transfer", "eu", T)
    )
    prims["sha256_jcs"] = (
        __import__("substrate2.digest", fromlist=["digest"]).sha256_jcs({"a": 1})
        == open_pkg.sha256_jcs({"a": 1})
    )
    from algovoi_substrate import transactional as open_tx
    from substrate2 import transactional as s2_tx
    prims["transition_hash"] = (
        s2_tx.transition_hash(H["a"], "COMMITTED", T, T, T)
        == open_tx.transition_hash(H["a"], "COMMITTED", T, T, T)
    )
    from algovoi_substrate import composite_trust_query as open_ctq
    from substrate2 import composite_trust_query as s2_ctq
    rows = [{"source_id": "src-b", "outcome": "UNTRUSTED"}, {"source_id": "src-a", "outcome": "TRUSTED"}]
    prims["composite_trust_query_hash"] = (
        s2_ctq.composite_trust_query_hash(rows) == open_ctq.composite_trust_query_hash(rows)
    )
    from algovoi_substrate import settlement_binding as open_sb
    from substrate2 import settlement_binding as s2_sb
    prims["settlement_action_binding"] = (
        s2_sb.settlement_action_binding(H["a"], H["b"], H["c"], R["d"])
        == open_sb.settlement_action_binding(H["a"], H["b"], H["c"], R["d"])
    )
    from algovoi_substrate import caip as open_caip
    from substrate2 import caip as s2_caip
    prims["caip_verdicts"] = all(
        s2_caip.is_caip2(p) == open_caip.is_caip2(p)
        and s2_caip.is_valid_caip2(p) == open_caip.is_valid_caip2(p)
        for p in ("eip155:1", "eip155:1\n", "algorand", "EIP155:1", "eip155:abc", "swift:iso4217")
    )
    out["primitives"] = dict(sorted(prims.items()))

    out["_identical"] = (
        mismatched == 0
        and all(out["edge_shapes"].values())
        and all(prims.values())
        and compared > 0
    )
    return out


def main() -> int:
    report = {
        "A_source": section_source(),
        "B_vectors": section_vectors(),
        "C_primitives": section_primitives(),
        "D_receipts": section_receipts(),
        "EF_verdicts": section_verdicts(),
        "G_byte_identity": section_byte_identity(),
    }
    blob = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    digest = hashlib.sha256(blob).hexdigest()

    per_section = {
        k: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()
        for k, v in report.items()
    }

    if "--full" in sys.argv:
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
        return 0

    bi = report["G_byte_identity"]
    print(f"substrate2 {substrate2.__version__}")
    print(f"source files hashed : {len(report['A_source'])}")
    print(f"vector sets         : {len(report['B_vectors']) - 1}")
    print(f"vectors recomputed  : {sum(len(v) - 1 for v in report['B_vectors'].values() if isinstance(v, dict))}")
    print(f"primitive surfaces  : {len(report['C_primitives'])}")
    print(f"receipt surfaces    : {len(report['D_receipts'])}")
    if bi.get("_status") == "OPEN_PACKAGE_ABSENT":
        print("byte-identity       : UNPROVEN (open package not installed)")
    else:
        print(f"byte-identity       : {'IDENTICAL' if bi.get('_identical') else 'DIVERGED'} "
              f"vs algovoi-substrate {bi.get('_open_version')} "
              f"({bi.get('vector_inputs_compared')} vector inputs, "
              f"{len(bi.get('edge_shapes', {}))} edge shapes, "
              f"{len(bi.get('primitives', {}))} primitives)")
    print()
    for k in sorted(per_section):
        print(f"  {k:16} {per_section[k]}")
    print()
    print(f"REPORT_DIGEST {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
