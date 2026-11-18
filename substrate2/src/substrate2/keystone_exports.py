"""substrate2.keystone_exports — one keystone fact, many evidence formats.

The keystone is the record; an evidence format is just how that record is presented to an
outside party. This facade renders a single keystone bundle into the formats the ecosystem
already runs, each carrying the SAME decision_ref / execution_ref so they are provably the
same fact:

    native  signed keystone evidence chain (Falcon-1024 + optional ML-DSA-65)   [always]
    jws     EdDSA compact JWS over the keystone attestation                     [needs ed25519_sk]
    pef     Payment Evidence Frame wrapping the keystone refs                    [always]
    tap     Visa TAP receipt (Ed25519 + optional Falcon)                         [needs ed25519_sk]
    zkp     zkp_keystone receipt (predicate over the ref, value hidden)          [needs prover material]
    epi     evidence-package profile                                             [needs algovoi-records-vault-epi]

native / pef are unsigned-or-Falcon and always available; jws / tap need an Ed25519 key; zkp
needs a {commitment_b64, proof_b64, threshold_milliunits, issuer_did} dict from the prover; epi
needs the algovoi-records-vault-epi package (licence-gated). Returns {format: artifact}; formats
that cannot be produced are omitted from the result with a reason under result["_skipped"].
"""
from __future__ import annotations

from . import keystone_evidence as _ke
from . import tap as _tap
from . import zkp as _zkp
from .digest import sha256_jcs_prefixed
from .execution import execution_ref as _execution_ref
from .pef import build_pef


def execution_binding_ref(execution_ref: str, retention_chain_ref: str, settlement_ref: str) -> str:
    """The keystone binding over a rails settlement: ties execution_ref to the on-chain
    settlement_ref (and its retention chain). Same construction proven in keystone_rails_bind."""
    return sha256_jcs_prefixed({
        "execution_ref": execution_ref,
        "retention_chain_ref": retention_chain_ref,
        "settlement_ref": settlement_ref,
    })


def bundle_from_gateway_settlement(gateway_receipt: dict, *, decision_ref: str, trust_query_ref: str,
                                   action_type: str = "payment", scope: str = "bilateral",
                                   outcome: str = "COMMITTED", executed_at_ms: int,
                                   retention_chain_ref: str | None = None,
                                   mandate_ref: str | None = None) -> dict:
    """Build a settlement-bound keystone bundle from a REAL gateway_settlement receipt.

    The rails produce the receipt (SettlementLedger.record); this turns it into the keystone fact
    every emitter then exports. Requires receipt["authorized_by_ref"] == decision_ref (the
    settlement must be the one the keystone decision authorized)."""
    if gateway_receipt.get("authorized_by_ref") != decision_ref:
        raise ValueError("gateway receipt authorized_by_ref does not match decision_ref")
    settlement_ref = sha256_jcs_prefixed(gateway_receipt)
    er = _execution_ref(decision_ref, action_type, scope, outcome, int(executed_at_ms))
    if retention_chain_ref is None:
        retention_chain_ref = sha256_jcs_prefixed({
            "canon_version": "jcs-rfc8785-v1", "type": "retention_chain_link",
            "subject_ref": settlement_ref, "prev": None, "seq": 0,
        })
    binding_ref = execution_binding_ref(er, retention_chain_ref, settlement_ref)
    out = {
        "decision_ref": decision_ref, "execution_ref": er, "action_type": action_type,
        "scope": scope, "outcome": outcome, "executed_at_ms": int(executed_at_ms),
        "settlement_ref": settlement_ref, "retention_chain_ref": retention_chain_ref,
        "binding_ref": binding_ref, "trust_query_ref": trust_query_ref,
    }
    if mandate_ref is not None:
        out["mandate_ref"] = mandate_ref
    return out

_ATTESTATION_KEYS = (
    "decision_ref", "execution_ref", "action_type", "scope", "outcome", "executed_at_ms",
    "settlement_ref", "binding_ref", "retention_chain_ref", "trust_query_ref", "mandate_ref",
)


def keystone_attestation(bundle: dict) -> dict:
    """The canonical ref-only summary of a keystone fact (no payload, no PII)."""
    att = {"canon_version": "jcs-rfc8785-v1"}
    att.update({k: bundle[k] for k in _ATTESTATION_KEYS if k in bundle})
    return att


def export_keystone(bundle: dict, *, falcon_sk: bytes, falcon_pk: bytes,
                    ed25519_sk=None, mldsa_sk=None, mldsa_pk=None,
                    formats=("native", "jws", "pef", "tap"),
                    frame_provider_did: str = "did:web:api.algovoi.co.uk",
                    zkp_material: dict | None = None, epi_out_dir: str | None = None) -> dict:
    """Render one keystone bundle into the requested evidence formats. Every artifact carries the
    same decision_ref/execution_ref. See module docstring for per-format requirements."""
    att = keystone_attestation(bundle)
    out: dict = {"_attestation": att, "_skipped": {}}

    if "native" in formats:
        cores = _ke.keystone_evidence_cores(bundle)
        out["native"] = _ke.build_keystone_evidence_chain(cores, falcon_sk, falcon_pk, mldsa_sk, mldsa_pk)

    if "jws" in formats:
        if ed25519_sk is None:
            out["_skipped"]["jws"] = "ed25519_sk required"
        else:
            from .jws import sign_receipt
            out["jws"] = sign_receipt(att, private_key=ed25519_sk)

    if "pef" in formats:
        out["pef"] = build_pef(claim_type="payment_execution", receipt=att,
                               frame_provider_did=frame_provider_did,
                               frame_timestamp_ms=int(bundle["executed_at_ms"]))

    if "tap" in formats:
        if ed25519_sk is None:
            out["_skipped"]["tap"] = "ed25519_sk required"
        else:
            out["tap"] = _tap.tap_from_keystone(bundle, ed25519_sk=ed25519_sk,
                                                falcon_sk=falcon_sk, falcon_pk=falcon_pk)

    if "zkp" in formats:
        if not zkp_material:
            out["_skipped"]["zkp"] = "zkp_material (commitment_b64, proof_b64, threshold_milliunits, issuer_did) required"
        elif not bundle.get("mandate_ref"):
            out["_skipped"]["zkp"] = "bundle.mandate_ref required as the predicate bound_source"
        else:
            out["zkp"] = _zkp.zkp_from_keystone(
                bundle, commitment_b64=zkp_material["commitment_b64"],
                proof_b64=zkp_material["proof_b64"],
                threshold_milliunits=zkp_material["threshold_milliunits"],
                issuer_did=zkp_material["issuer_did"], secret_key=falcon_sk, public_key=falcon_pk,
                expires_at=zkp_material.get("expires_at", "2030-01-01T00:00:00Z"),
                issued_at=zkp_material.get("issued_at", "2026-01-01T00:00:00Z"),
                predicate=zkp_material.get("predicate"))

    if "epi" in formats:
        try:
            from algovoi_records_vault_epi import export_epi
        except ImportError:
            out["_skipped"]["epi"] = "algovoi-records-vault-epi not installed"
        else:
            if epi_out_dir is None:
                out["_skipped"]["epi"] = "epi_out_dir required"
            else:
                try:
                    cores = _ke.keystone_evidence_cores(bundle)
                    envelopes = _ke.build_keystone_evidence_chain(cores, falcon_sk, falcon_pk, mldsa_sk, mldsa_pk)
                    out["epi"] = export_epi(streams={"keystone": envelopes}, public_key=falcon_pk,
                                            secret_key=falcon_sk, out_dir=epi_out_dir,
                                            artifact_id="urn:algovoi:epi:keystone")
                except Exception as exc:  # licence-gated or runtime issue: skip, do not fail the facade
                    out["_skipped"]["epi"] = f"epi export unavailable: {type(exc).__name__}"

    return out


def refs_consistent(exported: dict, decision_ref: str, execution_ref: str) -> bool:
    """Confirm every produced format carries the same decision_ref/execution_ref (the proof that
    they are presentations of one keystone fact, not different facts).

    The old substring-in-blob test passed as long as the expected refs appeared *anywhere*
    (they always do, via ``_attestation``), so a format artifact carrying a DIFFERENT ref
    still passed; an empty ref matched unconditionally. This walks the structure and requires
    every occurrence of a decision_ref / execution_ref field to EQUAL the expected value, and
    at least one of each to be present. Empty expected refs are rejected."""
    if not isinstance(decision_ref, str) or not decision_ref:
        return False
    if not isinstance(execution_ref, str) or not execution_ref:
        return False

    def _collect(obj, key, acc):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == key and isinstance(v, str):
                    acc.append(v)
                _collect(v, key, acc)
        elif isinstance(obj, list):
            for v in obj:
                _collect(v, key, acc)

    d_refs: list[str] = []
    e_refs: list[str] = []
    _collect(exported, "decision_ref", d_refs)
    _collect(exported, "execution_ref", e_refs)
    return (bool(d_refs) and all(r == decision_ref for r in d_refs)
            and bool(e_refs) and all(r == execution_ref for r in e_refs))


__all__ = ["keystone_attestation", "export_keystone", "refs_consistent",
           "execution_binding_ref", "bundle_from_gateway_settlement"]
