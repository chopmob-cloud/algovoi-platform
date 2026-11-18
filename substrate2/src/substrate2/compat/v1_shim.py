"""
substrate2.compat.v1_shim — register the old v1 module names in sys.modules, backed by
substrate2, so existing `from algovoi_substrate... import ...` (and sibling packages)
resolve to substrate2 with no code change at the call sites.

Cutover: an in-tree bootstrap calls install() when SUBSTRATE2_ENABLED=1, before the
gateway's imports resolve. Flag off -> the real v1 packages load unchanged. install() is
idempotent and reversible via uninstall().
"""
from __future__ import annotations

import sys
import types

_INSTALLED: list[str] = []


def installed() -> bool:
    """True once install() has registered the v1 compat aliases in sys.modules.

    A genuine runtime signal (not a static flag): used by the gateway /health endpoint to
    report which substrate is actually serving, so the 'Substrate 2 in production' claim is
    independently observable rather than assertion-only.
    """
    return bool(_INSTALLED)


def _mod(name: str, attrs: dict, *, is_pkg: bool = False) -> types.ModuleType:
    m = types.ModuleType(name)
    if is_pkg:
        m.__path__ = []  # mark as a package so submodule imports resolve
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[name] = m
    _INSTALLED.append(name)
    return m


def install() -> None:
    """Register all v1 module aliases backed by substrate2. Idempotent."""
    from substrate2 import canon, digest, action, audit, transactional as tx, httpsig, jws, pqc, pef
    from substrate2 import composite_trust_query as _ctq
    from substrate2.receipts import compliance, settlement, refund, cancellation, ctq
    from substrate2 import atb_credential, zkp, federation
    from substrate2 import caip as _caip
    from substrate2 import settlement_binding as _sbind

    # ---- algovoi_substrate (+ submodules) ----
    sub = {
        "CANON_VERSION": canon.CANON_VERSION,
        "CanonicalizationError": canon.CanonicalizationError,
        "canonicalize": canon.canonicalize,
        "canonicalize_bytes": canon.canonicalize_bytes,
        "sha256_jcs": digest.sha256_jcs,
        "action_ref": action.action_ref,
        "action_ref_object": action.action_ref_object,
        "ActionRefError": action.ActionRefError,
        "SCREEN_RESULTS": compliance.SCREEN_RESULTS,
        "ComplianceReceipt": compliance.ComplianceReceipt,
        "ComplianceReceiptError": compliance.ComplianceReceiptError,
        "build_compliance_receipt": compliance.build_compliance_receipt,
        "AuditChainError": audit.AuditChainError,
        "AuditChainRow": audit.AuditChainRow,
        "append_to_chain": audit.append_to_chain,
        "verify_audit_chain": audit.verify_audit_chain,
        "TransactionalChain": tx.TransactionalChain,
        "TransactionalError": tx.TransactionalError,
        "TransitionInput": tx.TransitionInput,
        "TransitionPreimage": tx.TransitionPreimage,
        "TransitionRecord": tx.TransitionRecord,
        "build_transactional_action_chain": tx.build_transactional_action_chain,
        "transition_hash": tx.transition_hash,
        "transition_preimage": tx.transition_preimage,
        "CompositeTrustQueryError": _ctq.CompositeTrustQueryError,
        "composite_trust_query_hash": _ctq.composite_trust_query_hash,
        # caip + settlement_binding: shipped by algovoi-substrate 0.5.x and previously
        # unmapped here, so `from algovoi_substrate import caip` raised under the shim
        # while working fine on v1. test_shim_completeness.py now fails on that class of
        # drift rather than leaving it to be found by hand.
        "CaipError": _caip.CaipError,
        "is_caip2": _caip.is_caip2,
        "is_caip10": _caip.is_caip10,
        "is_caip19": _caip.is_caip19,
        "require_caip2": _caip.require_caip2,
        "require_caip10": _caip.require_caip10,
        "require_caip19": _caip.require_caip19,
        "SettlementBindingError": _sbind.SettlementBindingError,
        "settlement_action_binding": _sbind.settlement_action_binding,
        "settlement_binding_preimage": _sbind.settlement_binding_preimage,
    }
    _mod("algovoi_substrate", sub, is_pkg=True)
    _mod("algovoi_substrate.caip", {
        k: getattr(_caip, k) for k in dir(_caip) if not k.startswith("_")
    })
    _mod("algovoi_substrate.settlement_binding", {
        "settlement_action_binding": _sbind.settlement_action_binding,
        "settlement_binding_preimage": _sbind.settlement_binding_preimage,
        "SettlementBindingError": _sbind.SettlementBindingError,
        "SettlementBindingPreimage": _sbind.SettlementBindingPreimage,
    })
    _mod("algovoi_substrate.canonicalize", {
        "canonicalize": canon.canonicalize, "canonicalize_bytes": canon.canonicalize_bytes,
        "sha256_jcs": digest.sha256_jcs, "CANON_VERSION": canon.CANON_VERSION,
        "CanonicalizationError": canon.CanonicalizationError,
    })
    _mod("algovoi_substrate.action_ref", {
        "action_ref": action.action_ref, "action_ref_object": action.action_ref_object,
        "ActionRefError": action.ActionRefError,
    })
    _mod("algovoi_substrate.audit_chain", {
        "append_to_chain": audit.append_to_chain, "verify_audit_chain": audit.verify_audit_chain,
        "AuditChainRow": audit.AuditChainRow, "AuditChainError": audit.AuditChainError,
    })
    _mod("algovoi_substrate.compliance_receipt", {
        "build_compliance_receipt": compliance.build_compliance_receipt,
        "SCREEN_RESULTS": compliance.SCREEN_RESULTS, "ComplianceReceipt": compliance.ComplianceReceipt,
        "ComplianceReceiptError": compliance.ComplianceReceiptError,
    })
    _mod("algovoi_substrate.transactional", {
        "transition_preimage": tx.transition_preimage, "transition_hash": tx.transition_hash,
        "build_transactional_action_chain": tx.build_transactional_action_chain,
        "TransactionalChain": tx.TransactionalChain, "TransactionalError": tx.TransactionalError,
        "TransitionInput": tx.TransitionInput, "TransitionPreimage": tx.TransitionPreimage,
        "TransitionRecord": tx.TransitionRecord,
    })
    _mod("algovoi_substrate.composite_trust_query", {
        "composite_trust_query_hash": _ctq.composite_trust_query_hash,
        "CompositeTrustQueryError": _ctq.CompositeTrustQueryError,
    })

    # ---- RFC 9421 signer / verifier ----
    _mod("algovoi_rfc9421_signer", {
        "sign_request": httpsig.sign_request, "SignError": httpsig.SignError,
        "SignResult": httpsig.SignResult, "DEFAULT_COVERED": httpsig.DEFAULT_COVERED,
    })
    from substrate2 import rfc9421_verifier as rv
    _mod("algovoi_rfc9421_verifier", {
        "SignatureInputParseError": rv.SignatureInputParseError, "SigningBaseError": rv.SigningBaseError,
        "ContentDigestError": rv.ContentDigestError, "VerifyError": rv.VerifyError,
        "ParsedSignatureInput": rv.ParsedSignatureInput, "VerifyResult": rv.VerifyResult,
        "parse_signature_input": rv.parse_signature_input, "parse_signature_value": rv.parse_signature_value,
        "build_signing_base": rv.build_signing_base, "compute_content_digest": rv.compute_content_digest,
        "verify_content_digest": rv.verify_content_digest, "verify_signature": rv.verify_signature,
        "verify_request": rv.verify_request,
    }, is_pkg=True)
    # Submodule paths the gateway imports from (e.g. compliance_gate.py:574).
    _mod("algovoi_rfc9421_verifier.parse", {
        "parse_signature_input": rv.parse_signature_input, "parse_signature_value": rv.parse_signature_value,
        "SignatureInputParseError": rv.SignatureInputParseError, "ParsedSignatureInput": rv.ParsedSignatureInput,
    })
    _mod("algovoi_rfc9421_verifier.signing_base", {
        "build_signing_base": rv.build_signing_base, "SigningBaseError": rv.SigningBaseError,
    })
    _mod("algovoi_rfc9421_verifier.content_digest", {
        "compute_content_digest": rv.compute_content_digest, "verify_content_digest": rv.verify_content_digest,
        "ContentDigestError": rv.ContentDigestError,
    })
    _mod("algovoi_rfc9421_verifier.verify", {
        "verify_request": rv.verify_request, "verify_signature": rv.verify_signature,
        "VerifyResult": rv.VerifyResult, "VerifyError": rv.VerifyError,
    })

    # ---- receipt sibling packages ----
    _mod("algovoi_settlement_attestation", {
        "SETTLEMENT_RESULTS": settlement.SETTLEMENT_RESULTS,
        "SettlementAttestationError": settlement.SettlementAttestationError,
        "build_settlement_attestation": settlement.build_settlement_attestation,
    })
    _mod("algovoi_refund_receipt", {
        "REFUND_RESULTS": refund.REFUND_RESULTS, "RefundReceiptError": refund.RefundReceiptError,
        "build_refund_receipt": refund.build_refund_receipt,
    })
    _mod("algovoi_cancellation_receipt", {
        "CANCELLATION_REASONS": cancellation.CANCELLATION_REASONS,
        "CancellationReceiptError": cancellation.CancellationReceiptError,
        "build_cancellation_receipt": cancellation.build_cancellation_receipt,
    })
    _mod("algovoi_composite_trust_query", {
        "TRUST_OUTCOMES": ctq.TRUST_OUTCOMES, "CtqResponseError": ctq.CtqResponseError,
        "build_ctq_response": ctq.build_ctq_response,
    })
    _mod("algovoi_pef", {
        "PEF_VERSION": pef.PEF_VERSION, "CANON_VERSION": pef.CANON_VERSION,
        "RECEIPT_FORMAT": pef.RECEIPT_FORMAT, "CLAIM_TYPES": pef.CLAIM_TYPES, "PefError": pef.PefError,
        "build_pef": pef.build_pef, "pef_frame_id": pef.pef_frame_id, "verify_pef": pef.verify_pef,
    })
    # algovoi_receipt_verifier — substrate2.jws now implements the full verifier contract:
    # ReceiptVerificationError(*, code, message, field) with the 9-code ERROR_CODES set, a
    # VerifiedReceipt (raw_payload/alg/kid/canon_version/screen_result/...), and decode_jws/
    # verify_jws/verify_compliance_receipt with the keyword (public_key=, jwks=) signature the
    # gateway (receipt_verify.py) and the reused algovoi-receipt-verifier suite both expect.
    _mod("algovoi_receipt_verifier", {
        "ERROR_CODES": jws.ERROR_CODES,
        "ReceiptVerificationError": jws.ReceiptVerificationError,
        "VerifiedReceipt": jws.VerifiedReceipt,
        "decode_jws": jws.decode_jws,
        "verify_jws": jws.verify_jws,
        "public_key_from_jwk": jws.public_key_from_jwk,
        "verify_compliance_receipt": jws.verify_compliance_receipt,
    })

    # ---- ZKP / federation ----
    _mod("algovoi_zkp_receipt", {
        "PaymentReceipt": zkp.PaymentReceipt, "ZkpReceiptEnvelope": zkp.ZkpReceiptEnvelope,
        "ZkpReceiptVerifyResult": zkp.ZkpReceiptVerifyResult,
        "build_zkp_receipt_payload": zkp.build_zkp_receipt_payload,
        "verify_zkp_receipt": zkp.verify_zkp_receipt,
    })
    _mod("algovoi_federation_validator", {
        "FederationValidator": federation.FederationValidator,
        "FederationResult": federation.FederationResult, "FederationToken": federation.FederationToken,
        "IssuerEntry": federation.IssuerEntry, "CredentialVerifyResult": federation.CredentialVerifyResult,
        "compose_commitments": federation.compose_commitments,
        "verify_pqc_credential": federation.verify_pqc_credential,
        "issue_federation_token": federation.issue_federation_token,
        "verify_federation_token": federation.verify_federation_token,
    })

    from substrate2 import atb_credential_verifier as acv
    _mod("algovoi_atb_credential_verifier", {
        "ATBCredentialVerifier": acv.ATBCredentialVerifier, "ATBVerifyResult": acv.ATBVerifyResult,
        "fetch_hub_keys": acv.fetch_hub_keys, "clear_key_cache": acv.clear_key_cache,
    })


def uninstall() -> None:
    for name in _INSTALLED:
        sys.modules.pop(name, None)
    _INSTALLED.clear()


__all__ = ["install", "uninstall"]
