"""
substrate2 — INTERNAL, provenance-clean reimplementation of the AlgoVoi substrate.

DO NOT PUBLISH. Local-only. See README.md and PROVENANCE.md.

The umbrella namespace re-exports the stable public surface. compat.v1_shim (Phase 5) maps
these to the old v1 import paths for drop-in cutover.
"""
from __future__ import annotations

__version__ = "2.0.0"

from .canon import (  # noqa: F401
    CANON_VERSION,
    CanonicalizationError,
    canonicalize,
    canonicalize_bytes,
)
from .digest import (  # noqa: F401
    SHA256_PREFIX,
    sha256_hex,
    sha256_jcs,
    sha256_jcs_prefixed,
)
from .action import ActionRefError, action_ref, action_ref_object  # noqa: F401
from .execution import (  # noqa: F401
    EXECUTION_OUTCOMES,
    ExecutionRefError,
    execution_ref,
    execution_ref_object,
    screen_binding_ref,
)
from .execution_evidence import (  # noqa: F401
    build_execution_evidence_chain,
    execution_evidence_core,
    export_execution_evidence_pack,
)
from .composite_trust_query import (  # noqa: F401
    CompositeTrustQueryError,
    composite_trust_query_hash,
)
from .audit import (  # noqa: F401
    AuditChainError,
    AuditChainRow,
    append_to_chain,
    verify_audit_chain,
)
from .transactional import (  # noqa: F401
    TransactionalChain,
    TransactionalError,
    build_transactional_action_chain,
    transition_hash,
    transition_preimage,
)
from .receipts.compliance import (  # noqa: F401
    SCREEN_RESULTS,
    ComplianceReceipt,
    ComplianceReceiptError,
    build_compliance_receipt,
)
from .receipts.settlement import (  # noqa: F401
    SETTLEMENT_RESULTS,
    SettlementAttestationError,
    build_settlement_attestation,
)
from .compliance_basis import (  # noqa: F401  COMMERCIAL keep (not open / corpus / IETF / docs)
    OBLIGATIONS,
    REASON_CODES,
    ComplianceBasisError,
    basis_binding_ref,
    basis_ref,
    check_entry,
    compliance_basis,
)
from .receipts.refund import REFUND_RESULTS, RefundReceiptError, build_refund_receipt  # noqa: F401
from .receipts.cancellation import (  # noqa: F401
    CANCELLATION_REASONS,
    CancellationReceiptError,
    build_cancellation_receipt,
)
from .receipts.ctq import TRUST_OUTCOMES, CtqResponseError, build_ctq_response  # noqa: F401
from .pef import build_pef, pef_frame_id, verify_pef  # noqa: F401
from .retention_chain import (  # noqa: F401
    RetentionChainError,
    SignedChainLinkResult,
    retention_chain_ref,
    verify_chain_link,
    verify_chain_sequence,
    verify_signed_chain_link,
)
from .policy_binding import (  # noqa: F401
    POLICY_BINDING_VERSION,
    PolicyBindingError,
    policy_bound_ref,
    policy_ref,
    verify_policy_binding,
)
from .httpsig import (  # noqa: F401
    DEFAULT_COVERED,
    SignError,
    SignResult,
    sign_request,
    verify_request,
)
from .freshness import FreshnessError  # noqa: F401  RFC 9421 signature-freshness error
# NB: `check_freshness` is intentionally NOT re-exported here: the umbrella already
# binds that name to keystone_secure's validity-window check. The RFC 9421 freshness
# helper is reachable as substrate2.rfc9421_verifier.check_freshness / .freshness.check_freshness.
from .jws import (  # noqa: F401
    ReceiptVerificationError,
    VerifiedReceipt,
    did_key_for,
    jwk_for,
    kid_for,
    sign_receipt,
    verify_compliance_receipt,
)
from . import pqc  # noqa: F401
from .atb_credential import (  # noqa: F401
    ATBVerifyResult,
    build_atb_envelope_b64,
    verify_atb_envelope,
)
from .zkp import (  # noqa: F401
    PaymentReceipt,
    ZkpReceiptEnvelope,
    ZkpReceiptVerifyResult,
    build_zkp_keystone_payload,
    build_zkp_receipt_payload,
    prove_range_b64,
    verify_zkp_keystone,
    verify_zkp_receipt,
    zkp_from_keystone,
)
from .federation import (  # noqa: F401
    CredentialVerifyResult,
    FederationResult,
    FederationToken,
    FederationValidator,
    IssuerEntry,
    compose_commitments,
    issue_federation_token,
    verify_federation_token,
    verify_pqc_credential,
)
from .tap import (  # noqa: F401
    sign_tap_receipt,
    tap_from_keystone,
    tap_receipt_preimage,
    verify_tap_receipt,
)
from .keystone_exports import (  # noqa: F401
    bundle_from_gateway_settlement,
    execution_binding_ref,
    export_keystone,
    keystone_attestation,
    refs_consistent,
)
from .keystone_secure import (  # noqa: F401  COMMERCIAL keep: flow-point hardening refs
    KeystoneSecureError,
    REVOCATION_REASONS,
    STATUS_VALUES,
    check_freshness,
    decision_audit_ref,
    guard_context_ref,
    revocation_ref,
    verify_decision_audit,
    verify_revocation_chain,
    with_validity,
)
from .caip import (  # noqa: F401  CAIP-2/10/19; mirrors algovoi_substrate.caip byte-for-byte
    CaipError,
    caip10_of,
    caip19_slip44,
    is_caip2,
    is_caip10,
    is_caip19,
    is_registered_caip2,
    is_valid_caip2,
    registered_namespaces,
    require_caip2,
    require_caip10,
    require_caip19,
    require_registered_caip2,
    require_valid_caip2,
)
from .settlement_binding import (  # noqa: F401
    SettlementBindingError,
    settlement_action_binding,
    settlement_binding_preimage,
)
from .vc import (  # noqa: F401  W3C VC 2.0 (ratified) + SD-JWT VC (draft, labelled)
    ATB_VCT,
    VC2_CONTEXT,
    VcError,
    is_vc2,
    secure_vc_jose,
    sd_jwt_vc_issuer_jwt,
    to_sd_jwt_vc,
    to_vc,
    verify_vc_binding,
)
from .timestamp import (  # noqa: F401  RFC 3161; needs substrate2[timestamp] at call time
    TimestampError,
    TimestampResult,
    TimestampToken,
    build_chain_timestamp,
    chain_timestamp_preimage,
    chain_timestamp_ref,
    fetch_timestamp,
    parse_timestamp_response,
    timestamp_request,
    verify_chain_timestamp,
    verify_timestamp_token,
)

__all__ = [
    "__version__",
    "CANON_VERSION", "CanonicalizationError", "canonicalize", "canonicalize_bytes",
    "SHA256_PREFIX", "sha256_hex", "sha256_jcs", "sha256_jcs_prefixed",
    "ActionRefError", "action_ref", "action_ref_object",
    "EXECUTION_OUTCOMES", "ExecutionRefError", "execution_ref", "execution_ref_object",
    "screen_binding_ref",
    "build_execution_evidence_chain", "execution_evidence_core", "export_execution_evidence_pack",
    "CompositeTrustQueryError", "composite_trust_query_hash",
    "AuditChainError", "AuditChainRow", "append_to_chain", "verify_audit_chain",
    "TransactionalChain", "TransactionalError", "build_transactional_action_chain",
    "transition_hash", "transition_preimage",
    "SCREEN_RESULTS", "ComplianceReceipt", "ComplianceReceiptError", "build_compliance_receipt",
    "SETTLEMENT_RESULTS", "SettlementAttestationError", "build_settlement_attestation",
    "REFUND_RESULTS", "RefundReceiptError", "build_refund_receipt",
    "CANCELLATION_REASONS", "CancellationReceiptError", "build_cancellation_receipt",
    "TRUST_OUTCOMES", "CtqResponseError", "build_ctq_response",
    "build_pef", "pef_frame_id", "verify_pef",
    "POLICY_BINDING_VERSION", "PolicyBindingError", "policy_bound_ref", "policy_ref",
    "verify_policy_binding",
    "REASON_CODES", "OBLIGATIONS", "ComplianceBasisError", "check_entry", "compliance_basis",
    "basis_ref", "basis_binding_ref",
    "DEFAULT_COVERED", "SignError", "SignResult", "sign_request", "verify_request",
    "FreshnessError",
    "ReceiptVerificationError", "VerifiedReceipt", "did_key_for", "jwk_for", "kid_for",
    "sign_receipt", "verify_compliance_receipt",
    "pqc",
    "ATBVerifyResult", "build_atb_envelope_b64", "verify_atb_envelope",
    "PaymentReceipt", "ZkpReceiptEnvelope", "ZkpReceiptVerifyResult",
    "build_zkp_receipt_payload", "verify_zkp_receipt",
    "build_zkp_keystone_payload", "zkp_from_keystone", "verify_zkp_keystone", "prove_range_b64",
    "CredentialVerifyResult", "FederationResult", "FederationToken", "FederationValidator",
    "IssuerEntry", "compose_commitments", "issue_federation_token", "verify_federation_token",
    "verify_pqc_credential",
    "sign_tap_receipt", "tap_from_keystone", "tap_receipt_preimage", "verify_tap_receipt",
    "export_keystone", "keystone_attestation", "refs_consistent",
    "bundle_from_gateway_settlement", "execution_binding_ref",
    "KeystoneSecureError", "REVOCATION_REASONS", "STATUS_VALUES",
    "decision_audit_ref", "verify_decision_audit", "revocation_ref", "verify_revocation_chain",
    "guard_context_ref", "with_validity", "check_freshness",
    "CaipError", "is_caip2", "is_caip10", "is_caip19",
    "require_caip2", "require_caip10", "require_caip19",
    "is_registered_caip2", "require_registered_caip2", "is_valid_caip2", "require_valid_caip2",
    "registered_namespaces", "caip10_of", "caip19_slip44",
    "SettlementBindingError", "settlement_action_binding", "settlement_binding_preimage",
    "TimestampError", "TimestampToken", "TimestampResult",
    "timestamp_request", "fetch_timestamp", "parse_timestamp_response", "verify_timestamp_token",
    "chain_timestamp_preimage", "chain_timestamp_ref", "build_chain_timestamp",
    "verify_chain_timestamp",
    "VcError", "VC2_CONTEXT", "ATB_VCT", "to_vc", "is_vc2", "verify_vc_binding",
    "secure_vc_jose", "to_sd_jwt_vc", "sd_jwt_vc_issuer_jwt",
]
