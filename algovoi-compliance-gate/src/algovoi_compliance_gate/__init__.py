"""
algovoi-compliance-gate — turn a screening decision into a signed, no-PII compliance receipt.

Screen a payer (sanctions / PEP / AML via **your injected provider**), map to a categorical
**ALLOW / REFER / DENY** verdict, and emit a **Falcon-1024-signed** receipt whose payer reference is
``sha256(network:address)`` — never the cleartext. It is the **origination side of Proofs**: the
receipt this produces is exactly what ``algovoi-proofs`` binds and proves.

Embed::

    from algovoi_compliance_gate import ComplianceGate, DenylistScreener, verify_compliance_receipt, signing

    pk, sk = signing.generate_keypair()
    gate = ComplianceGate(secret_key=sk, public_key=pk,
                          screener=DenylistScreener(deny={"0xBAD…"}),   # or your own Screener
                          gate_did="did:web:compliance.acme.com")
    out = await gate.screen_and_certify(network="base", address="0x…")
    #   out["result"] in {ALLOW, REFER, DENY}; out["receipt"], out["receipt_envelope"], out["receipt_hash"]
    assert verify_compliance_receipt(out["receipt_envelope"], pk).verified

Run as a service::

    from algovoi_compliance_gate import create_app, ComplianceGate, AllowAllScreener, bearer_token_auth
    app = create_app(ComplianceGate(secret_key=sk, public_key=pk, screener=AllowAllScreener()),
                     public_key=pk, auth_dependency=bearer_token_auth("tok"))

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_compliance_gate import hub_client, signing
from algovoi_compliance_gate.app import create_app
from algovoi_compliance_gate.auth import bearer_token_auth
from algovoi_compliance_gate.checks import (
    OBLIGATIONS,
    REASON_CODES,
    Check,
    CheckResult,
    JurisdictionCheck,
    PepCheck,
    RiskThresholdCheck,
    SanctionsCheck,
    TravelRuleCheck,
)
from algovoi_compliance_gate.evidence_export import export_evidence_pack, verify_evidence_pack
from algovoi_compliance_gate.gate import ENTRY_TYPE, ComplianceGate
from algovoi_compliance_gate.models import (
    CertifiedScreenResult,
    ScreenRequest,
    VerifyRequest,
    VerifyResult,
)
from algovoi_compliance_gate.policy import combine, default_policy
from algovoi_compliance_gate.screener import (
    AllowAllScreener,
    DenylistScreener,
    ScreenResult,
    Screener,
)
from algovoi_compliance_gate.verifier import verify_compliance_receipt

__version__ = "0.2.0"

__all__ = [
    "ComplianceGate",
    "ENTRY_TYPE",
    "verify_compliance_receipt",
    "Screener",
    "ScreenResult",
    "AllowAllScreener",
    "DenylistScreener",
    "Check",
    "CheckResult",
    "SanctionsCheck",
    "PepCheck",
    "JurisdictionCheck",
    "RiskThresholdCheck",
    "TravelRuleCheck",
    "REASON_CODES",
    "OBLIGATIONS",
    "default_policy",
    "combine",
    "export_evidence_pack",
    "verify_evidence_pack",
    "create_app",
    "bearer_token_auth",
    "hub_client",
    "signing",
    "ScreenRequest",
    "CertifiedScreenResult",
    "VerifyRequest",
    "VerifyResult",
    "__version__",
]
