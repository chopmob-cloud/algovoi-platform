"""
algovoi-atb-credential-verifier
================================
Standalone verifier for AlgoVoi ATB Pass Certificates.

Verifies X-ATB-Credential (Phase 1, Falcon-1024) and
X-ATB-ZK-Credential (Phase 2, Bulletproofs ZKP) headers.

IETF anchor: draft-hopley-x402-atb-reputation-credential-00
Docs: https://docs.algovoi.co.uk/atb-reputation-credential

Quick start
-----------
Phase 1 (cleartext score):

    from algovoi_atb_credential_verifier import ATBCredentialVerifier

    verifier = ATBCredentialVerifier(
        issuer_did="did:web:agent-trust-bench.algovoi.co.uk",
        public_key_b64="<Falcon-1024 PK from /.well-known/atb-keys.json>",
    )
    result = verifier.verify(request.headers.get("X-ATB-Credential"))
    if result.grants_discount:
        price = int(price * 0.80)

Phase 2 (ZKP — no score revealed):

    result = await verifier.verify_zkp_async(
        header_value=request.headers.get("X-ATB-ZK-Credential"),
        zkp_service_url="http://localhost:8091",
    )
    # result.passed = True means score >= threshold (proven, not asserted)
"""
from algovoi_atb_credential_verifier.verifier import (
    ATBCredentialVerifier,
    ATBVerifyResult,
)
from algovoi_atb_credential_verifier.hub_resolver import fetch_hub_keys

__all__ = [
    "ATBCredentialVerifier",
    "ATBVerifyResult",
    "fetch_hub_keys",
]
__version__ = "0.1.1"
