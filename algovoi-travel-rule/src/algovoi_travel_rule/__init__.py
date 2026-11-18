"""
algovoi-travel-rule — FATF Travel Rule (Recommendation 16) as a signed, no-PII, PQC-confidential
evidence flow.

Determine whether the Travel Rule applies to a transfer, exchange the IVMS101 originator/beneficiary
payload **post-quantum** (ML-KEM-1024 + AES-256-GCM) VASP-to-VASP, and emit a **Falcon-1024-signed**
Travel Rule receipt whose only reference to the PII is `ivms101_hash = sha256(JCS(ivms101))`. The
receipt binds into the Substrate 2 evidence chain and verifies offline from the issuer public key.

Embed::

    from algovoi_travel_rule import TravelRule, IVMS101, Person, verify_travel_rule_receipt, signing
    from algovoi_travel_rule.encryption import generate_mlkem_keypair

    pk, sk = signing.generate_keypair()                       # originating VASP signing key
    tr = TravelRule(secret_key=sk, public_key=pk, originating_vasp_did="did:web:vasp.acme")

    ivms = IVMS101(originator=Person(name="A", account="0x.."), beneficiary=Person(name="B", account="0x.."))
    out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:vasp.beta",
                     amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
    assert verify_travel_rule_receipt(out["receipt_envelope"], pk).verified

    # PQC-seal the PII to the beneficiary VASP and exchange:
    bpk, bsk = generate_mlkem_keypair()
    sealed = tr.seal_ivms101(ivms101=ivms, beneficiary_mlkem_pubkey=bpk)
    received = TravelRule.open_ivms101(sealed_b64=sealed, mlkem_secret=bsk)

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""
from __future__ import annotations

from algovoi_travel_rule import licensing, signing
from algovoi_travel_rule.encryption import HybridPqcEncryptor, generate_mlkem_keypair
from algovoi_travel_rule.models import (
    CertifyRequest,
    IVMS101,
    Person,
    TransferAmount,
    VerifyRequest,
    VerifyResult,
)
from algovoi_travel_rule.travel_rule import TravelRule, TravelRuleError
from algovoi_travel_rule.verifier import verify_ivms101_binding, verify_travel_rule_receipt

__version__ = "0.1.1"

__all__ = [
    "TravelRule",
    "TravelRuleError",
    "IVMS101",
    "Person",
    "TransferAmount",
    "CertifyRequest",
    "VerifyRequest",
    "VerifyResult",
    "verify_travel_rule_receipt",
    "verify_ivms101_binding",
    "generate_mlkem_keypair",
    "HybridPqcEncryptor",
    "signing",
    "licensing",
    "__version__",
]
