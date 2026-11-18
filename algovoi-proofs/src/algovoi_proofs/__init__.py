"""
AlgoVoi Proofs — privacy-preserving compliance proofs.

Mint a zero-knowledge proof that a payment was screened/compliant and the payer's score is above
a threshold, **without revealing PII or the score**; verify it publicly with a post-quantum
(Falcon-1024) issuer signature. Self-contained: inject your Falcon key + a Bulletproofs prover URL.
"""
from __future__ import annotations

from algovoi_proofs import compliance, signing, zkp_envelope
from algovoi_proofs.app import create_app
from algovoi_proofs.issuer import ProofIssuer
from algovoi_proofs.models import (
    IssueRequest,
    IssueResponse,
    PaymentIn,
    VerifyRequest,
    VerifyResult,
)
from algovoi_proofs.prover import ProverClient, ProverUnavailable
from algovoi_proofs.verifier import verify_proof

__version__ = "0.1.1"

__all__ = [
    "__version__",
    "create_app",
    "ProofIssuer",
    "ProverClient",
    "ProverUnavailable",
    "verify_proof",
    "IssueRequest",
    "IssueResponse",
    "VerifyRequest",
    "VerifyResult",
    "PaymentIn",
    "signing",
    "compliance",
    "zkp_envelope",
]
