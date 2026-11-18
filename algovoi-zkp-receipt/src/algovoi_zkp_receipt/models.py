"""Data models for ZKP-bound payment receipt attestation."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal


# Supported x402 chains.
Chain = Literal[
    "algorand", "voi", "hedera", "stellar", "base", "solana", "tempo", "polygon"
]


@dataclass
class PaymentReceipt:
    """On-chain payment receipt from a settled x402 transaction."""

    payment_id: str    # gateway-assigned payment UUID
    chain: Chain
    amount_microusd: int
    recipient: str     # chain-specific address
    tx_id: str         # on-chain transaction identifier
    settled_at: str    # ISO 8601 UTC


@dataclass
class ZkpReceiptEnvelope:
    """Parsed ZKP receipt envelope (pre-verification).

    A ZKP receipt is a Falcon-1024-signed envelope whose payload contains
    both payment receipt fields and ATB ZKP credential fields. The Falcon
    signature covers ALL fields — receipt and credential together. This
    proves: "the agent that made this specific payment has ATB score ≥
    threshold."

    v0.1: The ZKP range proof uses the standard ATB transcript (threshold-
    bound but not payment-bound). v0.2 will add payment-bound transcript
    domain separation for replay prevention across payments.
    """

    raw_b64url: str
    alg: str
    kid: str
    issuer_did: str
    payment_id: str
    chain: str
    amount_microusd: int
    recipient: str
    tx_id: str
    settled_at: str
    commitment_b64: str
    proof_b64: str
    threshold_milliunits: int
    expires_at: datetime
    issued_at: datetime | None = None


@dataclass
class ZkpReceiptVerifyResult:
    """Result of verifying a ZKP receipt envelope."""

    valid: bool
    payment_id: str | None = None
    chain: str | None = None
    amount_microusd: int | None = None
    tx_id: str | None = None
    issuer_did: str | None = None
    kid: str | None = None
    expires_at: datetime | None = None
    failure_reason: str | None = None
