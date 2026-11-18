"""Data models for the AlgoVoi federation token validator."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class PqcCredentialFields:
    """Parsed fields extracted from a PQC credential envelope before verification."""

    raw_b64url: str
    alg: str                         # "Falcon-1024" or "ML-DSA-65"
    kid: str                         # hex key-id (sha256 truncated)
    issuer_did: str                  # bench_issuer DID from payload
    commitment_b64: str              # Bulletproofs Pedersen commitment (base64 standard)
    proof_b64: str                   # Bulletproofs range proof (base64 standard)
    threshold_milliunits: int        # range proof lower bound (0–1000)
    expires_at: datetime
    issued_at: datetime | None = None
    methodology_version: str | None = None
    cert_version: str = "2"          # "2" = Phase 2 ZKP cert


@dataclass
class CredentialVerifyResult:
    """Result of verifying a single PQC credential (Falcon-1024 sig + structural ZKP check)."""

    valid: bool
    issuer_did: str | None = None
    kid: str | None = None
    alg: str | None = None
    commitment_b64: str | None = None  # present only if valid=True
    proof_b64: str | None = None       # present only if valid=True
    threshold_milliunits: int | None = None
    expires_at: datetime | None = None
    failure_reason: str | None = None


@dataclass
class IssuerEntry:
    """Compact issuer reference embedded in a FederationToken payload."""

    did: str
    kid: str
    alg: str


@dataclass
class FederationToken:
    """Validated federation token with composite commitment and issuer list.

    Produced by :class:`FederationValidator.compose`. The ``raw`` field
    contains the serialised, HMAC-signed envelope ready to present as a
    credential header or request body field.
    """

    raw: str                         # base64url-encoded signed envelope
    fed_commitment_hex: str          # SHA-256(comm_0 || comm_1 || … || nonce)
    fed_nonce_hex: str               # per-composition random nonce
    issuers: list[IssuerEntry]
    expires_at: datetime             # min(expires_at) across all input credentials
    issued_at: datetime


@dataclass
class FederationResult:
    """Outcome of a federation composition attempt."""

    valid: bool
    token: FederationToken | None = None
    failure_reason: str | None = None
    credential_results: list[CredentialVerifyResult] = field(default_factory=list)
