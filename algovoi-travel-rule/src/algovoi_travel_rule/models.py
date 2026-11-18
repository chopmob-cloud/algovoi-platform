"""
Data models — the IVMS101 PII payload (exchanged VASP-to-VASP, never in the receipt) and the
no-PII Travel Rule receipt I/O.
"""
from __future__ import annotations

from pydantic import BaseModel


class Person(BaseModel):
    """An IVMS101 originator/beneficiary. This is the regulated PII — it travels VASP-to-VASP
    (PQC-sealed), and only its content hash ever appears in a receipt."""
    name: str
    account: str                       # wallet / account identifier (the on-chain or VASP account)
    address: str | None = None
    national_id: str | None = None
    customer_id: str | None = None
    date_of_birth: str | None = None   # YYYY-MM-DD
    country: str | None = None         # ISO 3166-1 alpha-2


class IVMS101(BaseModel):
    """interVASP Messaging Standard 101 payload — originator + beneficiary for one transfer."""
    originator: Person
    beneficiary: Person


class TransferAmount(BaseModel):
    currency: str                      # ISO 4217 (or asset symbol)
    amount_minor: int                  # minor units (e.g. cents)


class CertifyRequest(BaseModel):
    transfer_ref: str
    beneficiary_vasp_did: str
    amount: TransferAmount
    ivms101: IVMS101 | None = None
    direction: str = "originator"      # "originator" | "beneficiary"
    result: str = "PREPARED"           # PREPARED | SENT | RECEIVED | ACKNOWLEDGED


class VerifyRequest(BaseModel):
    receipt_envelope: str
    issuer_public_key_b64: str


class VerifyResult(BaseModel):
    verified: bool
    reason: str
    applies: bool | None = None
    transfer_ref: str | None = None
    receipt: dict | None = None
    receipt_hash: str | None = None
    # kid of the key that actually signed. The caller MUST confirm this is the authorised key for the
    # receipt's originating_vasp_did — verification proves signature validity, NOT the claimed identity.
    signer_kid: str | None = None
