"""Data models for the crypto-agility registry + migration evidence."""
from __future__ import annotations

from pydantic import BaseModel


class Classification(BaseModel):
    """How an algorithm sits relative to the post-quantum transition."""
    algorithm: str
    family: str            # "signature" | "kem" | "unknown"
    kind: str              # "classical" | "post-quantum" | "hybrid" | "unknown"
    quantum_vulnerable: bool


class KeyRecord(BaseModel):
    """A key tracked in the agility registry, with its migration status."""
    kid: str
    algorithm: str
    role: str              # "signature" | "kem"
    status: str            # "active" | "deprecated" | "migrated"
    classification: Classification
    migrated_to_kid: str | None = None
    note: str = ""


class InventorySummary(BaseModel):
    total: int
    quantum_vulnerable_active: list[str]   # kids that still need migration
    post_quantum: list[str]
    by_status: dict


class VerifyResult(BaseModel):
    verified: bool
    reason: str
    kind: str | None = None         # "migration-attestation" | "hybrid-envelope" | "rewrap-attestation"
    payload: dict | None = None
    payload_hash: str | None = None
