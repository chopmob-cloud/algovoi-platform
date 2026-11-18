"""Request/response models for the Verifiable Archive app."""
from __future__ import annotations

from pydantic import BaseModel, field_validator

MAX_METADATA_KEYS = 64
MAX_STR = 1024


class NotarizeRequest(BaseModel):
    data_b64: str | None = None       # base64 of the document bytes — stored encrypted
    doc_hash: str | None = None       # "sha256:…"; supply alone to notarize by hash (no blob stored)
    doc_size: int | None = None
    title: str = ""
    content_type: str = "application/octet-stream"
    metadata: dict = {}

    @field_validator("title", "content_type")
    @classmethod
    def _str(cls, v: str) -> str:
        if len(v) > MAX_STR:
            raise ValueError(f"value must be ≤ {MAX_STR} chars")
        return v

    @field_validator("metadata")
    @classmethod
    def _meta(cls, v: dict) -> dict:
        if len(v) > MAX_METADATA_KEYS:
            raise ValueError(f"metadata must have ≤ {MAX_METADATA_KEYS} keys")
        return v


class NotarizeResponse(BaseModel):
    entry_id: str
    seq: int
    doc_hash: str
    stored: bool
    enc_alg: str
    prev_receipt_hash: str | None = None
    receipt: str
    kid: str
    archived_at: str


class VerifyEntryRequest(BaseModel):
    receipt: str


class VerifyEntryResult(BaseModel):
    verified: bool
    status: str  # valid | invalid
    entry_id: str | None = None
    seq: int | None = None
    doc_hash: str | None = None
    title: str | None = None
    content_type: str | None = None
    enc_alg: str | None = None
    prev_receipt_hash: str | None = None
    kid: str | None = None
    archived_at: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class VerifyChainResult(BaseModel):
    valid: bool
    length: int
    head_receipt_hash: str | None = None
    broken_at: int | None = None
    reason: str | None = None
