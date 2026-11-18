"""Data models for the watchlist + the signed monitoring delta evidence."""
from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel


@dataclass
class WatchRecord:
    """Internal watchlist state for one monitored subject.

    ``network`` + ``address`` are retained *inside the monitor* so it can re-screen; they NEVER appear in
    a receipt -- evidence carries only ``subject_ref = sha256(network:address)``.
    """
    subject_ref: str
    network: str
    address: str
    first_watched_ms: int
    last_result: str | None = None
    last_screened_ms: int | None = None
    note: str = ""


class WatchStatus(BaseModel):
    """Public, no-PII snapshot of one watched subject."""
    subject_ref: str
    last_result: str | None = None
    last_screened_ms: int | None = None
    first_watched_ms: int


class VerifyResult(BaseModel):
    verified: bool
    reason: str
    subject_ref: str | None = None
    transition: str | None = None
    receipt: dict | None = None
    receipt_hash: str | None = None
