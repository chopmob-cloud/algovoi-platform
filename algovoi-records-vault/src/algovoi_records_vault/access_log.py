"""F3 — read-access audit log (HIPAA §164.312(b) "record and examine access").

The base archive proves *write* integrity (what was archived, when, unaltered) but says nothing about
*reads* — who retrieved which record and whether it was allowed. For protected health information that
read trail is itself a regulatory requirement. This module closes the documented "no read-access log"
boundary: the vault wraps :meth:`Archive.retrieve` and appends a signed ``access_event`` — principal,
document hash, ``granted``/``denied``, reason — to its own ``access/`` signed-chain stream **before
returning or re-raising**. The log is the same tamper-evident, offline-verifiable shape as everything
else, so an auditor can prove the access history was not edited after the fact.
"""
from __future__ import annotations

import json

from algovoi_records_vault.principals import Principal, principal_fields
from algovoi_records_vault.vault import _VaultStream


def to_jsonl(events: list[dict]) -> str:
    """JSON-lines for SIEM / GRC ingest (Splunk / Elastic / Datadog) — one event per line."""
    return "\n".join(json.dumps(e, separators=(",", ":"), sort_keys=True) for e in events)


class AccessLog:
    """Logs every retrieve as a signed access event, then performs (or refuses) the read."""

    def __init__(self, *, stream: _VaultStream, archive) -> None:
        self._stream = stream
        self._archive = archive

    async def retrieve(self, *, doc_hash: str, principal: Principal | None = None,
                       reason: str = "") -> bytes:
        """Retrieve a document, logging a signed ``granted``/``denied`` access event either way.

        On any failure (not stored, integrity mismatch, decryption key absent) a ``denied`` event is
        sealed with the error class, then the original exception re-raises — the denial is on record.
        """
        try:
            data = await self._archive.retrieve(doc_hash=doc_hash)
        except Exception as exc:  # noqa: BLE001
            await self._append(doc_hash, principal, "denied", reason, type(exc).__name__)
            raise
        await self._append(doc_hash, principal, "granted", reason, None)
        return data

    async def log_decision(self, *, doc_hash: str, decision: str, principal: Principal | None = None,
                           reason: str = "", error: str | None = None) -> dict:
        """Record an externally-made access decision (e.g. an ACL denial) without performing a read."""
        if decision not in ("granted", "denied"):
            raise ValueError("decision must be 'granted' or 'denied'")
        return await self._append(doc_hash, principal, decision, reason, error)

    async def _append(self, doc_hash: str, principal: Principal | None, decision: str,
                      reason: str, error: str | None) -> dict:
        fields = {
            "doc_hash": doc_hash,
            "decision": decision,        # granted | denied
            "reason": reason,
            "error": error,
            **principal_fields(principal),
        }
        return await self._stream.append(fields)

    async def events(self) -> list[dict]:
        """All access-event payloads in order (the ``recorded_at`` of each is the access time)."""
        return await self._stream.list_payloads()

    async def export_jsonl(self) -> str:
        """HIPAA read-access report as JSON-lines for SIEM/GRC ingest."""
        return to_jsonl(await self.events())

    async def verify_chain(self):
        """Offline integrity of the access log — proves no access event was edited or removed."""
        return await self._stream.verify_chain()
