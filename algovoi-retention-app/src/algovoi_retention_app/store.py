"""Append-only, per-issuer retention store.

DSN-backed, the same pattern as the Compliance Command Center store: SQLite by
default (``RETENTION_DSN=sqlite:///path`` or the ``RETENTION_DB`` path), with a
Postgres DSN accepted via the same env for a managed deployment.

The store is an *index*, not the source of truth: every row carries the
content-addressed ``chain_ref`` produced by the public ``algovoi_retention_chain``
primitive, so integrity is verifiable from the rows alone. A database swap or
silent corruption cannot forge a chain -- a re-verify recomputes every ref.

Rules (founder-approved design): independent per-issuer chains, strict
append-only, duplicate ``receipt_hash`` per issuer rejected, no gaps (the
sequence and prev-link are derived from the issuer head, so the caller does no
bookkeeping).
"""
from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from algovoi_retention_chain import retention_chain_ref


@dataclass
class RetentionRecord:
    issuer_id: str
    chain_seq: int
    prev_receipt_hash: str
    receipt_hash: str
    chain_ref: str
    created_at: str

    def as_dict(self) -> dict:
        return asdict(self)


class DuplicateReceipt(ValueError):
    """Raised when a receipt_hash already exists for the issuer."""


_DDL = """
CREATE TABLE IF NOT EXISTS retention (
    issuer_id          TEXT    NOT NULL,
    chain_seq          INTEGER NOT NULL,
    prev_receipt_hash  TEXT    NOT NULL,
    receipt_hash       TEXT    NOT NULL,
    chain_ref          TEXT    NOT NULL,
    created_at         TEXT    NOT NULL,
    PRIMARY KEY (issuer_id, chain_seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_retention_receipt
    ON retention (issuer_id, receipt_hash);
"""


def _dsn_to_sqlite_path(dsn: str | None) -> str:
    if not dsn:
        return os.environ.get("RETENTION_DB", "retention.db")
    if dsn.startswith("sqlite:///"):
        return dsn[len("sqlite:///"):]
    if dsn.startswith("sqlite://"):
        return dsn[len("sqlite://"):] or ":memory:"
    raise ValueError(
        f"unsupported DSN {dsn!r}: this build ships the SQLite backend; a "
        "Postgres DSN uses the same schema via the [postgres] extra"
    )


class RetentionStore:
    """SQLite-backed append-only retention index. Thread-safe for the service."""

    def __init__(self, dsn: str | None = None) -> None:
        self.path = _dsn_to_sqlite_path(dsn or os.environ.get("RETENTION_DSN"))
        if self.path not in (":memory:", ""):
            parent = os.path.dirname(self.path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_DDL)
        self._conn.commit()

    # ── reads ────────────────────────────────────────────────────────────────
    def head(self, issuer_id: str) -> RetentionRecord | None:
        cur = self._conn.execute(
            "SELECT * FROM retention WHERE issuer_id=? ORDER BY chain_seq DESC LIMIT 1",
            (issuer_id,),
        )
        row = cur.fetchone()
        return _row(row) if row else None

    def chain(self, issuer_id: str) -> list[RetentionRecord]:
        cur = self._conn.execute(
            "SELECT * FROM retention WHERE issuer_id=? ORDER BY chain_seq ASC",
            (issuer_id,),
        )
        return [_row(r) for r in cur.fetchall()]

    def all_records(self) -> list[RetentionRecord]:
        cur = self._conn.execute(
            "SELECT * FROM retention ORDER BY issuer_id ASC, chain_seq ASC"
        )
        return [_row(r) for r in cur.fetchall()]

    def issuers(self) -> list[str]:
        cur = self._conn.execute(
            "SELECT DISTINCT issuer_id FROM retention ORDER BY issuer_id ASC"
        )
        return [r["issuer_id"] for r in cur.fetchall()]

    def counts(self) -> dict[str, int]:
        cur = self._conn.execute(
            "SELECT issuer_id, COUNT(*) n FROM retention GROUP BY issuer_id"
        )
        return {r["issuer_id"]: r["n"] for r in cur.fetchall()}

    # ── append (the core write) ────────────────────────────────────────────────
    def append(self, issuer_id: str, receipt_hash: str) -> RetentionRecord:
        """Append a receipt to the issuer's chain. Computes chain_seq, prev-link
        and chain_ref from the issuer head, so the caller supplies only the
        receipt hash. Strictly append-only; duplicate receipt_hash is rejected."""
        if not issuer_id:
            raise ValueError("issuer_id must be non-empty")
        with self._lock:
            head = self.head(issuer_id)
            chain_seq = 0 if head is None else head.chain_seq + 1
            prev_receipt_hash = "" if head is None else head.receipt_hash
            ref = retention_chain_ref(
                prev_receipt_hash=prev_receipt_hash,
                receipt_hash=receipt_hash,
                chain_seq=chain_seq,
                issuer_id=issuer_id,
            )
            rec = RetentionRecord(
                issuer_id=issuer_id,
                chain_seq=chain_seq,
                prev_receipt_hash=prev_receipt_hash,
                receipt_hash=receipt_hash,
                chain_ref=ref,
                created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            try:
                self._conn.execute(
                    "INSERT INTO retention VALUES (?,?,?,?,?,?)",
                    (rec.issuer_id, rec.chain_seq, rec.prev_receipt_hash,
                     rec.receipt_hash, rec.chain_ref, rec.created_at),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                raise DuplicateReceipt(
                    f"receipt_hash already recorded for issuer {issuer_id!r}"
                ) from exc
            return rec

    def close(self) -> None:
        self._conn.close()


def _row(row: sqlite3.Row) -> RetentionRecord:
    return RetentionRecord(
        issuer_id=row["issuer_id"],
        chain_seq=row["chain_seq"],
        prev_receipt_hash=row["prev_receipt_hash"],
        receipt_hash=row["receipt_hash"],
        chain_ref=row["chain_ref"],
        created_at=row["created_at"],
    )
