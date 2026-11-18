"""
SQLite-backed watchlist + delta-receipt log for the continuous-monitor appliance.

The only identifying data a monitor holds is the counterparty `(network, address)`. That is
**PQC-encrypted at rest** per row (ML-KEM-1024 + AES-256-GCM, the suite `HybridPqcEncryptor`); the
`subject_ref` hash, the verdicts, the timestamps, and the signed receipts are non-PII and stored in
clear. So an exfiltrated DB file leaks no counterparty identities without the ML-KEM secret key.

Put the DB file on a persistent Docker volume (e.g. ``/app/data/monitor.db``) so the watchlist + receipt
history survive container recreates.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from algovoi_sanctions_monitor.encryption import HybridPqcEncryptor


class WatchlistStore:
    """Persistent watchlist with PQC-encrypted subjects. Inject a ``HybridPqcEncryptor`` (pk encrypts new
    rows, sk decrypts at sweep time)."""

    def __init__(self, db_path: str, encryptor: HybridPqcEncryptor) -> None:
        self._enc = encryptor
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the appliance's async sweep loop and the API handlers run in the same
        # event loop but can be dispatched on different threads (e.g. uvicorn/TestClient); writes are
        # serialised by the single event loop. All access goes through this one connection.
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS watchlist (
                subject_ref       TEXT PRIMARY KEY,
                enc_subject       BLOB NOT NULL,        -- PQC(ML-KEM-1024+AES-256-GCM) of {n,a}
                last_result       TEXT,
                first_watched_ms  INTEGER NOT NULL,
                last_screened_ms  INTEGER,
                note              TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS delta_receipts (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_ref       TEXT NOT NULL,
                transition        TEXT NOT NULL,
                receipt_envelope  TEXT NOT NULL,
                receipt_hash      TEXT NOT NULL,
                created_ms        INTEGER NOT NULL,
                chain_seq         INTEGER,
                chain_hash        TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_delta_subject ON delta_receipts(subject_ref);
            -- SECURITY (2026-08-19): tamper-evident head for the delta chain. A plain append-only table is
            -- TRUNCATION-BLIND (delete the last/any row and it silently vanishes). Each delta is hash-linked
            -- (chain_hash = sha256(prev_chain_hash | receipt_hash | seq)) and this head pins the count + last
            -- hash, so verify_delta_chain detects a dropped tail or an interior hole.
            CREATE TABLE IF NOT EXISTS delta_head (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                seq_count       INTEGER NOT NULL,
                last_chain_hash TEXT
            );
            """
        )
        # Migrate a pre-existing delta_receipts table that lacks the chain columns.
        cols = {r[1] for r in self._db.execute("PRAGMA table_info(delta_receipts)").fetchall()}
        if "chain_seq" not in cols:
            self._db.execute("ALTER TABLE delta_receipts ADD COLUMN chain_seq INTEGER")
        if "chain_hash" not in cols:
            self._db.execute("ALTER TABLE delta_receipts ADD COLUMN chain_hash TEXT")
        if self._db.execute("SELECT count(*) FROM delta_head").fetchone()[0] == 0:
            self._db.execute("INSERT INTO delta_head (id, seq_count, last_chain_hash) VALUES (1, 0, NULL)")
        self._db.commit()

    # ---- watchlist ---------------------------------------------------------------
    def add(self, *, subject_ref: str, network: str, address: str, first_watched_ms: int, note: str = "") -> None:
        enc = self._enc.encrypt(json.dumps({"n": network, "a": address}).encode())
        self._db.execute(
            "INSERT OR IGNORE INTO watchlist (subject_ref, enc_subject, first_watched_ms, note) VALUES (?,?,?,?)",
            (subject_ref, enc, first_watched_ms, note),
        )
        self._db.commit()

    def remove(self, subject_ref: str) -> bool:
        cur = self._db.execute("DELETE FROM watchlist WHERE subject_ref=?", (subject_ref,))
        self._db.commit()
        return cur.rowcount > 0

    def subjects(self) -> list[tuple[str, str, str, str | None, int]]:
        """Decrypt every row -> (subject_ref, network, address, last_result, first_watched_ms). Used by
        the sweep; the plaintext (network, address) exists only transiently in process memory."""
        out = []
        for ref, enc, last, fw in self._db.execute(
            "SELECT subject_ref, enc_subject, last_result, first_watched_ms FROM watchlist"
        ).fetchall():
            d = json.loads(self._enc.decrypt(enc))
            out.append((ref, d["n"], d["a"], last, fw))
        return out

    def set_result(self, subject_ref: str, result: str, screened_ms: int) -> None:
        self._db.execute(
            "UPDATE watchlist SET last_result=?, last_screened_ms=? WHERE subject_ref=?",
            (result, screened_ms, subject_ref),
        )
        self._db.commit()

    def status(self) -> list[dict]:
        """No-PII snapshot (no decryption)."""
        return [
            {"subject_ref": r[0], "last_result": r[1], "last_screened_ms": r[2], "first_watched_ms": r[3]}
            for r in self._db.execute(
                "SELECT subject_ref, last_result, last_screened_ms, first_watched_ms FROM watchlist"
            ).fetchall()
        ]

    def count(self) -> int:
        return int(self._db.execute("SELECT count(*) FROM watchlist").fetchone()[0])

    # ---- delta-receipt log -------------------------------------------------------
    @staticmethod
    def _chain_link(prev_hash: str | None, receipt_hash: str, seq: int) -> str:
        return hashlib.sha256(f"{prev_hash or ''}|{receipt_hash}|{seq}".encode()).hexdigest()

    def delta_head(self) -> dict:
        """The tamper-evident head of the delta chain: {seq_count, last_chain_hash}. Pin this out-of-band
        (or hold the last chain_hash a caller saw) to detect trailing truncation."""
        row = self._db.execute("SELECT seq_count, last_chain_hash FROM delta_head WHERE id=1").fetchone()
        return {"seq_count": int(row[0]), "last_chain_hash": row[1]} if row else {"seq_count": 0, "last_chain_hash": None}

    def log_delta(self, *, subject_ref: str, transition: str, envelope: str, receipt_hash: str, created_ms: int) -> None:
        head = self.delta_head()
        seq = head["seq_count"]
        chain_hash = self._chain_link(head["last_chain_hash"], receipt_hash, seq)
        self._db.execute(
            "INSERT INTO delta_receipts (subject_ref, transition, receipt_envelope, receipt_hash, created_ms, chain_seq, chain_hash) "
            "VALUES (?,?,?,?,?,?,?)",
            (subject_ref, transition, envelope, receipt_hash, created_ms, seq, chain_hash),
        )
        self._db.execute(
            "UPDATE delta_head SET seq_count=?, last_chain_hash=? WHERE id=1",
            (seq + 1, chain_hash),
        )
        self._db.commit()

    def recent_deltas(self, limit: int = 100) -> list[dict]:
        return [
            {"subject_ref": r[0], "transition": r[1], "receipt_envelope": r[2], "receipt_hash": r[3], "created_ms": r[4]}
            for r in self._db.execute(
                "SELECT subject_ref, transition, receipt_envelope, receipt_hash, created_ms "
                "FROM delta_receipts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]

    def verify_delta_chain(self, *, expected_head: dict | None = None) -> dict:
        """Verify the delta-receipt hash chain is intact and not truncated.

        SECURITY (2026-08-19): recomputes every ``chain_hash`` in ``chain_seq`` order, requires the sequence
        to be contiguous from 0 (an interior deletion leaves a gap), and checks the recomputed head against
        the persisted ``delta_head`` — so a dropped trailing receipt (a hidden sanctions hit) is detected.
        Pass ``expected_head`` ({seq_count, last_chain_hash} recorded out-of-band) to also catch an attacker
        who rewrote the head row to match a truncated table. Returns {valid, reason, count, head_hash}.
        """
        rows = self._db.execute(
            "SELECT chain_seq, receipt_hash, chain_hash FROM delta_receipts ORDER BY chain_seq ASC"
        ).fetchall()
        prev: str | None = None
        for i, (seq, receipt_hash, chain_hash) in enumerate(rows):
            if seq != i:
                return {"valid": False, "reason": f"seq_gap_or_reorder@{i}", "count": len(rows), "head_hash": prev}
            expect = self._chain_link(prev, receipt_hash, i)
            if chain_hash != expect:
                return {"valid": False, "reason": f"chain_hash_mismatch@{i}", "count": len(rows), "head_hash": prev}
            prev = chain_hash
        head = self.delta_head()
        if head["seq_count"] != len(rows) or head["last_chain_hash"] != prev:
            return {"valid": False, "reason": "head_mismatch", "count": len(rows), "head_hash": prev}
        if expected_head is not None:
            if int(expected_head.get("seq_count", -1)) != len(rows) or expected_head.get("last_chain_hash") != prev:
                return {"valid": False, "reason": "behind_pinned_head", "count": len(rows), "head_hash": prev}
        return {"valid": True, "reason": None, "count": len(rows), "head_hash": prev}

    def close(self) -> None:
        self._db.close()
