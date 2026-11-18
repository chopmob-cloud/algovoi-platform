"""
Pluggable append-only persistence for the audit log, with two bundled reference stores.

A store holds the signed entries in sequence and reports the chain head. Implement
:class:`AuditStore` to back it with your own database; ``InMemoryStore`` and ``SqliteStore`` run out
of the box. Entries are append-only — there is no update or delete in the interface.
"""
from __future__ import annotations

import asyncio
import sqlite3
from typing import Protocol, runtime_checkable


@runtime_checkable
class AuditStore(Protocol):
    async def insert(self, record: dict) -> None: ...
    async def get(self, seq: int) -> dict | None: ...
    async def head(self) -> dict: ...   # {seq_count, last_entry_hash, last_event_id}


class InMemoryStore:
    """Process-local store. Not durable — for tests, demos, and single-process embedding."""

    def __init__(self) -> None:
        self._rows: dict[int, dict] = {}

    async def insert(self, record: dict) -> None:
        self._rows[int(record["seq"])] = dict(record)

    async def get(self, seq: int) -> dict | None:
        r = self._rows.get(int(seq))
        return dict(r) if r else None

    async def head(self) -> dict:
        n = len(self._rows)
        if n == 0:
            return {"seq_count": 0, "last_entry_hash": None, "last_event_id": None}
        last = self._rows[n - 1]
        return {"seq_count": n, "last_entry_hash": last["entry_hash"], "last_event_id": last["event_id"]}


class SqliteStore:
    """Durable single-file store using stdlib ``sqlite3`` (run off the event loop). No extra dependency."""

    def __init__(self, path: str = "audit_log.db") -> None:
        self._path = path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS audit_entries (
                    seq INTEGER PRIMARY KEY, event_id TEXT NOT NULL, event_type TEXT NOT NULL,
                    envelope TEXT NOT NULL, entry_hash TEXT NOT NULL, recorded_at TEXT NOT NULL
                )"""
            )

    def _insert(self, r: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO audit_entries (seq,event_id,event_type,envelope,entry_hash,recorded_at) "
                "VALUES (?,?,?,?,?,?)",
                (int(r["seq"]), r["event_id"], r["event_type"], r["envelope"], r["entry_hash"], r["recorded_at"]),
            )

    def _get(self, seq: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM audit_entries WHERE seq=?", (int(seq),)).fetchone()
            return dict(row) if row else None

    def _head(self) -> dict:
        with self._conn() as c:
            n = c.execute("SELECT COUNT(*) AS n FROM audit_entries").fetchone()["n"]
            if n == 0:
                return {"seq_count": 0, "last_entry_hash": None, "last_event_id": None}
            last = c.execute("SELECT entry_hash, event_id FROM audit_entries ORDER BY seq DESC LIMIT 1").fetchone()
            return {"seq_count": n, "last_entry_hash": last["entry_hash"], "last_event_id": last["event_id"]}

    async def insert(self, record: dict) -> None:
        await asyncio.to_thread(self._insert, record)

    async def get(self, seq: int) -> dict | None:
        return await asyncio.to_thread(self._get, seq)

    async def head(self) -> dict:
        return await asyncio.to_thread(self._head)
