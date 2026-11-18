"""
Pluggable persistence for issued passports, with two bundled reference implementations.

A store records issued passports and their revocation state, keyed by ``(kid, passport_id)``.
Implement the :class:`PassportStore` protocol to back it with your own database (Postgres,
DynamoDB, …); ``InMemoryStore`` and ``SqliteStore`` are ready to run out of the box.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class PassportStore(Protocol):
    async def insert(self, record: dict) -> None: ...
    async def get(self, *, kid: str, passport_id: str) -> dict | None: ...
    async def revoke(self, *, passport_id: str, reason: str | None) -> bool: ...
    async def list_revoked(self, *, kid: str) -> list[str]: ...


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryStore:
    """Process-local store. Not durable — for tests, demos, and single-process embedding."""

    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}

    async def insert(self, record: dict) -> None:
        self._rows[str(record["id"])] = dict(record)

    async def get(self, *, kid: str, passport_id: str) -> dict | None:
        r = self._rows.get(str(passport_id))
        return dict(r) if r and r.get("kid") == kid else None

    async def revoke(self, *, passport_id: str, reason: str | None) -> bool:
        r = self._rows.get(str(passport_id))
        if r and r.get("revoked_at") is None:
            r["revoked_at"] = _now_iso()
            r["revoke_reason"] = reason
            return True
        return False

    async def list_revoked(self, *, kid: str) -> list[str]:
        return [k for k, v in self._rows.items() if v.get("kid") == kid and v.get("revoked_at") is not None]


class SqliteStore:
    """Durable single-file store using stdlib ``sqlite3`` (run off the event loop). No extra dependency."""

    def __init__(self, path: str = "passports.db") -> None:
        self._path = path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS passports (
                    id TEXT PRIMARY KEY, kid TEXT NOT NULL, agent_did TEXT NOT NULL,
                    scopes TEXT NOT NULL, spend_limit_microusd INTEGER, spend_window TEXT,
                    issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, credential TEXT NOT NULL,
                    revoked_at TEXT, revoke_reason TEXT, tenant_id TEXT
                )"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS ix_passports_kid ON passports(kid)")

    def _insert(self, r: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO passports "
                "(id,kid,agent_did,scopes,spend_limit_microusd,spend_window,issued_at,expires_at,"
                "credential,revoked_at,revoke_reason,tenant_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(r["id"]), r["kid"], r["agent_did"], json.dumps(r.get("scopes", [])),
                 r.get("spend_limit_microusd"), r.get("spend_window"), r["issued_at"], r["expires_at"],
                 r["credential"], r.get("revoked_at"), r.get("revoke_reason"), r.get("tenant_id")),
            )

    def _get(self, kid: str, pid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM passports WHERE kid=? AND id=?", (kid, str(pid))).fetchone()
            if not row:
                return None
            d = dict(row)
            d["scopes"] = json.loads(d.get("scopes") or "[]")
            return d

    def _revoke(self, pid: str, reason: str | None) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE passports SET revoked_at=?, revoke_reason=? WHERE id=? AND revoked_at IS NULL",
                (_now_iso(), reason, str(pid)),
            )
            return cur.rowcount > 0

    def _list_revoked(self, kid: str) -> list[str]:
        with self._conn() as c:
            return [r["id"] for r in c.execute(
                "SELECT id FROM passports WHERE kid=? AND revoked_at IS NOT NULL", (kid,)).fetchall()]

    async def insert(self, record: dict) -> None:
        await asyncio.to_thread(self._insert, record)

    async def get(self, *, kid: str, passport_id: str) -> dict | None:
        return await asyncio.to_thread(self._get, kid, passport_id)

    async def revoke(self, *, passport_id: str, reason: str | None) -> bool:
        return await asyncio.to_thread(self._revoke, passport_id, reason)

    async def list_revoked(self, *, kid: str) -> list[str]:
        return await asyncio.to_thread(self._list_revoked, kid)
