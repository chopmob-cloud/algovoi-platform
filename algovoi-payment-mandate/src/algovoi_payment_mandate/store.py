"""
Pluggable persistence for mandates and their charge ledger, with two bundled reference stores.

A store records issued mandates and their revocation state, **and** the ledger of authorized
charges (used to enforce the per-period cap). Keyed by ``(kid, mandate_id)``; charges add a
``charge_id`` for idempotency. Implement :class:`MandateStore` to back it with your own database;
``InMemoryStore`` and ``SqliteStore`` run out of the box.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable


@runtime_checkable
class MandateStore(Protocol):
    async def insert(self, record: dict) -> None: ...
    async def get(self, *, kid: str, mandate_id: str) -> dict | None: ...
    async def revoke(self, *, mandate_id: str, reason: str | None) -> bool: ...
    async def list_revoked(self, *, kid: str) -> list[str]: ...
    async def record_charge(self, charge: dict) -> None: ...
    async def get_charge(self, *, kid: str, mandate_id: str, charge_id: str) -> dict | None: ...
    async def period_total(self, *, kid: str, mandate_id: str, period_key: str) -> int: ...
    async def get_last_chain_record(self, *, kid: str, mandate_id: str) -> dict | None: ...
    async def list_chain_records(self, *, kid: str, mandate_id: str) -> list[dict]: ...


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryStore:
    """Process-local store. Not durable — for tests, demos, and single-process embedding."""

    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}
        self._charges: dict[tuple[str, str, str], dict] = {}

    async def insert(self, record: dict) -> None:
        self._rows[str(record["id"])] = dict(record)

    async def get(self, *, kid: str, mandate_id: str) -> dict | None:
        r = self._rows.get(str(mandate_id))
        return dict(r) if r and r.get("kid") == kid else None

    async def revoke(self, *, mandate_id: str, reason: str | None) -> bool:
        r = self._rows.get(str(mandate_id))
        if r and r.get("revoked_at") is None:
            r["revoked_at"] = _now_iso()
            r["revoke_reason"] = reason
            return True
        return False

    async def list_revoked(self, *, kid: str) -> list[str]:
        return [k for k, v in self._rows.items() if v.get("kid") == kid and v.get("revoked_at") is not None]

    async def record_charge(self, charge: dict) -> None:
        key = (charge["kid"], str(charge["mandate_id"]), charge["charge_id"])
        self._charges.setdefault(key, dict(charge))

    async def get_charge(self, *, kid: str, mandate_id: str, charge_id: str) -> dict | None:
        c = self._charges.get((kid, str(mandate_id), charge_id))
        return dict(c) if c else None

    async def period_total(self, *, kid: str, mandate_id: str, period_key: str) -> int:
        return sum(
            int(c["amount"]) for c in self._charges.values()
            if c["kid"] == kid and str(c["mandate_id"]) == str(mandate_id)
            and c["period_key"] == period_key and c.get("authorized")
        )

    async def get_last_chain_record(self, *, kid: str, mandate_id: str) -> dict | None:
        candidates = [
            c for c in self._charges.values()
            if c["kid"] == kid and str(c["mandate_id"]) == str(mandate_id)
            and c.get("authorized") and c.get("chain_seq") is not None
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda c: int(c["chain_seq"]))

    async def list_chain_records(self, *, kid: str, mandate_id: str) -> list[dict]:
        records = [
            c for c in self._charges.values()
            if c["kid"] == kid and str(c["mandate_id"]) == str(mandate_id)
            and c.get("authorized") and c.get("chain_seq") is not None
        ]
        return sorted(records, key=lambda c: int(c["chain_seq"]))


class SqliteStore:
    """Durable single-file store using stdlib ``sqlite3`` (run off the event loop). No extra dependency."""

    def __init__(self, path: str = "mandates.db") -> None:
        self._path = path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS mandates (
                    id TEXT PRIMARY KEY, kid TEXT NOT NULL, payer TEXT NOT NULL, payee TEXT NOT NULL,
                    asset TEXT, chain TEXT, max_amount INTEGER NOT NULL, period TEXT NOT NULL,
                    max_per_charge INTEGER, scope TEXT NOT NULL, issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL, mandate TEXT NOT NULL, revoked_at TEXT, revoke_reason TEXT
                )"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS ix_mandates_kid ON mandates(kid)")
            c.execute(
                """CREATE TABLE IF NOT EXISTS charges (
                    kid TEXT NOT NULL, mandate_id TEXT NOT NULL, charge_id TEXT NOT NULL,
                    amount INTEGER NOT NULL, asset TEXT, period_key TEXT NOT NULL,
                    authorized INTEGER NOT NULL, ts TEXT NOT NULL,
                    chain_seq INTEGER, chain_ref TEXT, receipt_hash TEXT,
                    PRIMARY KEY (kid, mandate_id, charge_id)
                )"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS ix_charges_period ON charges(kid, mandate_id, period_key)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_charges_chain ON charges(kid, mandate_id, chain_seq)")
            # Migrate existing databases that predate the chain columns.
            for col in ("chain_seq", "chain_ref", "receipt_hash"):
                try:
                    c.execute(f"ALTER TABLE charges ADD COLUMN {col} {'INTEGER' if col == 'chain_seq' else 'TEXT'}")
                except sqlite3.OperationalError:
                    pass  # column already exists

    def _insert(self, r: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO mandates "
                "(id,kid,payer,payee,asset,chain,max_amount,period,max_per_charge,scope,issued_at,"
                "expires_at,mandate,revoked_at,revoke_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(r["id"]), r["kid"], r["payer"], r["payee"], r.get("asset"), r.get("chain"),
                 int(r["max_amount"]), r["period"], r.get("max_per_charge"), json.dumps(r.get("scope", [])),
                 r["issued_at"], r["expires_at"], r["mandate"], r.get("revoked_at"), r.get("revoke_reason")),
            )

    def _get(self, kid: str, mid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM mandates WHERE kid=? AND id=?", (kid, str(mid))).fetchone()
            if not row:
                return None
            d = dict(row)
            d["scope"] = json.loads(d.get("scope") or "[]")
            return d

    def _revoke(self, mid: str, reason: str | None) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE mandates SET revoked_at=?, revoke_reason=? WHERE id=? AND revoked_at IS NULL",
                (_now_iso(), reason, str(mid)),
            )
            return cur.rowcount > 0

    def _list_revoked(self, kid: str) -> list[str]:
        with self._conn() as c:
            return [r["id"] for r in c.execute(
                "SELECT id FROM mandates WHERE kid=? AND revoked_at IS NOT NULL", (kid,)).fetchall()]

    def _record_charge(self, ch: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO charges "
                "(kid,mandate_id,charge_id,amount,asset,period_key,authorized,ts,chain_seq,chain_ref,receipt_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ch["kid"], str(ch["mandate_id"]), ch["charge_id"], int(ch["amount"]), ch.get("asset"),
                 ch["period_key"], 1 if ch.get("authorized") else 0, ch["ts"],
                 ch.get("chain_seq"), ch.get("chain_ref"), ch.get("receipt_hash")),
            )

    def _get_last_chain_record(self, kid: str, mid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT chain_seq, chain_ref, receipt_hash FROM charges "
                "WHERE kid=? AND mandate_id=? AND authorized=1 AND chain_seq IS NOT NULL "
                "ORDER BY chain_seq DESC LIMIT 1",
                (kid, str(mid)),
            ).fetchone()
            return dict(row) if row else None

    def _list_chain_records(self, kid: str, mid: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT kid, mandate_id, charge_id, amount, asset, period_key, ts, "
                "chain_seq, chain_ref, receipt_hash FROM charges "
                "WHERE kid=? AND mandate_id=? AND authorized=1 AND chain_seq IS NOT NULL "
                "ORDER BY chain_seq ASC",
                (kid, str(mid)),
            ).fetchall()
            return [dict(r) for r in rows]

    def _get_charge(self, kid: str, mid: str, cid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM charges WHERE kid=? AND mandate_id=? AND charge_id=?",
                (kid, str(mid), cid)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["authorized"] = bool(d["authorized"])
            return d

    def _period_total(self, kid: str, mid: str, pkey: str) -> int:
        with self._conn() as c:
            row = c.execute(
                "SELECT COALESCE(SUM(amount),0) AS t FROM charges "
                "WHERE kid=? AND mandate_id=? AND period_key=? AND authorized=1",
                (kid, str(mid), pkey)).fetchone()
            return int(row["t"])

    async def insert(self, record: dict) -> None:
        await asyncio.to_thread(self._insert, record)

    async def get(self, *, kid: str, mandate_id: str) -> dict | None:
        return await asyncio.to_thread(self._get, kid, mandate_id)

    async def revoke(self, *, mandate_id: str, reason: str | None) -> bool:
        return await asyncio.to_thread(self._revoke, mandate_id, reason)

    async def list_revoked(self, *, kid: str) -> list[str]:
        return await asyncio.to_thread(self._list_revoked, kid)

    async def record_charge(self, charge: dict) -> None:
        await asyncio.to_thread(self._record_charge, charge)

    async def get_charge(self, *, kid: str, mandate_id: str, charge_id: str) -> dict | None:
        return await asyncio.to_thread(self._get_charge, kid, mandate_id, charge_id)

    async def period_total(self, *, kid: str, mandate_id: str, period_key: str) -> int:
        return await asyncio.to_thread(self._period_total, kid, mandate_id, period_key)

    async def get_last_chain_record(self, *, kid: str, mandate_id: str) -> dict | None:
        return await asyncio.to_thread(self._get_last_chain_record, kid, mandate_id)

    async def list_chain_records(self, *, kid: str, mandate_id: str) -> list[dict]:
        return await asyncio.to_thread(self._list_chain_records, kid, mandate_id)
