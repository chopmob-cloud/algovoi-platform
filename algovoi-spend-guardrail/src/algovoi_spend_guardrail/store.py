"""
Durable persistence for the decision chain — one DSN, SQLite by default, Postgres by config.

Without a store the :class:`DecisionLedger` keeps the chain in memory (fine for embedding / a single
request burst). A deployed enforcement gate passes a :class:`DecisionStore` so the chain survives a
restart: ``seq`` stays continuous, the hash links stay intact, and the rolling-window velocity cap is
computed over the *persisted* ALLOWs rather than only this process's memory.

``SPEND_GUARDRAIL_DB`` selects the backend (the only thing that changes between an appliance and an
enterprise deployment):

  unset / ``sqlite:///path.db``        SQLite, a single file, stdlib only (the default)
  ``postgresql://user:pass@host/db``   PostgreSQL, needs the optional ``psycopg`` driver

This stores only the opaque signed envelopes plus the few no-PII fields the velocity query needs; the
Falcon/ML-DSA signing and hash-linking are unchanged — this just swaps where the envelopes land.
"""
from __future__ import annotations

import os

_DECISIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS guardrail_decisions ("
    "seq INTEGER PRIMARY KEY, envelope TEXT NOT NULL, decision TEXT NOT NULL, "
    "agent_did TEXT, amount BIGINT, evaluated_at TEXT NOT NULL)"
)
_VELOCITY_IDX = ("CREATE INDEX IF NOT EXISTS ix_gd_velocity "
                 "ON guardrail_decisions (agent_did, evaluated_at)")


def _default_dsn() -> str:
    dsn = os.environ.get("SPEND_GUARDRAIL_DB")
    if dsn:
        return dsn
    base = os.environ.get("SPEND_GUARDRAIL_DATA_DIR", ".")
    return "sqlite:///" + os.path.join(base, "spend-guardrail.db")


class DecisionStore:
    """Backend-agnostic persistence for the decision chain, keyed off a DSN. SQLite or PostgreSQL."""

    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn or _default_dsn()
        if self.dsn.startswith("sqlite"):
            self.kind = "sqlite"
            self._ph = "?"
            self._path = self.dsn[len("sqlite:///"):] if self.dsn.startswith("sqlite:///") \
                else self.dsn.split("://", 1)[-1]
            d = os.path.dirname(self._path)
            if d:
                os.makedirs(d, exist_ok=True)
        elif self.dsn.startswith("postgres"):
            self.kind = "postgres"
            self._ph = "%s"
        else:
            raise RuntimeError(f"unsupported SPEND_GUARDRAIL_DB: {self.dsn!r} "
                               f"(use sqlite:///... or postgresql://...)")
        self._init()

    def _conn(self):
        if self.kind == "sqlite":
            import sqlite3
            return sqlite3.connect(self._path)
        try:
            import psycopg
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("the postgresql backend needs the optional driver: "
                               "pip install 'algovoi-spend-guardrail[postgres]'  (psycopg)") from exc
        return psycopg.connect(self.dsn, autocommit=True)

    def _exec(self, sql: str, params: tuple = (), *, fetch: str | None = None, commit: bool = False):
        c = self._conn()
        try:
            cur = c.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall() if fetch == "all" else (cur.fetchone() if fetch == "one" else None)
            if commit:
                c.commit()
            return rows
        finally:
            c.close()

    def _init(self) -> None:
        c = self._conn()
        try:
            cur = c.cursor()
            cur.execute(_DECISIONS_DDL)
            cur.execute(_VELOCITY_IDX)
            c.commit()
        finally:
            c.close()

    def count(self) -> int:
        return int(self._exec("SELECT COUNT(*) FROM guardrail_decisions", fetch="one")[0])

    def last_envelope(self) -> str | None:
        """Highest-seq envelope, or None — lets append compute the next ``prev`` link O(1)."""
        r = self._exec("SELECT envelope FROM guardrail_decisions ORDER BY seq DESC LIMIT 1", fetch="one")
        return r[0] if r else None

    def load(self) -> list[str]:
        """Every envelope in chain order (O(n)) — used by export + chain verification."""
        return [r[0] for r in self._exec(
            "SELECT envelope FROM guardrail_decisions ORDER BY seq ASC", fetch="all")]

    def append(self, *, seq: int, envelope: str, decision: str,
               agent_did: str | None, amount: int | None, evaluated_at: str) -> None:
        self._exec(
            f"INSERT INTO guardrail_decisions (seq, envelope, decision, agent_did, amount, evaluated_at) "  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound
            f"VALUES ({self._ph}, {self._ph}, {self._ph}, {self._ph}, {self._ph}, {self._ph})",
            (seq, envelope, decision, agent_did, amount, evaluated_at), commit=True)

    def velocity_total(self, *, agent_did: str | None, since_iso: str) -> int:
        """Sum of ALLOW amounts for ``agent_did`` at/after ``since_iso`` (the rolling window).

        Only ALLOWs count toward velocity, and an ALLOW always carries a real ``agent_did``, so a null
        agent simply matches nothing.
        """
        if agent_did is None:
            return 0
        r = self._exec(
            f"SELECT COALESCE(SUM(amount), 0) FROM guardrail_decisions "  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound
            f"WHERE decision = {self._ph} AND agent_did = {self._ph} AND evaluated_at >= {self._ph}",
            ("ALLOW", agent_did, since_iso), fetch="one")
        return int(r[0] or 0)


__all__ = ["DecisionStore"]
