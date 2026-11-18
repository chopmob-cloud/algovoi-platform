"""Durable persistence for the admission chain — one DSN, SQLite by default, Postgres by config.

Without a store the :class:`AdmissionLedger` keeps the chain in memory. A deployed gate passes an
:class:`AdmissionStore` so the chain survives a restart: ``seq`` stays continuous and the hash links
stay intact. ``SUBSTRATE_GUARD_DB`` selects the backend:

  unset / ``sqlite:///path.db``        SQLite, a single file, stdlib only (the default)
  ``postgresql://user:pass@host/db``   PostgreSQL, needs the optional ``psycopg`` driver

Only the opaque signed envelopes plus a few no-PII columns are stored; signing + hash-linking are
unchanged — this just swaps where the envelopes land.
"""
from __future__ import annotations

import os

_DDL = (
    "CREATE TABLE IF NOT EXISTS guard_decisions ("
    "seq INTEGER PRIMARY KEY, envelope TEXT NOT NULL, decision TEXT NOT NULL, "
    "profile_ref TEXT NOT NULL, evaluated_at TEXT NOT NULL)"
)


def _default_dsn() -> str:
    dsn = os.environ.get("SUBSTRATE_GUARD_DB")
    if dsn:
        return dsn
    base = os.environ.get("SUBSTRATE_GUARD_DATA_DIR", ".")
    return "sqlite:///" + os.path.join(base, "substrate-guard-pro.db")


class AdmissionStore:
    """Backend-agnostic persistence for the admission chain, keyed off a DSN. SQLite or PostgreSQL."""

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
            raise RuntimeError(f"unsupported SUBSTRATE_GUARD_DB: {self.dsn!r} "
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
                               "pip install 'algovoi-substrate-guard-pro[postgres]'  (psycopg)") from exc
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
            cur.execute(_DDL)
            c.commit()
        finally:
            c.close()

    def count(self) -> int:
        return int(self._exec("SELECT COUNT(*) FROM guard_decisions", fetch="one")[0])

    def last_envelope(self) -> str | None:
        r = self._exec("SELECT envelope FROM guard_decisions ORDER BY seq DESC LIMIT 1", fetch="one")
        return r[0] if r else None

    def load(self) -> list[str]:
        return [r[0] for r in self._exec(
            "SELECT envelope FROM guard_decisions ORDER BY seq ASC", fetch="all")]

    def append(self, *, seq: int, envelope: str, decision: str,
               profile_ref: str, evaluated_at: str) -> None:
        self._exec(
            f"INSERT INTO guard_decisions (seq, envelope, decision, profile_ref, evaluated_at) "
            f"VALUES ({self._ph}, {self._ph}, {self._ph}, {self._ph}, {self._ph})",
            (seq, envelope, decision, profile_ref, evaluated_at), commit=True)


__all__ = ["AdmissionStore"]
