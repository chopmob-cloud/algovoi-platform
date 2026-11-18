"""Pluggable persistence for the console: one DSN, SQLite by default, Postgres by config.

``COMMAND_CENTER_DB`` selects the backend, and that is the only thing that changes
between an air-gapped appliance and an enterprise deployment:

  unset / ``sqlite:///path.db``     SQLite, a single file, stdlib only (the default)
  ``postgresql://user:pass@host/db``  PostgreSQL, needs the optional ``psycopg`` driver

Only two things persist here: the signed console audit chain (append-only) and the
local user accounts. The audit chain's Falcon signing and hash-linking are unchanged;
this just swaps where the opaque envelopes and the user rows land. Switching
SQLite to Postgres is pure config, there is no second code path for the chain logic.

Connections are opened per operation, which keeps it simple and thread-safe under the
web framework's threadpool. A connection pool is a later optimisation for high
write concurrency (a shared multi-tenant deployment); the appliance is single-writer.
"""
from __future__ import annotations

import json
import os

_AUDIT_DDL = "CREATE TABLE IF NOT EXISTS console_audit (seq INTEGER PRIMARY KEY, envelope TEXT NOT NULL)"
# ``mfa`` holds per-user second-factor state (enrolled factors + secrets) as a JSON blob. It is added
# by migration to pre-existing tables in _init, so an upgraded deployment keeps its accounts.
_USERS_DDL = ("CREATE TABLE IF NOT EXISTS cc_users "
              "(username TEXT PRIMARY KEY, pwd TEXT, salt TEXT, role TEXT, mfa TEXT)")
_VERIFIED_DDL = "CREATE TABLE IF NOT EXISTS verified_content (content_sha TEXT PRIMARY KEY)"
_SERVICES_DDL = ("CREATE TABLE IF NOT EXISTS cc_services (name TEXT PRIMARY KEY, type TEXT NOT NULL, "
                 "base_url TEXT NOT NULL, health_path TEXT NOT NULL, registered_at BIGINT NOT NULL)")


def _default_dsn() -> str:
    dsn = os.environ.get("COMMAND_CENTER_DB")
    if dsn:
        return dsn
    base = os.environ.get("COMMAND_CENTER_DATA_DIR", ".")
    return "sqlite:///" + os.path.join(base, "command-center.db")


class Store:
    """Backend-agnostic persistence keyed off a DSN. SQLite or PostgreSQL."""

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
            raise RuntimeError(f"unsupported COMMAND_CENTER_DB: {self.dsn!r} "
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
                               "pip install 'algovoi-command-center[postgres]'  (psycopg)") from exc
        return psycopg.connect(self.dsn, autocommit=True)

    def _exec(self, sql: str, params: tuple = (), *, fetch: str | None = None, commit: bool = False):
        c = self._conn()
        try:
            cur = c.cursor()
            cur.execute(sql, params)
            if fetch == "all":
                rows = cur.fetchall()
            elif fetch == "one":
                rows = cur.fetchone()
            else:
                rows = None
            if commit:
                c.commit()
            return rows
        finally:
            c.close()

    def _init(self) -> None:
        c = self._conn()
        try:
            cur = c.cursor()
            cur.execute(_AUDIT_DDL)
            cur.execute(_USERS_DDL)
            cur.execute(_VERIFIED_DDL)
            cur.execute(_SERVICES_DDL)
            # migrate an existing cc_users table (created before 0.4.7) to carry the mfa column
            if self.kind == "sqlite":
                try:
                    cur.execute("ALTER TABLE cc_users ADD COLUMN mfa TEXT")
                except Exception:  # noqa: BLE001 — column already present
                    pass
            else:
                cur.execute("ALTER TABLE cc_users ADD COLUMN IF NOT EXISTS mfa TEXT")
            c.commit()
        finally:
            c.close()

    # ---- signed console audit chain -------------------------------------------------
    def audit_load(self) -> list[str]:
        """All envelopes in chain order. Used by verify() and entries() (O(n), as before)."""
        return [r[0] for r in self._exec(
            "SELECT envelope FROM console_audit ORDER BY seq ASC", fetch="all")]

    def audit_count(self) -> int:
        return int(self._exec("SELECT COUNT(*) FROM console_audit", fetch="one")[0])

    def audit_last(self) -> str | None:
        """The highest-seq envelope, or None. Lets append compute prev without loading
        the whole chain, so append is O(1) rather than O(n)."""
        r = self._exec("SELECT envelope FROM console_audit ORDER BY seq DESC LIMIT 1", fetch="one")
        return r[0] if r else None

    def audit_append(self, seq: int, envelope: str) -> None:
        self._exec(f"INSERT INTO console_audit (seq, envelope) VALUES ({self._ph}, {self._ph})",  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound
                   (seq, envelope), commit=True)

    # ---- local user accounts --------------------------------------------------------
    def users_load(self) -> dict:
        rows = self._exec("SELECT username, pwd, salt, role, mfa FROM cc_users", fetch="all")
        out: dict = {}
        for (u, p, s, r, m) in rows:
            rec = {"pwd": p, "salt": s, "role": r}
            if m:
                try:
                    rec["mfa"] = json.loads(m)
                except Exception:  # noqa: BLE001 — tolerate a corrupt blob rather than fail login
                    pass
            out[u] = rec
        return out

    def users_save(self, users: dict) -> None:
        c = self._conn()
        try:
            cur = c.cursor()
            for u, d in users.items():
                mfa = json.dumps(d["mfa"]) if d.get("mfa") else None
                vals = (u, d.get("pwd"), d.get("salt"), d.get("role"), mfa)
                if self.kind == "sqlite":
                    cur.execute("INSERT OR REPLACE INTO cc_users (username, pwd, salt, role, mfa) "
                                "VALUES (?, ?, ?, ?, ?)", vals)
                else:
                    cur.execute("INSERT INTO cc_users (username, pwd, salt, role, mfa) "
                                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (username) DO UPDATE SET "
                                "pwd=EXCLUDED.pwd, salt=EXCLUDED.salt, role=EXCLUDED.role, "
                                "mfa=EXCLUDED.mfa", vals)
            c.commit()
        finally:
            c.close()


    # ---- registered services (live-health bridge) -----------------------------------
    def services_load(self) -> dict:
        """name -> {type, base_url, health_path, registered_at}. Products self-register
        here; the console polls each one's health on demand (see app.py /api/services)."""
        rows = self._exec(
            "SELECT name, type, base_url, health_path, registered_at FROM cc_services ORDER BY name",
            fetch="all")
        return {n: {"type": t, "base_url": b, "health_path": h, "registered_at": r}
                for (n, t, b, h, r) in rows}

    def service_register(self, name: str, type_: str, base_url: str, health_path: str,
                         registered_at: int) -> None:
        vals = (name, type_, base_url, health_path, registered_at)
        if self.kind == "sqlite":
            self._exec("INSERT OR REPLACE INTO cc_services "
                       "(name, type, base_url, health_path, registered_at) VALUES (?, ?, ?, ?, ?)",
                       vals, commit=True)
        else:
            self._exec("INSERT INTO cc_services (name, type, base_url, health_path, registered_at) "
                       "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (name) DO UPDATE SET "
                       "type=EXCLUDED.type, base_url=EXCLUDED.base_url, "
                       "health_path=EXCLUDED.health_path, registered_at=EXCLUDED.registered_at", vals,
                       commit=True)

    def service_remove(self, name: str) -> None:
        self._exec(f"DELETE FROM cc_services WHERE name = {self._ph}", (name,), commit=True)  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound

    # ---- verified-content cache (skip re-verifying an unchanged chain) --------------
    def verified_seen(self, content_sha: str) -> bool:
        return self._exec(f"SELECT 1 FROM verified_content WHERE content_sha = {self._ph}",  # nosec B608 - parameterized query; only the portable placeholder (self._ph) is interpolated, values are bound
                          (content_sha,), fetch="one") is not None

    def verified_add(self, content_sha: str) -> None:
        if self.kind == "sqlite":
            self._exec("INSERT OR IGNORE INTO verified_content (content_sha) VALUES (?)",
                       (content_sha,), commit=True)
        else:
            self._exec("INSERT INTO verified_content (content_sha) VALUES (%s) ON CONFLICT DO NOTHING",
                       (content_sha,), commit=True)


_STORE: Store | None = None


def get_store() -> Store:
    """Process-wide store singleton, built from COMMAND_CENTER_DB on first use."""
    global _STORE
    if _STORE is None:
        _STORE = Store()
    return _STORE
