"""Run the Verifiable Audit Log as an HTTP service (console script / uvicorn target).

Ships the env-driven wiring from ``examples/run_service.py``, made production-safe:
the Falcon-1024 signing key is **bootstrapped once and persisted** to a 0600 key
file. This matters more here than anywhere else — the audit log is an append-only,
tamper-evident hash chain, and every entry is signed. If the signing key changed on
each restart (an ephemeral key), entries written before the restart would no longer
verify against the running key, breaking the chain's whole purpose. So we load-or-create.

Run it::

    algovoi-audit-log-serve                # console script (pip install '...[serve]')
    # or
    uvicorn algovoi_audit_log.serve:app

Configuration (environment):
    AUDITLOG_DB            SQLite path                        (default ./audit_log.db)
    AUDITLOG_KEY_FILE      Falcon signing key json           (default <db dir>/audit-log-key.json,
                           bootstrapped 0600 on first run)
    AUDITLOG_FALCON_PK_B64 / AUDITLOG_FALCON_SK_B64
                           explicit Falcon-1024 keypair (overrides the key file)
    AUDITLOG_API_TOKEN     bearer token for /append          (unset = open; set in production)
    AUDITLOG_ISSUER_DID    issuer DID stamped into entries   (default did:web:issuer.example.com)
    AUDITLOG_HOST/PORT     bind for the console script         (default 127.0.0.1:8087; a non-loopback
                           host requires AUDITLOG_API_TOKEN)
"""
from __future__ import annotations

import base64
import json
import os

from algovoi_audit_log import AuditLog, SqliteStore, bearer_token_auth, create_app, signing


def _db_path() -> str:
    return os.environ.get("AUDITLOG_DB", "./audit_log.db")


def _key_file() -> str:
    if os.environ.get("AUDITLOG_KEY_FILE"):
        return os.environ["AUDITLOG_KEY_FILE"]
    return os.path.join(os.path.dirname(_db_path()) or ".", "audit-log-key.json")


def _load_or_bootstrap_keys() -> tuple[bytes, bytes]:
    """Return (pk, sk). Explicit env keys win; otherwise load the persisted key
    file, or bootstrap one (0600) on first run."""
    pk_b64, sk_b64 = os.environ.get("AUDITLOG_FALCON_PK_B64"), os.environ.get("AUDITLOG_FALCON_SK_B64")
    if pk_b64 and sk_b64:
        return base64.b64decode(pk_b64), base64.b64decode(sk_b64)
    path = _key_file()
    if os.path.exists(path):
        d = json.load(open(path, encoding="utf-8"))
        return base64.b64decode(d["pk"]), base64.b64decode(d["sk"])
    pk, sk = signing.generate_keypair()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"pk": base64.b64encode(pk).decode(), "sk": base64.b64encode(sk).decode()}, fh)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return pk, sk


def build_app():
    pk, sk = _load_or_bootstrap_keys()
    log = AuditLog(secret_key=sk, public_key=pk, store=SqliteStore(_db_path()),
                   issuer_did=os.environ.get("AUDITLOG_ISSUER_DID", "did:web:issuer.example.com"))
    return create_app(log, public_key=pk,
                      auth_dependency=bearer_token_auth(os.environ.get("AUDITLOG_API_TOKEN")),
                      title="AlgoVoi Verifiable Audit Log")


app = build_app()


def main() -> None:
    """Console entry point — serve the audit log (``algovoi-audit-log-serve``)."""
    import uvicorn
    # SECURITY (2026-08-20): default to loopback, and refuse a non-loopback (public) bind unless
    # AUDITLOG_API_TOKEN is set — the token is "unset = open", so a 0.0.0.0 default would otherwise
    # leave /append writable by anyone on the network.
    host = os.environ.get("AUDITLOG_HOST", "127.0.0.1")
    token = os.environ.get("AUDITLOG_API_TOKEN") or None
    if host not in ("127.0.0.1", "localhost", "::1") and not token:
        raise RuntimeError(
            "refusing to bind the audit log to a non-loopback address without AUDITLOG_API_TOKEN "
            "(/append would be open to anyone). Set AUDITLOG_API_TOKEN for a public bind, or keep "
            "the default loopback host.")
    uvicorn.run(app, host=host, port=int(os.environ.get("AUDITLOG_PORT", "8087")))


if __name__ == "__main__":
    main()
