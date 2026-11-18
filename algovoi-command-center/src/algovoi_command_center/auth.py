"""Local-accounts authentication + signed sessions for the Compliance Command Center.

v1 identity: local accounts (air-gap friendly — no external IdP needed to run). Phase e adds LDAP / AD
and OIDC / SAML SSO behind the same ``authenticate`` + session surface. Passwords are PBKDF2-HMAC; the
session is an HMAC-signed token (no server-side state, no extra dependency).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from algovoi_command_center import roles

_PBKDF2_ROUNDS = 200_000


def _secret() -> bytes:
    s = os.environ.get("COMMAND_CENTER_SECRET")
    if not s:
        # ephemeral per-process secret if none configured (sessions won't survive restart)
        s = os.environ.setdefault("COMMAND_CENTER_SECRET", secrets.token_hex(32))
    return s.encode()


def hash_password(password: str, *, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return dk.hex(), salt


def verify_password(password: str, pwd_hex: str, salt: str) -> bool:
    cand, _ = hash_password(password, salt=salt)
    return hmac.compare_digest(cand, pwd_hex)


def _users_file() -> str | None:
    """Legacy file path if configured; None means use the store (the default)."""
    return os.environ.get("COMMAND_CENTER_USERS_FILE")


def load_users() -> dict:
    p = _users_file()
    if p:                                       # legacy file mode
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        users: dict = {}
    else:                                       # store mode (default)
        from algovoi_command_center.store import get_store
        users = get_store().users_load()
    if users:
        return users
    # bootstrap a default admin from env (password required; never a hardcoded default)
    user = os.environ.get("COMMAND_CENTER_ADMIN_USER", "admin")
    pwd = os.environ.get("COMMAND_CENTER_ADMIN_PASS")
    if not pwd:
        return {}
    pwd_hex, salt = hash_password(pwd)
    users = {user: {"pwd": pwd_hex, "salt": salt, "role": roles.ADMIN}}
    save_users(users)
    return users


def save_users(users: dict) -> None:
    p = _users_file()
    if p:
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(users, fh, indent=2)
    else:
        from algovoi_command_center.store import get_store
        get_store().users_save(users)


def authenticate(username: str, password: str) -> dict | None:
    """Authenticate via the configured provider chain (local accounts + LDAP/AD; OIDC/SAML plug in
    behind the same interface). Returns ``{username, role}`` on success, else None."""
    from algovoi_command_center import providers
    return providers.authenticate(username, password)


def make_session(username: str, role: str, *, ttl_secs: int = 8 * 3600) -> str:
    body = base64.urlsafe_b64encode(
        json.dumps({"t": "session", "u": username, "r": role,
                    "exp": int(time.time()) + ttl_secs}).encode()).rstrip(b"=").decode()
    mac = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def read_session(token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    body, mac = token.rsplit(".", 1)
    if not hmac.compare_digest(mac, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "==" * 2))
    except Exception:  # noqa: BLE001
        return None
    # Token types are domain-separated: only a token minted as a session is a session. Reject a
    # pending-2FA (``pf``) or step-up (``su``) token even though it shares this HMAC key, so a
    # pre-2FA pending cookie can never be replayed as an authenticated session.
    if data.get("t") != "session" or "pf" in data or "su" in data:
        return None
    if data.get("exp", 0) < int(time.time()):
        return None
    return {"username": data["u"], "role": data["r"]}


def make_stepup(username: str, *, ttl_secs: int = 300) -> str:
    """Short-lived signed token proving the user re-entered their password recently. Gates sensitive
    actions (downloads, create) with a fresh credential check; valid for ``ttl_secs`` (default 5 min)."""
    body = base64.urlsafe_b64encode(
        json.dumps({"t": "stepup", "u": username, "su": 1,
                    "exp": int(time.time()) + ttl_secs}).encode()).rstrip(b"=").decode()
    mac = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def read_stepup(token: str | None, username: str) -> bool:
    """True iff ``token`` is a valid, unexpired step-up token for ``username``."""
    if not token or "." not in token:
        return False
    body, mac = token.rsplit(".", 1)
    if not hmac.compare_digest(mac, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()):
        return False
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "==" * 2))
    except Exception:  # noqa: BLE001
        return False
    return (data.get("t") == "stepup" and data.get("su") == 1
            and data.get("u") == username and data.get("exp", 0) >= int(time.time()))


def make_pending(username: str, role: str, *, ttl_secs: int = 300) -> str:
    """A short-lived signed token issued after a correct password when the user has 2FA enrolled. It
    proves the first factor passed but grants no access on its own — only the 2FA challenge accepts it,
    and only exchanges it for a real session on a correct code. Carries the role so the eventual session
    matches, and never doubles as a session (``user_of`` reads the session cookie only)."""
    body = base64.urlsafe_b64encode(
        json.dumps({"t": "pending", "u": username, "r": role, "pf": 1,
                    "exp": int(time.time()) + ttl_secs}).encode()).rstrip(b"=").decode()
    mac = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def read_pending(token: str | None) -> dict | None:
    """Return ``{"username", "role"}`` for a valid, unexpired pending-2FA token, else None."""
    if not token or "." not in token:
        return None
    body, mac = token.rsplit(".", 1)
    if not hmac.compare_digest(mac, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "==" * 2))
    except Exception:  # noqa: BLE001
        return None
    if data.get("t") != "pending" or data.get("pf") != 1 or data.get("exp", 0) < int(time.time()):
        return None
    return {"username": data["u"], "role": data["r"]}
