"""Two-factor flow tests. These require the TOTP add-on (algovoi-command-center-totp) to be installed,
which is exactly what proves the discovery / adoption path: the console offers TOTP only because the
add-on's entry point is present."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from algovoi_command_center import licensing as _lic

totp = pytest.importorskip("algovoi_command_center_totp")


@pytest.fixture(autouse=True)
def _license_totp_addon(monkeypatch):
    """The TOTP add-on is licence-gated; bypass that gate so the factor is discoverable under test."""
    import algovoi_command_center_totp.licensing as _l
    monkeypatch.setattr(_l, "require_license", lambda: {"ok": True})


@pytest.fixture()
def app(monkeypatch, tmp_path):
    monkeypatch.setattr(_lic, "require_license", lambda: {"ok": True})
    monkeypatch.setenv("COMMAND_CENTER_KEY_FILE", str(tmp_path / "key.json"))
    monkeypatch.setenv("COMMAND_CENTER_USERS_FILE", str(tmp_path / "users.json"))
    monkeypatch.setenv("COMMAND_CENTER_AUDIT_FILE", str(tmp_path / "audit.json"))
    monkeypatch.setenv("COMMAND_CENTER_INGEST_DIR", str(tmp_path / "ing"))
    monkeypatch.setenv("COMMAND_CENTER_SECRET", "s" * 64)
    monkeypatch.setenv("COMMAND_CENTER_ADMIN_USER", "admin")
    monkeypatch.setenv("COMMAND_CENTER_ADMIN_PASS", "s3cret-pw")
    from algovoi_command_center.app import create_app
    return create_app()


def test_store_mfa_roundtrip_and_migration(tmp_path, monkeypatch):
    """2FA state must survive in the SQLite/Postgres store, not only in file mode. Also covers the
    migration that adds the mfa column to a pre-0.4.7 cc_users table without dropping accounts."""
    import sqlite3
    monkeypatch.delenv("COMMAND_CENTER_USERS_FILE", raising=False)
    dbfile = tmp_path / "cc.db"
    con = sqlite3.connect(dbfile)   # a pre-0.4.7 table: no mfa column
    con.execute("CREATE TABLE cc_users (username TEXT PRIMARY KEY, pwd TEXT, salt TEXT, role TEXT)")
    con.execute("INSERT INTO cc_users VALUES ('legacy','h','s','viewer')")
    con.commit(); con.close()
    monkeypatch.setenv("COMMAND_CENTER_DB", "sqlite:///" + str(dbfile))
    from algovoi_command_center.store import Store
    s = Store()                     # _init migrates: ADD COLUMN mfa, legacy account preserved
    users = s.users_load()
    assert users["legacy"]["role"] == "viewer"
    users["legacy"]["mfa"] = {"totp": {"secret": "ABC234XYZ", "active": True}}
    s.users_save(users)
    reloaded = Store().users_load()
    assert reloaded["legacy"]["mfa"]["totp"]["active"] is True
    assert reloaded["legacy"]["mfa"]["totp"]["secret"] == "ABC234XYZ"


def test_factor_is_discovered():
    from algovoi_command_center import factors
    assert "totp" in factors.discover()
    assert factors.available()
    assert any(c["name"] == "totp" for c in factors.catalog())


def _enroll_secret(client) -> str:
    page = client.get("/mfa/enroll/totp").text
    m = re.search(r'#f7f6f2">([A-Z2-7]{24,})<', page)   # the base32 setup key box (not the QR svg)
    assert m, "setup key not found on enroll page"
    return m.group(1)


def test_opt_in_then_required_end_to_end(app):
    pw = "s3cret-pw"
    # 1) fresh account: no 2FA, login lands straight on the dashboard
    c = TestClient(app, follow_redirects=False)
    r = c.post("/login", data={"username": "admin", "password": pw})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "cc_session" in r.headers.get("set-cookie", "")

    # 2) enroll TOTP from the Security page, confirming a live code
    c2 = TestClient(app)
    c2.post("/login", data={"username": "admin", "password": pw})
    secret = _enroll_secret(c2)
    r = c2.post("/mfa/enroll/totp", data={"code": totp.totp_at(secret)})
    assert "second factor active" in r.text

    # 3) now login is held behind the 2FA challenge (opt-in has become required)
    c3 = TestClient(app, follow_redirects=False)
    r = c3.post("/login", data={"username": "admin", "password": pw})
    assert r.status_code == 303 and r.headers["location"] == "/mfa/challenge"
    assert "cc_pending" in r.headers.get("set-cookie", "")
    # the pending token is not a session: the dashboard still bounces to login
    assert c3.get("/").headers["location"] == "/login"

    # 4) a wrong code is rejected, the right code exchanges the pending token for a session
    assert c3.post("/mfa/challenge", data={"code": "000000"}).status_code == 401
    r = c3.post("/mfa/challenge", data={"code": totp.totp_at(secret)})
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "cc_session" in r.headers.get("set-cookie", "")


def test_disable_requires_stepup(app):
    pw = "s3cret-pw"
    c = TestClient(app, follow_redirects=False)
    c.post("/login", data={"username": "admin", "password": pw})
    # enroll first (follow redirects for the page fetches)
    cc = TestClient(app)
    cc.post("/login", data={"username": "admin", "password": pw})
    secret = _enroll_secret(cc)
    cc.post("/mfa/enroll/totp", data={"code": totp.totp_at(secret)})
    # disabling without a step-up bounces to /verify
    r = cc.post("/mfa/disable/totp", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/verify")
    # after a step-up, disable succeeds
    cc.post("/verify", data={"next": "/mfa", "password": pw})
    r = cc.post("/mfa/disable/totp", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/mfa"
    from algovoi_command_center import factors
    assert not factors.has_active("admin")
