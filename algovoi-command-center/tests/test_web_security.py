"""Web-interface security hardening tests: response headers, Secure cookies, brute-force throttle,
and open-redirect sanitisation on the step-up flow."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from algovoi_command_center import licensing as _lic


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


def test_security_headers_present(app):
    r = TestClient(app).get("/login")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp and "default-src 'self'" in csp


def test_session_cookie_secure_over_https_only(app):
    # over HTTPS the session cookie must carry Secure
    c = TestClient(app, base_url="https://testserver")
    r = c.post("/login", data={"username": "admin", "password": "s3cret-pw"}, follow_redirects=False)
    assert "secure" in r.headers.get("set-cookie", "").lower()
    # over plain HTTP (air-gapped / behind a TLS proxy that did not forward) it must NOT be Secure,
    # otherwise the cookie would be dropped and login would silently fail
    c2 = TestClient(app, base_url="http://testserver")
    r2 = c2.post("/login", data={"username": "admin", "password": "s3cret-pw"}, follow_redirects=False)
    assert "secure" not in r2.headers.get("set-cookie", "").lower()


def test_login_bruteforce_throttle(app):
    c = TestClient(app)
    # 10 bad attempts are allowed (each 401); the 11th within the window is throttled (429)
    codes = [c.post("/login", data={"username": "admin", "password": "wrong"},
                    follow_redirects=False).status_code for _ in range(11)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


def test_verify_open_redirect_sanitised(app):
    c = TestClient(app)
    c.post("/login", data={"username": "admin", "password": "s3cret-pw"})
    for evil in ("//evil.example", "/\\evil.example", "https://evil.example"):
        html = c.get("/verify", params={"next": evil}).text
        assert "evil.example" not in html  # sanitised to "/"
