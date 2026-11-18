"""Security (2026-08-20): the console-script serve entrypoint must default to loopback and refuse a
non-loopback (public) bind unless AUDITLOG_API_TOKEN is set — the token is "unset = open", so a
0.0.0.0 default would otherwise leave /append writable by anyone on the network."""
import uvicorn
import pytest

from algovoi_audit_log import licensing as _lic
_lic.require_license = lambda *a, **k: {"package": _lic.PACKAGE_NAME, "tier": "test"}

from algovoi_audit_log import serve


def test_public_bind_without_token_refused(monkeypatch):
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("should not bind"))
    monkeypatch.setenv("AUDITLOG_HOST", "0.0.0.0")
    monkeypatch.delenv("AUDITLOG_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="non-loopback"):
        serve.main()


def test_public_bind_with_token_allowed(monkeypatch):
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: captured.update(k))
    monkeypatch.setenv("AUDITLOG_HOST", "0.0.0.0")
    monkeypatch.setenv("AUDITLOG_API_TOKEN", "audit-token-explicit")
    serve.main()
    assert captured["host"] == "0.0.0.0"


def test_default_is_loopback(monkeypatch):
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: captured.update(k))
    monkeypatch.delenv("AUDITLOG_HOST", raising=False)
    monkeypatch.delenv("AUDITLOG_API_TOKEN", raising=False)
    serve.main()
    assert captured["host"] == "127.0.0.1"
