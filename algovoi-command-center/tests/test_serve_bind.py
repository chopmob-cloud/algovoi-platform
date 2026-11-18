"""Security (2026-08-20): the console-script serve entrypoint must default to loopback and refuse a
non-loopback (public) bind unless COMMAND_CENTER_SERVICE_TOKEN is explicitly set — a 0.0.0.0 default
would otherwise expose the admin / audit / provisioning API on the network."""
import uvicorn
import pytest

from algovoi_command_center import licensing as _lic
_lic.require_license = lambda *a, **k: {"test": True}

from algovoi_command_center.app import main


def test_public_bind_without_token_refused(monkeypatch):
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("should not bind"))
    monkeypatch.setenv("COMMAND_CENTER_HOST", "0.0.0.0")
    monkeypatch.delenv("COMMAND_CENTER_SERVICE_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="non-loopback"):
        main()


def test_public_bind_with_token_allowed(monkeypatch):
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: captured.update(k))
    monkeypatch.setenv("COMMAND_CENTER_HOST", "0.0.0.0")
    monkeypatch.setenv("COMMAND_CENTER_SERVICE_TOKEN", "svc-token-explicit")
    main()
    assert captured["host"] == "0.0.0.0"


def test_default_is_loopback(monkeypatch):
    captured = {}
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: captured.update(k))
    monkeypatch.delenv("COMMAND_CENTER_HOST", raising=False)
    monkeypatch.delenv("COMMAND_CENTER_SERVICE_TOKEN", raising=False)
    main()
    assert captured["host"] == "127.0.0.1"
