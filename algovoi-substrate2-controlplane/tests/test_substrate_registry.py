"""TDD coverage for the substrate-neutral control-plane registry."""
from __future__ import annotations

import os
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

# Configure the package before importing the app: the service initialises its
# persistent store at import time.
_DATA_DIR = pathlib.Path(__file__).parent / ".tmp-control-plane"
_DATA_DIR.mkdir(exist_ok=True)
os.environ["S2CP_DATA_DIR"] = str(_DATA_DIR)
os.environ.pop("S2CP_DB", None)
os.environ["S2CP_ADMIN_TOKEN"] = "test-admin-token-substrate-registry"
os.environ["S2CP_AUDIT_KEY"] = "test-audit-key-substrate-registry"
sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))

from app.main import _ADMIN_TOKEN, app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"Authorization": f"Bearer {_ADMIN_TOKEN}"}


def test_all_substrate_families_register_and_persist(client, admin_headers):
    registrations = [
        {
            "name": "open-substrate",
            "family": "open-substrate",
            "version": "1",
            "adapter": "canonical-evidence",
            "base_url": "http://127.0.0.1:1",
            "capabilities": ["refs", "offline-verify"],
        },
        {
            "name": "substrate-2",
            "family": "substrate-2",
            "version": "2",
            "adapter": "substrate2-controlplane",
            "base_url": "http://127.0.0.1:2",
            "capabilities": ["federation", "zkp", "keystone"],
        },
        {
            "name": "payment-rails",
            "family": "payment-rails",
            "version": "1",
            "adapter": "payment-rails",
            "base_url": "http://127.0.0.1:3",
            "capabilities": ["x402", "mpp", "ap2", "a2a"],
        },
    ]

    for payload in registrations:
        response = client.post("/v1/substrates", json=payload, headers=admin_headers)
        assert response.status_code == 200, response.text

    response = client.get("/v1/substrates", headers=admin_headers)
    assert response.status_code == 200
    substrates = response.json()["substrates"]
    names = {item["name"] for item in substrates}
    assert {"open-substrate", "substrate-2", "payment-rails"} <= names
    payment = next(item for item in substrates if item["name"] == "payment-rails")
    assert payment["capabilities"] == ["x402", "mpp", "ap2", "a2a"]

    # The registry is durable: a fresh Store load sees the same entries.
    from algovoi_substrate2_controlplane.store import Store

    fresh = Store(dsn=f"sqlite:///{_DATA_DIR / 'control-plane.db'}")
    assert {"open-substrate", "substrate-2", "payment-rails"} <= set(fresh.substrates_load())


def test_substrate_registry_is_admin_only(client, admin_headers):
    payload = {
        "name": "unauthorised",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:4",
    }
    assert client.get("/v1/substrates").status_code == 401
    assert client.post("/v1/substrates", json=payload).status_code == 401
    assert client.delete("/v1/substrates/unauthorised").status_code == 401

    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    assert client.delete("/v1/substrates/unauthorised", headers=admin_headers).status_code == 200


def test_audit_failure_is_degraded_and_blocks_mutation(client, admin_headers, monkeypatch):
    import base64
    import algovoi_substrate2_controlplane.service as service

    monkeypatch.setattr(service, "_verify_audit_chain", lambda entries: False)
    assert client.get("/health").json()["status"] == "degraded"
    payload = {"did": "did:web:blocked.example", "public_key_b64": base64.b64encode(b"x" * 1793).decode()}
    response = client.post("/v1/issuers", json=payload, headers=admin_headers)
    assert response.status_code == 503
    assert "did:web:blocked.example" not in client.get("/v1/issuers").text
    monkeypatch.undo()
    service._refresh_persisted_state()


def test_legacy_service_registration_uses_same_url_hardening(client, admin_headers):
    base = {"name": "legacy", "type": "addon", "base_url": "http://127.0.0.1:99999", "health_path": "/health"}
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["base_url"] = "http://127.0.0.1:20"
    base["health_path"] = "/health/%2e%2e/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["health_path"] = "/health/%252e%252e/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["health_path"] = "/health/..%2fadmin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    from urllib.parse import quote
    encoded = ".."
    for _ in range(33):
        encoded = quote(encoded, safe="")
    base["health_path"] = f"/health/{encoded}/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422
    base["base_url"] = "http://127.0.0.1:20/%2e%2e/admin"
    assert client.post("/v1/services", json=base, headers=admin_headers).status_code == 422


def test_substrate_registration_rejects_unsafe_or_ambiguous_values(client, admin_headers):
    base = {
        "name": "bad substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "file:///etc/passwd",
    }
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 422

    base["name"] = "credentialed-target"
    base["base_url"] = "https://user:secret@example.com"
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 422

    base["name"] = "bad-port"
    base["base_url"] = "http://127.0.0.1:99999"
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 422

    base["name"] = "whitespace-url"
    base["base_url"] = "  http://127.0.0.1:11/  "
    response = client.post("/v1/substrates", json=base, headers=admin_headers)
    assert response.status_code == 200
    stored = client.get("/v1/substrates", headers=admin_headers).json()["substrates"]
    item = next(item for item in stored if item["name"] == "whitespace-url")
    assert item["base_url"] == "http://127.0.0.1:11"


def test_https_posture_targets_fail_closed_without_dns_rebinding_window(client, admin_headers):
    payload = {
        "name": "https-target",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "https://example.com",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    posture = client.get("/v1/posture", headers=admin_headers).json()
    item = next(item for item in posture["substrates"] if item["name"] == "https-target")
    assert item["up"] is False
    assert "HTTPS" in item["detail"]


def test_substrate_only_failure_is_degraded_in_panel(client, admin_headers):
    payload = {
        "name": "panel-down-substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:12",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    panel = client.get("/", headers=admin_headers)
    assert panel.status_code == 200
    assert "Service degraded" in panel.text
    assert "Healthy targets" in panel.text
    assert "0/" in panel.text


def test_package_version_is_consistent():
    from algovoi_substrate2_controlplane import __version__

    assert __version__ == "0.3.5"


def test_pinned_probe_preserves_base_url_path_prefix():
    from algovoi_substrate2_controlplane.service import _resolve_posture_target

    target = _resolve_posture_target("http://127.0.0.1:13/prefix", "/health")
    assert target is not None
    assert target[0].endswith("/prefix/health")


def test_pinned_probe_preserves_explicit_port_in_host_header():
    from algovoi_substrate2_controlplane.service import _resolve_posture_target

    target = _resolve_posture_target("http://127.0.0.1:8092/prefix", "/health")
    assert target is not None
    assert target[1] == "127.0.0.1:8092"


def test_audit_chain_verification_detects_tampering():
    from algovoi_substrate2_controlplane.service import _AUDIT_KEY, _verify_audit_chain
    import hashlib
    import hmac
    import json

    body = {"seq": 0, "action": "policy_bind", "detail": {"subject_ref": "x", "policy_ref": "y"}, "prev": ""}
    mac = hmac.new(_AUDIT_KEY, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
    entry = {**body, "mac": mac}
    assert _verify_audit_chain([entry]) is True
    tampered = {**entry, "detail": {"x": 2}}
    assert _verify_audit_chain([tampered]) is False
    assert _verify_audit_chain([{"seq": 0, "action": "test", "detail": None, "prev": "", "mac": ""}]) is False


def test_http_panel_login_does_not_require_secure_cookie_by_default(client):
    response = client.post("/login", data={"password": _ADMIN_TOKEN}, follow_redirects=False)
    assert response.status_code == 303
    assert "Secure" not in response.headers["set-cookie"]


def test_posture_and_panel_expose_registered_substrates(client, admin_headers):
    payload = {
        "name": "posture-substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:9",
        "health_path": "/health",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200

    posture = client.get("/v1/posture", headers=admin_headers).json()
    assert "substrates" in posture
    item = next(item for item in posture["substrates"] if item["name"] == "posture-substrate")
    assert item["up"] is False

    panel = client.get("/", headers=admin_headers)
    assert panel.status_code == 200
    assert "Substrates" in panel.text
    assert "posture-substrate" in panel.text


def test_posture_blocks_link_local_metadata_targets(client, admin_headers):
    payload = {
        "name": "metadata-target",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://169.254.169.254",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    assert client.get("/v1/posture").status_code == 401
    posture = client.get("/v1/posture", headers=admin_headers).json()
    item = next(item for item in posture["substrates"] if item["name"] == "metadata-target")
    assert item["up"] is False
    assert item["detail"].startswith("blocked:")


def test_substrate_changes_are_audited(client, admin_headers):
    payload = {
        "name": "audited-substrate",
        "family": "custom",
        "version": "1",
        "adapter": "custom",
        "base_url": "http://127.0.0.1:10",
    }
    assert client.post("/v1/substrates", json=payload, headers=admin_headers).status_code == 200
    assert client.delete("/v1/substrates/audited-substrate", headers=admin_headers).status_code == 200
    audit = client.get("/v1/audit", headers=admin_headers).json()["entries"]
    actions = [entry["action"] for entry in audit]
    assert "substrate_register" in actions
    assert "substrate_remove" in actions
