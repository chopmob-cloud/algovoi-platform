"""Appliance API tests — auth, generate, split, recover, access toggle over the HTTP surface."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair


@pytest.fixture()
def client(tmp_path, monkeypatch):
    sup_pk, _ = generate_mlkem_keypair()
    monkeypatch.setenv("ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64", signing.b64u_encode(sup_pk))
    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "recovery.vault"))
    monkeypatch.setenv("VAULT_UNLOCK_SECRET", "unit-test-unlock-secret")
    monkeypatch.setenv("VAULT_API_TOKEN", "test-token")
    # Recovery Vault is licence-gated at boot (fail-closed). Real licences are Falcon-1024 signed by the
    # AlgoVoi issuer key, so unit tests bypass the OEM gate the same way the CCC / Records Vault suites do.
    # The gate itself is exercised by test_licence_gate_fails_closed below.
    monkeypatch.setattr("algovoi_recovery_vault.service.require_license", lambda: {"test": True})
    from algovoi_recovery_vault.service import create_app
    return TestClient(create_app())


def test_licence_gate_fails_closed(tmp_path, monkeypatch):
    """With no licence present the appliance refuses to boot: the commercial fail-closed guarantee."""
    monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "recovery.vault"))
    monkeypatch.setenv("VAULT_UNLOCK_SECRET", "unit-test-unlock-secret")
    monkeypatch.setenv("VAULT_API_TOKEN", "test-token")
    from algovoi_recovery_vault.service import create_app
    from algovoi_recovery_vault.licensing import LicenseError
    with pytest.raises(LicenseError):
        create_app()  # no licence -> the gate must refuse to build the app


AUTH = {"Authorization": "Bearer test-token"}


def test_healthz_open_and_auth_enforced(client):
    assert client.get("/healthz").json() == {"ok": True}
    assert client.get("/v1/status").status_code == 401          # no token
    assert client.get("/v1/status", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/v1/status", headers=AUTH).status_code == 200


def test_generate_split_recover_flow(client):
    r = client.post("/v1/archives", json={"name": "primary"}, headers=AUTH)
    assert r.status_code == 200 and "archive_pub_b64" in r.json()

    r = client.post("/v1/archives/primary/split",
                    json={"threshold_k": 2, "total_n": 3}, headers=AUTH)
    body = r.json()
    assert r.status_code == 200
    assert body["envelope"]["support_assisted"] is True      # access enabled by default
    shares = body["shares"]
    assert len(shares) == 2

    r = client.post("/v1/archives/primary/recover", json={"shares": shares}, headers=AUTH)
    assert r.status_code == 200 and r.json()["recovered"] is True


def test_recover_with_too_few_shares_400(client):
    client.post("/v1/archives", json={"name": "primary"}, headers=AUTH)
    body = client.post("/v1/archives/primary/split",
                       json={"threshold_k": 3, "total_n": 5}, headers=AUTH).json()
    r = client.post("/v1/archives/primary/recover",
                    json={"shares": body["shares"][:2]}, headers=AUTH)
    assert r.status_code == 400


def test_disable_access_then_split_is_self_custody(client):
    client.post("/v1/archives", json={"name": "primary"}, headers=AUTH)
    assert client.post("/v1/access", json={"enabled": False}, headers=AUTH).json() == {"algovoi_access": False}
    body = client.post("/v1/archives/primary/split",
                       json={"threshold_k": 2, "total_n": 3}, headers=AUTH).json()
    assert body["envelope"]["support_assisted"] is False
    assert len(body["shares"]) == 3
    # explicit request for an AlgoVoi share is refused while disabled
    r = client.post("/v1/archives/primary/split",
                    json={"threshold_k": 2, "total_n": 3, "include_algovoi_support": True}, headers=AUTH)
    assert r.status_code == 400

    st = client.get("/v1/status", headers=AUTH).json()
    assert st["algovoi_access"] is False


def test_auto_split_on_create_is_default(client):
    # POST /v1/archives with no split args -> default 2-of-3 recovery emitted in the same call
    body = client.post("/v1/archives", json={"name": "primary"}, headers=AUTH).json()
    assert "envelope" in body and "shares" in body
    assert body["envelope"]["threshold_k"] == 2 and body["envelope"]["total_n"] == 3
    assert body["envelope"]["support_assisted"] is True            # access on by default
    assert len(body["shares"]) == 2                                # n-1 (AlgoVoi holds 1)
    # the returned shares recover immediately
    r = client.post("/v1/archives/primary/recover", json={"shares": body["shares"]}, headers=AUTH)
    assert r.json()["recovered"] is True


def test_auto_split_can_be_turned_off(client):
    body = client.post("/v1/archives", json={"name": "p2", "auto_split": False}, headers=AUTH).json()
    assert "envelope" not in body and "shares" not in body
    assert body["archive_pub_b64"]


def test_protected_signing_key_flow(client):
    # any Substrate PQC signing key: generate + auto-split + recover via the API
    body = client.post("/v1/keys", json={"name": "sig"}, headers=AUTH).json()
    assert body["kind"] == "signing-falcon"
    assert body["envelope"]["kind"] == "generic-secret" and len(body["shares"]) == 2
    r = client.post("/v1/keys/sig/recover", json={"shares": body["shares"]}, headers=AUTH)
    assert r.json()["recovered"] is True
    st = client.get("/v1/status", headers=AUTH).json()
    assert st["keys"]["sig"]["kind"] == "signing-falcon"
    # export round-trips
    sec = client.get("/v1/keys/sig/secret", headers=AUTH).json()
    assert sec["public_b64"] and sec["secret_b64"]


def test_bind_guard_refuses_non_loopback_without_optin(monkeypatch):
    """Security fix 2026-08-19: the /v1/*/secret endpoints export plaintext keys, so a non-loopback bind
    is refused unless VAULT_ALLOW_REMOTE is explicitly set."""
    from algovoi_recovery_vault.service import _resolve_bind_host
    monkeypatch.setenv("VAULT_BIND", "0.0.0.0")
    monkeypatch.delenv("VAULT_ALLOW_REMOTE", raising=False)
    with pytest.raises(RuntimeError, match="non-loopback"):
        _resolve_bind_host()
    # loopback default is fine
    monkeypatch.delenv("VAULT_BIND", raising=False)
    assert _resolve_bind_host() == "127.0.0.1"
    # explicit opt-in allows it
    monkeypatch.setenv("VAULT_BIND", "0.0.0.0")
    monkeypatch.setenv("VAULT_ALLOW_REMOTE", "1")
    assert _resolve_bind_host() == "0.0.0.0"
