"""SCIM 2.0 provisioning tests for the AlgoVoi Compliance Command Center add-on.

These exercise the add-on exactly as the console drives it: discovered via its entry point, licence-gated,
mounted at ``/scim/v2`` on a real ``create_app()``, authenticated by the SCIM bearer token, and writing
every lifecycle change to the console's signed audit chain. They also assert the fail-closed behaviour:
with no licence the endpoint is not mounted at all.
"""
from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

# The console's own licence gate is bypassed so create_app() runs under test (no signing key to mint a
# real licence). The add-on's gate is handled per-test, since one test must see it FAIL.
import algovoi_command_center.licensing as _cclic  # noqa: E402
_cclic.require_license = lambda *a, **k: {"test": True}

from pqcrypto.sign.falcon_1024 import generate_keypair  # noqa: E402
from algovoi_command_center.audit import ConsoleAuditLog, LocalSigner  # noqa: E402

pytest.importorskip("algovoi_command_center_scim")
import algovoi_command_center_scim as scim_pkg  # noqa: E402
from algovoi_command_center_scim import licensing as _scimlic  # noqa: E402

SCIM_TOKEN = "scim-test-token-abc123"
_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"


def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("COMMAND_CENTER_USERS_FILE", str(tmp_path / "users.json"))
    monkeypatch.setenv("COMMAND_CENTER_AUDIT_FILE", str(tmp_path / "audit.json"))
    monkeypatch.setenv("COMMAND_CENTER_KEY_FILE", str(tmp_path / "key.json"))
    monkeypatch.setenv("COMMAND_CENTER_INGEST_DIR", str(tmp_path / "ing"))
    monkeypatch.setenv("COMMAND_CENTER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMMAND_CENTER_SECRET", "s" * 64)
    monkeypatch.setenv("COMMAND_CENTER_ADMIN_USER", "admin")
    monkeypatch.setenv("COMMAND_CENTER_ADMIN_PASS", "s3cret-pw")
    monkeypatch.setenv("COMMAND_CENTER_SCIM_TOKEN", SCIM_TOKEN)
    monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)


def _build_app(monkeypatch, tmp_path, *, licensed=True):
    _env(monkeypatch, tmp_path)
    if licensed:
        monkeypatch.setattr(_scimlic, "require_license", lambda: {"ok": True})
    from algovoi_command_center.app import create_app
    pk, sk = generate_keypair()
    return create_app(signer=LocalSigner(pk, sk))


def _client(monkeypatch, tmp_path, **kw):
    return TestClient(_build_app(monkeypatch, tmp_path, **kw))


def _hdr(extra=None):
    h = {"Authorization": f"Bearer {SCIM_TOKEN}", "Content-Type": "application/scim+json"}
    if extra:
        h.update(extra)
    return h


def _audit_actions(tmp_path):
    """Every action recorded on the console's signed chain (file mode)."""
    path = str(tmp_path / "audit.json")
    pk, sk = generate_keypair()  # entries() only decodes; the signer is not used to read
    return [e["action"] for e in ConsoleAuditLog(path, LocalSigner(pk, sk)).entries()]


# ── licence gate ──────────────────────────────────────────────────────────────

def test_provisioner_requires_license(monkeypatch):
    monkeypatch.delenv("ALGOVOI_LICENSE_KEY", raising=False)
    monkeypatch.delenv("ALGOVOI_LICENSE_FILE", raising=False)
    with pytest.raises(_scimlic.LicenseError):
        scim_pkg.ScimProvisioner()


def test_endpoint_unreachable_without_license(monkeypatch, tmp_path):
    # add-on installed (entry point present) but NOT licensed: the console must not mount /scim at all.
    c = _client(monkeypatch, tmp_path, licensed=False)
    assert c.get("/scim/v2/Users", headers=_hdr()).status_code == 404
    assert c.get("/scim/v2/Groups", headers=_hdr()).status_code == 404
    # the console itself is unaffected
    assert c.get("/health").status_code == 200


# ── bearer auth ─────────────────────────────────────────────────────────────

def test_bearer_required(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    assert c.get("/scim/v2/Users").status_code == 401                     # no header
    assert c.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/scim/v2/Users", headers=_hdr()).status_code == 200      # correct token


# ── Users: create / list / filter / get ─────────────────────────────────────

def test_create_list_filter_get_and_audit(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    body = {"schemas": [_USER_SCHEMA], "userName": "alice@example.com",
            "displayName": "Alice", "externalId": "ext-1",
            "emails": [{"value": "alice@example.com", "primary": True}], "active": True}
    r = c.post("/scim/v2/Users", headers=_hdr(), json=body)
    assert r.status_code == 201, r.text
    created = r.json()
    sid = created["id"]
    assert created["userName"] == "alice@example.com"
    assert created["active"] is True
    assert created["groups"][0]["value"] == "viewer"      # baseline role on provision

    # list contains the bootstrap admin + alice
    lst = c.get("/scim/v2/Users", headers=_hdr()).json()
    assert lst["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    names = {res["userName"] for res in lst["Resources"]}
    assert {"admin", "alice@example.com"} <= names

    # eq-filter on userName, emails.value, active
    f1 = c.get('/scim/v2/Users?filter=userName eq "alice@example.com"', headers=_hdr()).json()
    assert f1["totalResults"] == 1 and f1["Resources"][0]["id"] == sid
    f2 = c.get('/scim/v2/Users?filter=emails.value eq "alice@example.com"', headers=_hdr()).json()
    assert f2["totalResults"] == 1
    f3 = c.get('/scim/v2/Users?filter=active eq true', headers=_hdr()).json()
    assert f3["totalResults"] >= 2

    # get by id
    got = c.get(f"/scim/v2/Users/{sid}", headers=_hdr())
    assert got.status_code == 200 and got.json()["userName"] == "alice@example.com"
    assert c.get("/scim/v2/Users/deadbeef", headers=_hdr()).status_code == 404

    # duplicate userName -> 409
    assert c.post("/scim/v2/Users", headers=_hdr(), json=body).status_code == 409

    assert "scim_user_create" in _audit_actions(tmp_path)


# ── Users: update / patch / deactivate ──────────────────────────────────────

def test_patch_put_and_deactivate_audit(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    sid = c.post("/scim/v2/Users", headers=_hdr(),
                 json={"userName": "bob", "displayName": "Bob"}).json()["id"]

    # PATCH replace displayName + emails
    r = c.patch(f"/scim/v2/Users/{sid}", headers=_hdr(), json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "displayName", "value": "Bobby"},
                       {"op": "replace", "path": "emails", "value": [{"value": "bob@x.io"}]}]})
    assert r.status_code == 200 and r.json()["displayName"] == "Bobby"
    assert r.json()["emails"][0]["value"] == "bob@x.io"

    # PUT replace
    r = c.put(f"/scim/v2/Users/{sid}", headers=_hdr(),
              json={"userName": "bob", "displayName": "Robert", "active": True})
    assert r.status_code == 200 and r.json()["displayName"] == "Robert"

    # PATCH deactivate (Okta pathless form)
    r = c.patch(f"/scim/v2/Users/{sid}", headers=_hdr(),
                json={"Operations": [{"op": "replace", "value": {"active": False}}]})
    assert r.status_code == 200 and r.json()["active"] is False

    # reactivate
    r = c.patch(f"/scim/v2/Users/{sid}", headers=_hdr(),
                json={"Operations": [{"op": "replace", "path": "active", "value": True}]})
    assert r.json()["active"] is True

    actions = _audit_actions(tmp_path)
    assert "scim_user_update" in actions
    assert "scim_user_deactivate" in actions
    assert "scim_user_reactivate" in actions


def test_delete_is_soft_deactivate_and_blocks_login(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    sid = c.post("/scim/v2/Users", headers=_hdr(), json={"userName": "carol"}).json()["id"]

    # give carol a local password so we can prove sign-in is blocked after deprovision
    from algovoi_command_center import auth as _auth
    users = _auth.load_users()
    pwd_hex, salt = _auth.hash_password("carol-pw")
    users["carol"].update({"pwd": pwd_hex, "salt": salt})
    _auth.save_users(users)
    from algovoi_command_center import providers
    assert providers.authenticate("carol", "carol-pw") is not None    # active: can sign in

    # DELETE -> 204, soft: record remains, active=false
    assert c.delete(f"/scim/v2/Users/{sid}", headers=_hdr()).status_code == 204
    got = c.get(f"/scim/v2/Users/{sid}", headers=_hdr())
    assert got.status_code == 200 and got.json()["active"] is False      # not hard-deleted
    assert "carol" in _auth.load_users()

    # deprovisioned account can no longer sign in
    assert providers.authenticate("carol", "carol-pw") is None
    assert "scim_user_deactivate" in _audit_actions(tmp_path)


# ── Groups map 1:1 onto fixed RBAC roles ────────────────────────────────────

def test_groups_list_membership_and_audit(monkeypatch, tmp_path):
    from algovoi_command_center import roles
    c = _client(monkeypatch, tmp_path)
    dave = c.post("/scim/v2/Users", headers=_hdr(), json={"userName": "dave"}).json()
    sid = dave["id"]

    groups = c.get("/scim/v2/Groups", headers=_hdr()).json()
    assert {g["id"] for g in groups["Resources"]} == set(roles.ROLES)     # exactly the 4 roles

    # POST is idempotent for a known role, rejected for a new one
    assert c.post("/scim/v2/Groups", headers=_hdr(),
                  json={"displayName": "Administrator"}).status_code == 200
    assert c.post("/scim/v2/Groups", headers=_hdr(),
                  json={"displayName": "Wizards"}).status_code == 400

    # PATCH add dave to compliance_officer -> role changes
    r = c.patch("/scim/v2/Groups/compliance_officer", headers=_hdr(),
                json={"Operations": [{"op": "add", "path": "members",
                                      "value": [{"value": sid}]}]})
    assert r.status_code == 200
    assert c.get(f"/scim/v2/Users/{sid}", headers=_hdr()).json()["groups"][0]["value"] == "compliance_officer"
    grp = c.get("/scim/v2/Groups/compliance_officer", headers=_hdr()).json()
    assert sid in {m["value"] for m in grp["members"]}

    # PATCH remove dave -> drops to viewer baseline
    c.patch("/scim/v2/Groups/compliance_officer", headers=_hdr(),
            json={"Operations": [{"op": "remove", "path": 'members[value eq "%s"]' % sid}]})
    assert c.get(f"/scim/v2/Users/{sid}", headers=_hdr()).json()["groups"][0]["value"] == "viewer"

    # DELETE a role group is rejected (roles are fixed)
    assert c.delete("/scim/v2/Groups/admin", headers=_hdr()).status_code == 400
    assert c.get("/scim/v2/Groups/nope", headers=_hdr()).status_code == 404

    actions = _audit_actions(tmp_path)
    assert "scim_group_add_member" in actions
    assert "scim_group_remove_member" in actions


def test_last_admin_guard(monkeypatch, tmp_path):
    # bootstrap admin is the only admin; deactivating or demoting it must be refused.
    c = _client(monkeypatch, tmp_path)
    admin_sid = None
    for res in c.get("/scim/v2/Users", headers=_hdr()).json()["Resources"]:
        if res["userName"] == "admin":
            admin_sid = res["id"]
    assert admin_sid
    # DELETE (deactivate) last admin -> 409
    assert c.delete(f"/scim/v2/Users/{admin_sid}", headers=_hdr()).status_code == 409
    # demote last admin via group remove -> 409
    r = c.patch("/scim/v2/Groups/admin", headers=_hdr(),
                json={"Operations": [{"op": "remove", "path": 'members[value eq "%s"]' % admin_sid}]})
    assert r.status_code == 409


def test_discovery_endpoints(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path)
    spc = c.get("/scim/v2/ServiceProviderConfig", headers=_hdr())
    assert spc.status_code == 200 and spc.json()["patch"]["supported"] is True
    rt = c.get("/scim/v2/ResourceTypes", headers=_hdr()).json()
    assert {r["id"] for r in rt["Resources"]} == {"User", "Group"}
