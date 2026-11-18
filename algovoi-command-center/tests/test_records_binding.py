"""Unit + integration tests for the CCC Records Vault binding and Users management page.

The RecordsVault / Archive licence gate is bypassed here (monkeypatched) so the binding logic can be
exercised offline without a real OEM licence; the demo/VM2 clean-box run exercises the licensed path.
"""
from __future__ import annotations

import asyncio
import base64
import os

import pytest

from algovoi_doc_archive import archive as _arch
from algovoi_records_vault import vault as _vault
from algovoi_records_vault import licensing as _rv_lic
from algovoi_doc_archive import licensing as _da_lic


@pytest.fixture(autouse=True)
def _no_license(monkeypatch):
    monkeypatch.setattr(_rv_lic, "require_license", lambda: {"ok": True})
    monkeypatch.setattr(_da_lic, "require_license", lambda: {"ok": True})
    # vault.py imported licensing at module load into its own namespace; patch both call sites
    monkeypatch.setattr("algovoi_records_vault.vault.licensing.require_license", lambda: {"ok": True})


def _signer():
    from algovoi_doc_archive.signer import LocalSigner
    from pqcrypto.sign.falcon_1024 import generate_keypair
    pk, sk = generate_keypair()
    return LocalSigner(pk, sk)


def _vault_at(tmp_path, signer):
    from algovoi_doc_archive.archive import Archive
    from algovoi_doc_archive.backend import LocalFsBackend
    from algovoi_doc_archive.encryption import HybridPqcEncryptor
    from algovoi_records_vault import RecordsVault
    from pqcrypto.kem.ml_kem_1024 import generate_keypair as kem_kp
    epk, esk = kem_kp()
    archive = Archive(storage=LocalFsBackend(str(tmp_path / "arch")), signer=signer,
                      encryptor=HybridPqcEncryptor(epk, esk), issuer_did="did:web:test.local")
    return RecordsVault(archive=archive)


def test_record_view_flattens_metadata():
    from algovoi_command_center import records
    payload = {"seq": 3, "doc_hash": "sha256:ab", "content_type": "text/plain", "title": "T",
               "doc_size": 5, "stored": True, "archived_at": "2026-07-07T00:00:00Z",
               "metadata": {"subject_ref": "cust-1"}}
    v = records._record_view(payload)
    assert v["subject_ref"] == "cust-1"
    assert v["seq"] == 3 and v["doc_hash"] == "sha256:ab" and v["title"] == "T"


def test_notarize_list_retrieve_and_verify(tmp_path):
    from algovoi_command_center import records
    v = _vault_at(tmp_path, _signer())

    async def go():
        out = await records.notarize_record(v, title="Minutes", content_type="text/plain",
                                            data=b"hello world", subject_ref="cust-1")
        assert out["stored"] and out["timestamped"]
        recs = await records.list_records(v)
        assert len(recs) == 1 and recs[0]["subject_ref"] == "cust-1"
        got = await records.retrieve_record(v, doc_hash=out["doc_hash"])
        assert base64.b64decode(got["data_b64"]) == b"hello world"
        checks = await records.verify_all(v)
        assert checks["archive"]["valid"] and checks["access"]["valid"] and checks["tsa"]["valid"]
        p = await records.posture(v)
        assert p["records"] == 1 and p["verified"] is True
    asyncio.run(go())


def test_legal_hold_blocks_disposition(tmp_path, monkeypatch):
    from algovoi_command_center import records
    # tiny retention window so the record is instantly past-retention
    monkeypatch.setenv("COMMAND_CENTER_RETENTION_DAYS", "0")
    v = _vault_at(tmp_path, _signer())

    async def go():
        out = await records.notarize_record(v, title="Ledger", content_type="text/plain",
                                            data=b"data", subject_ref="cust-9")
        # with retention 0 and no hold -> disposable
        p1 = await records.posture(v)
        assert p1["disposable"] == 1
        # place a hold scoped to the subject -> no longer disposable
        holds = v.holds(retention_days=0, use_env_bridge=False)
        await holds.place_hold(matter_id="LIT-1", query={"subject_ref": "cust-9"},
                               reason="litigation", preservation_days=3650)
        p2 = await records.posture(v)
        assert p2["disposable"] == 0 and p2["held_matters"] == 1
        # early release is refused (preservation floor)
        from algovoi_records_vault.legal_hold import HoldActive
        with pytest.raises(HoldActive):
            await holds.release_hold(matter_id="LIT-1", reason="oops")
        assert out["doc_hash"]
    asyncio.run(go())


def test_evidence_streams_verify(tmp_path):
    from algovoi_command_center import records
    v = _vault_at(tmp_path, _signer())

    async def go():
        await records.notarize_record(v, title="x", content_type="text/plain", data=b"y")
        # empty evidence streams (consent/custody/keyring/redaction) must still verify as valid
        checks = await records.verify_all(v)
        for name in ("archive", "tsa", "access", "holds", "keyring", "consent", "custody", "redaction"):
            assert checks[name]["valid"], (name, checks[name])
    asyncio.run(go())


# ── Users management guardrails ──────────────────────────────────────────────────

@pytest.fixture()
def _users_file(tmp_path, monkeypatch):
    p = tmp_path / "users.json"
    monkeypatch.setenv("COMMAND_CENTER_USERS_FILE", str(p))
    return p


def test_users_add_role_remove_and_last_admin_guard(_users_file):
    from algovoi_command_center import users, roles, auth
    # seed one admin
    pwd_hex, salt = auth.hash_password("adminpw")
    auth.save_users({"root": {"pwd": pwd_hex, "salt": salt, "role": roles.ADMIN}})

    users.add_user("alice", "pw1", roles.COMPLIANCE_OFFICER)
    assert set(auth.load_users()) == {"root", "alice"}

    # cannot demote the last admin
    with pytest.raises(ValueError):
        users.set_role("root", roles.VIEWER, acting_user="alice")

    # promote alice, then root can be demoted (two admins exist)
    users.set_role("alice", roles.ADMIN, acting_user="root")
    users.set_role("root", roles.VIEWER, acting_user="alice")
    assert auth.load_users()["root"]["role"] == roles.VIEWER

    # cannot remove your own account
    with pytest.raises(ValueError):
        users.remove_user("alice", acting_user="alice")

    users.remove_user("root", acting_user="alice")
    assert set(auth.load_users()) == {"alice"}

    # cannot remove the last admin
    with pytest.raises(ValueError):
        users.remove_user("alice", acting_user="root")
