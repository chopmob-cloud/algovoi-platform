"""Vault core tests — at-rest encryption, threshold recovery, and the enable/disable control."""
from __future__ import annotations

import os

import pytest

from algovoi_doc_archive import signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair
from algovoi_recovery_vault.vault import Vault, VaultError


@pytest.fixture(autouse=True)
def _standin_support_key(monkeypatch):
    sup_pk, sup_sk = generate_mlkem_keypair()
    monkeypatch.setenv("ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64", signing.b64u_encode(sup_pk))
    return sup_pk, sup_sk


@pytest.fixture()
def vault_path(tmp_path):
    return str(tmp_path / "recovery.vault")


SECRET = b"correct horse battery staple"


def test_create_open_roundtrip_and_wrong_secret(vault_path):
    v = Vault.create(vault_path, SECRET)
    v.generate_archive("primary")
    # reopen with right secret
    v2 = Vault.open(vault_path, SECRET)
    assert "primary" in v2.status()["archives"]
    # wrong secret fails closed
    with pytest.raises(VaultError, match="could not unlock"):
        Vault.open(vault_path, b"wrong secret")


def test_at_rest_is_encrypted(vault_path):
    v = Vault.create(vault_path, SECRET)
    info = v.generate_archive("primary")
    raw = open(vault_path, "rb").read()
    # the archive public key (and certainly the secret) must not appear in cleartext on disk
    assert info["archive_pub_b64"].encode() not in raw
    assert b"archive_sk_b64" not in raw  # the JSON field name itself is inside the ciphertext


def test_split_and_recover_roundtrip(vault_path):
    v = Vault.create(vault_path, SECRET)
    v.generate_archive("primary")
    original = v.export_archive_secret("primary")
    env, shares = v.split("primary", threshold_k=2, total_n=3)
    assert env["support_assisted"] is True  # access enabled by default
    assert len(shares) == 2                  # n-1 to the client; AlgoVoi holds one
    # wipe + recover from k client shares
    out = v.recover("primary", shares=shares[:2])
    assert out["recovered"] is True
    assert v.export_archive_secret("primary") == original


def test_disable_access_blocks_algovoi_share(vault_path):
    v = Vault.create(vault_path, SECRET)
    v.generate_archive("primary")
    v.set_algovoi_access(False)
    assert v.algovoi_access_enabled() is False
    # default split now self-custody only: all n shares to the client, no embedded AlgoVoi share
    env, shares = v.split("primary", threshold_k=2, total_n=3)
    assert env["support_assisted"] is False
    assert "algovoi_support_share" not in env
    assert len(shares) == 3
    # explicitly requesting an AlgoVoi share is refused while disabled
    with pytest.raises(VaultError, match="AlgoVoi access is disabled"):
        v.split("primary", threshold_k=2, total_n=3, include_algovoi_support=True)


def test_resplit_invalidates_old_shares(vault_path):
    v = Vault.create(vault_path, SECRET)
    v.generate_archive("primary")
    _env1, shares1 = v.split("primary", threshold_k=2, total_n=3)
    _env2, shares2 = v.resplit("primary", threshold_k=2, total_n=3, include_algovoi_support=False)
    # old shares no longer reconstruct against the NEW envelope
    with pytest.raises(Exception):
        v.recover("primary", shares=shares1[:2])
    # new shares do
    assert v.recover("primary", shares=shares2[:2])["recovered"] is True


def test_persistence_across_instances(vault_path):
    v = Vault.create(vault_path, SECRET)
    v.generate_archive("primary")
    v.set_algovoi_access(False)
    v.split("primary", threshold_k=2, total_n=2)
    # fresh instance sees the persisted state
    v2 = Vault.open(vault_path, SECRET)
    st = v2.status()
    assert st["algovoi_access"] is False
    assert st["archives"]["primary"]["has_envelope"] is True
    assert st["archives"]["primary"]["support_assisted"] is False


def test_generic_signing_key_split_recover(vault_path):
    v = Vault.create(vault_path, SECRET)
    out = v.generate_signing_key("sig", auto_split=True)   # access on -> AlgoVoi holds 1, client gets 2
    assert out["kind"] == "signing-falcon"
    assert out["envelope"]["kind"] == "generic-secret" and len(out["shares"]) == 2
    original = v.export_key("sig")
    assert v.recover_key("sig", shares=out["shares"])["recovered"] is True
    assert v.export_key("sig") == original
    assert v.status()["keys"]["sig"]["kind"] == "signing-falcon"


def test_import_arbitrary_key(vault_path):
    v = Vault.create(vault_path, SECRET)
    secret = os.urandom(64)
    v.import_key("k1", secret=secret, kind="x25519")
    _env, shares = v.split_key("k1", threshold_k=2, total_n=3)
    assert v.recover_key("k1", shares=shares[:2])["recovered"] is True
    assert v.export_key("k1") == secret
