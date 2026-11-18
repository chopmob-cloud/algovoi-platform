"""Threshold-recovery tests — the Shamir k-of-n custody guarantees, enforced.

Key properties under test:
  * default split returns all n shares to the client; AlgoVoi holds NOTHING.
  * with opt-in support, AlgoVoi holds exactly ONE share and the client holds n-1.
  * AlgoVoi's lone share recovers NOTHING (below threshold) — the central guarantee.
  * any k shares (client-only, or client + AlgoVoi's contributed share) recover the key.
  * a recovered key passes the sentinel and decrypts a real document.
  * wrong threshold / tampering / bad params are rejected.
"""
from __future__ import annotations

import pytest

from algovoi_doc_archive import recovery, signing
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair
from algovoi_doc_archive.recovery import (
    RecoveryError,
    algovoi_share_mnemonic,
    recover_from_shares,
    restore_encryptor,
    split_recovery,
    verify_envelope,
)


@pytest.fixture()
def archive_keys():
    return generate_mlkem_keypair()  # (archive_pk, archive_sk)


@pytest.fixture()
def signer():
    return signing.generate_keypair()  # (falcon_pk, falcon_sk)


def _stand_in_support_key(monkeypatch):
    sup_pk, sup_sk = generate_mlkem_keypair()
    monkeypatch.setenv("ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64", signing.b64u_encode(sup_pk))
    return sup_pk, sup_sk


def test_default_self_custody_all_shares_returned(archive_keys):
    archive_pk, archive_sk = archive_keys
    env, shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=2, total_n=3
    )
    assert env["support_assisted"] is False
    assert "algovoi_support_share" not in env
    assert len(shares) == 3  # all n shares to the client; AlgoVoi holds nothing
    # any 2 reconstruct
    assert recover_from_shares(envelope=env, shares=shares[:2]) == archive_sk


def test_kminus1_shares_recover_nothing(archive_keys):
    archive_pk, archive_sk = archive_keys
    env, shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=3, total_n=5
    )
    with pytest.raises(RecoveryError, match="need at least 3 shares"):
        recover_from_shares(envelope=env, shares=shares[:2])


def test_optin_support_holds_exactly_one_share(monkeypatch, archive_keys):
    archive_pk, archive_sk = archive_keys
    _sup_pk, sup_sk = _stand_in_support_key(monkeypatch)

    env, client_shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk,
        threshold_k=2, total_n=3, include_algovoi_support=True,
    )
    assert env["support_assisted"] is True
    assert len(client_shares) == 2          # n-1 to the client
    assert "algovoi_support_share" in env   # exactly one, embedded + encrypted

    # AlgoVoi's lone share recovers NOTHING on its own (below threshold of 2).
    algovoi_mnemonic = algovoi_share_mnemonic(env, sup_sk)
    with pytest.raises(RecoveryError):
        recover_from_shares(envelope=env, shares=[algovoi_mnemonic])


def test_support_assisted_break_glass(monkeypatch, archive_keys):
    """Client lost all but ONE share; AlgoVoi contributes its one -> reaches k=2 -> recovers."""
    archive_pk, archive_sk = archive_keys
    _sup_pk, sup_sk = _stand_in_support_key(monkeypatch)

    env, client_shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk,
        threshold_k=2, total_n=3, include_algovoi_support=True,
    )
    surviving_client_share = client_shares[0]            # client kept only one
    algovoi_mnemonic = algovoi_share_mnemonic(env, sup_sk)  # support contributes its one
    recovered = recover_from_shares(envelope=env, shares=[surviving_client_share, algovoi_mnemonic])
    assert recovered == archive_sk


def test_client_can_self_recover_without_algovoi(monkeypatch, archive_keys):
    """With n-1=2 client shares and k=2, the client never needs AlgoVoi at all."""
    archive_pk, archive_sk = archive_keys
    _stand_in_support_key(monkeypatch)
    env, client_shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk,
        threshold_k=2, total_n=3, include_algovoi_support=True,
    )
    assert recover_from_shares(envelope=env, shares=client_shares[:2]) == archive_sk


def test_recovered_key_decrypts_a_real_document(archive_keys):
    archive_pk, archive_sk = archive_keys
    ciphertext = HybridPqcEncryptor(archive_pk).encrypt(b"PROD BACKUP blob")
    env, shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=2, total_n=2
    )
    recovered = recover_from_shares(envelope=env, shares=shares)
    enc = restore_encryptor(env, recovered)
    assert enc.can_decrypt and enc.decrypt(ciphertext) == b"PROD BACKUP blob"


def test_signed_envelope_verifies_and_tamper_detected(archive_keys, signer):
    archive_pk, archive_sk = archive_keys
    falcon_pk, falcon_sk = signer
    env, shares = split_recovery(
        master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=2, total_n=3,
        sign_secret_key=falcon_sk, sign_public_key=falcon_pk,
    )
    assert verify_envelope(env, falcon_pk) is True
    assert recover_from_shares(
        envelope=env, shares=shares[:2], verify_public_key=falcon_pk
    ) == archive_sk

    tampered = dict(env)
    tampered["threshold_k"] = 1  # try to weaken the threshold
    assert verify_envelope(tampered, falcon_pk) is False
    with pytest.raises(RecoveryError, match="signature did not verify"):
        recover_from_shares(envelope=tampered, shares=shares[:2], verify_public_key=falcon_pk)


def test_bad_parameters_rejected(archive_keys):
    archive_pk, archive_sk = archive_keys
    with pytest.raises(RecoveryError, match="1-of-n"):  # k=1 is no protection
        split_recovery(master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=1, total_n=3)
    with pytest.raises(RecoveryError, match="threshold_k <= total_n"):
        split_recovery(master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=4, total_n=3)
    with pytest.raises(RecoveryError, match="total_n must be >= 2"):
        split_recovery(master_secret=archive_sk, archive_public_key=archive_pk, threshold_k=2, total_n=1)


def test_generic_secret_mode_roundtrip(signer):
    # ANY key (e.g. a Falcon signing secret) can be split + recovered, no archive pubkey needed.
    falcon_pk, falcon_sk = signer
    env, shares = split_recovery(master_secret=falcon_sk, threshold_k=2, total_n=3)  # archive_public_key=None
    assert env["kind"] == "generic-secret"
    assert "archive_public_key_b64" not in env and "sentinel_b64" not in env
    recovered = recover_from_shares(envelope=env, shares=shares[:2])
    assert recovered == falcon_sk
    # too few shares still rejected; restore_encryptor is archive-only
    with pytest.raises(RecoveryError):
        recover_from_shares(envelope=env, shares=shares[:1])
    with pytest.raises(RecoveryError, match="archive-encryption-key"):
        restore_encryptor(env, recovered)


def test_generic_secret_with_optin_support(monkeypatch, archive_keys):
    _archive_pk, archive_sk = archive_keys
    _sup_pk, sup_sk = _stand_in_support_key(monkeypatch)
    env, client_shares = split_recovery(master_secret=archive_sk, threshold_k=2, total_n=3,
                                        include_algovoi_support=True)
    assert env["kind"] == "generic-secret" and env["support_assisted"] is True
    algovoi_m = algovoi_share_mnemonic(env, sup_sk)
    assert recover_from_shares(envelope=env, shares=[client_shares[0], algovoi_m]) == archive_sk


def test_baked_support_fingerprint_matches_constant():
    pk = signing.b64u_decode(recovery.ALGOVOI_SUPPORT_RECOVERY_PUBKEY_B64)
    assert recovery.fingerprint(pk) == recovery.ALGOVOI_SUPPORT_RECOVERY_FINGERPRINT
