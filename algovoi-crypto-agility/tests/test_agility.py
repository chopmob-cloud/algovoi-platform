"""Crypto-agility engine tests — classification, migration continuity, hybrid signing, ML-KEM re-wrap."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from algovoi_crypto_agility import (
    CryptoAgility,
    CryptoAgilityError,
    HybridPqcEncryptor,
    classify,
    generate_mlkem_keypair,
    signing,
    verify_hybrid_envelope,
    verify_legacy_ed25519,
    verify_migration_attestation,
)


@pytest.fixture()
def ca():
    pk, sk = signing.generate_keypair()
    return pk, sk, CryptoAgility(secret_key=sk, public_key=pk, authority_did="did:web:acme")


def test_classify():
    assert classify("Ed25519").kind == "classical" and classify("Ed25519").quantum_vulnerable is True
    assert classify("ML-KEM-1024").kind == "post-quantum" and classify("ML-KEM-1024").quantum_vulnerable is False
    assert classify("Falcon-1024").kind == "post-quantum"
    assert classify("X25519").family == "kem" and classify("X25519").quantum_vulnerable is True
    assert classify("X25519+ML-KEM-1024").kind == "hybrid" and classify("X25519+ML-KEM-1024").quantum_vulnerable is False
    assert classify("Whirligig-9000").quantum_vulnerable is True   # unknown -> treat as vulnerable


def test_inventory_flags_migration_need(ca):
    _pk, _sk, c = ca
    c.register(kid="old-sign", algorithm="Ed25519")
    c.register(kid="old-kem", algorithm="X25519")
    c.register(kid="new-sign", algorithm="Falcon-1024")
    inv = c.inventory()
    assert set(inv["quantum_vulnerable_active"]) == {"old-sign", "old-kem"}
    assert inv["post_quantum"] == ["new-sign"]
    assert inv["total"] == 3


def test_migrate_signature_continuity(ca):
    pk, _sk, c = ca
    lpriv = Ed25519PrivateKey.generate()
    lpub = lpriv.public_key().public_bytes_raw()
    msg = b"invoice-42 final"
    lsig = lpriv.sign(msg)
    assert verify_legacy_ed25519(message=msg, signature=lsig, public_key=lpub) is True
    ch = "sha256:" + hashlib.sha256(msg).hexdigest()
    c.register(kid="leg-1", algorithm="Ed25519")
    out = c.migrate_signature(content_hash=ch, legacy_alg="Ed25519", legacy_kid="leg-1",
                              legacy_signature_verified=True)
    r = verify_migration_attestation(out["attestation_envelope"], pk)
    assert r.verified and r.kind == "signature-migration"
    assert r.payload["legacy"]["quantum_vulnerable"] is True
    assert r.payload["migrated_to"]["algorithm"] == "Falcon-1024"
    assert r.payload["content_hash"] == ch
    assert c.inventory()["by_status"].get("migrated") == 1     # registry reflects the migration


def test_migrate_refuses_unverified_legacy(ca):
    _pk, _sk, c = ca
    with pytest.raises(CryptoAgilityError, match="not verified"):
        c.migrate_signature(content_hash="sha256:x", legacy_alg="Ed25519", legacy_kid="l",
                            legacy_signature_verified=False)


def test_bad_legacy_ed25519_rejected():
    lpriv = Ed25519PrivateKey.generate()
    lpub = lpriv.public_key().public_bytes_raw()
    assert verify_legacy_ed25519(message=b"a", signature=lpriv.sign(b"b"), public_key=lpub) is False


def test_classify_hybrid_fails_closed_on_unknown_component():
    """Security fix 2026-08-19: a "+"-joined name is only quantum-safe if every component is known AND at
    least one is post-quantum; a bogus/legacy component must not masquerade as a safe hybrid."""
    assert classify("Ed25519+x").quantum_vulnerable is True
    assert classify("RSA-1024+foo").quantum_vulnerable is True          # neither component is known
    assert classify("Ed25519+X25519").quantum_vulnerable is True        # all classical -> still vulnerable
    assert classify("X25519+ML-KEM-1024").quantum_vulnerable is False   # genuine hybrid stays safe


def test_migrate_signature_in_engine_verification(ca):
    """The authority itself verifies the legacy signature when given the material, and labels the
    attestation verification='in-engine' (security fix 2026-08-19)."""
    pk, _sk, c = ca
    lpriv = Ed25519PrivateKey.generate()
    lpub = lpriv.public_key().public_bytes_raw()
    msg = b"invoice-42 final"
    lsig = lpriv.sign(msg)
    ch = "sha256:" + hashlib.sha256(msg).hexdigest()
    out = c.migrate_signature(content_hash=ch, legacy_alg="Ed25519", legacy_kid="leg-1",
                              legacy_public_key=lpub, legacy_signature=lsig, legacy_message=msg)
    r = verify_migration_attestation(out["attestation_envelope"], pk)
    assert r.verified and r.payload["legacy"]["verification"] == "in-engine"


def test_migrate_signature_in_engine_rejects_bad_signature(ca):
    _pk, _sk, c = ca
    lpriv = Ed25519PrivateKey.generate()
    lpub = lpriv.public_key().public_bytes_raw()
    msg = b"invoice-42 final"
    bad_sig = lpriv.sign(b"a different message")
    ch = "sha256:" + hashlib.sha256(msg).hexdigest()
    with pytest.raises(CryptoAgilityError, match="in-engine legacy signature verification failed"):
        c.migrate_signature(content_hash=ch, legacy_alg="Ed25519", legacy_kid="leg-1",
                            legacy_public_key=lpub, legacy_signature=bad_sig, legacy_message=msg)


def test_migrate_signature_caller_asserted_is_labeled(ca):
    """The out-of-band boolean path still works but is honestly labeled caller-asserted, so a consumer
    can require verification=='in-engine' for a cryptographically-checked migration."""
    pk, _sk, c = ca
    out = c.migrate_signature(content_hash="sha256:abc", legacy_alg="Ed25519", legacy_kid="l",
                              legacy_signature_verified=True)
    r = verify_migration_attestation(out["attestation_envelope"], pk)
    assert r.verified and r.payload["legacy"]["verification"] == "caller-asserted"


def test_hybrid_sign(ca):
    pk, _sk, c = ca
    lpriv = Ed25519PrivateKey.generate()
    payload = {"order": "o-9", "amount": 100}
    h = c.hybrid_sign(payload=payload, legacy_alg="Ed25519", legacy_signature=lpriv.sign(b"x"))
    assert "pqc" in h and "legacy" in h
    assert verify_hybrid_envelope(h, pk).verified
    h["payload"] = {"order": "o-9", "amount": 999}              # tamper
    assert verify_hybrid_envelope(h, pk).verified is False


def test_hybrid_cosignature_enforced_when_legacy_key_supplied(ca):
    """Security fix 2026-08-19: the legacy block is outside the PQC signature, so a hybrid-aware verifier
    must independently verify the classical co-signature. Supplying legacy_public_key REQUIRES it."""
    import rfc8785
    pk, _sk, c = ca
    lpriv = Ed25519PrivateKey.generate()
    lpub = lpriv.public_key().public_bytes_raw()
    payload = {"order": "o-9", "amount": 100}
    good = c.hybrid_sign(payload=payload, legacy_alg="Ed25519",
                         legacy_signature=lpriv.sign(rfc8785.dumps(payload)), legacy_public_key=lpub)
    assert verify_hybrid_envelope(good, pk, legacy_public_key=lpub).verified
    # a legacy sig over unrelated bytes: PQC-only verification still passes, but requiring the co-signature
    # fails closed (the malleable legacy block can no longer be trusted as verified evidence).
    bad = c.hybrid_sign(payload=payload, legacy_alg="Ed25519", legacy_signature=lpriv.sign(b"x"))
    assert verify_hybrid_envelope(bad, pk).verified
    assert verify_hybrid_envelope(bad, pk, legacy_public_key=lpub).verified is False
    # stripping the legacy block also fails closed when a legacy key is required
    stripped = dict(good); stripped.pop("legacy")
    assert verify_hybrid_envelope(stripped, pk, legacy_public_key=lpub).verified is False


def test_hybrid_sign_rejects_bad_cosignature_at_production(ca):
    """hybrid_sign refuses to embed a legacy co-signature that does not cover the payload when a legacy
    key is supplied for pre-verification."""
    import rfc8785  # noqa: F401
    _pk, _sk, c = ca
    lpriv = Ed25519PrivateKey.generate()
    lpub = lpriv.public_key().public_bytes_raw()
    with pytest.raises(CryptoAgilityError, match="does not verify"):
        c.hybrid_sign(payload={"order": "o-9"}, legacy_alg="Ed25519",
                      legacy_signature=lpriv.sign(b"wrong"), legacy_public_key=lpub)


def test_rewrap_to_mlkem(ca):
    pk, _sk, c = ca
    npk, nsk = generate_mlkem_keypair()
    data = b"super secret key material"
    out = c.rewrap(plaintext=data, new_mlkem_pubkey=npk, old_kid="x25519-1", old_alg="X25519", content_label="dek")
    r = verify_migration_attestation(out["attestation_envelope"], pk)
    assert r.verified and r.kind == "rewrap-migration"
    assert r.payload["to"]["algorithm"] == "ML-KEM-1024" and r.payload["from"]["quantum_vulnerable"] is True
    assert "secret" not in out["attestation_envelope"]         # no plaintext in the receipt
    opened = HybridPqcEncryptor(b"", nsk).decrypt(signing.b64u_decode(out["sealed_b64"]))
    assert opened == data


def test_wrong_key_fails(ca):
    _pk, _sk, c = ca
    out = c.migrate_signature(content_hash="sha256:x", legacy_alg="Ed25519", legacy_kid="l",
                              legacy_signature_verified=True)
    wrong, _ = signing.generate_keypair()
    assert verify_migration_attestation(out["attestation_envelope"], wrong).verified is False


def test_free_for_any_suite_licence():
    from algovoi_crypto_agility import licensing
    assert licensing.INCLUDED_FREE_FOR_ANY_SUITE_LICENCE is True
