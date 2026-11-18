"""WatchlistStore tests — PQC-at-rest, persistence across reopen, no-PII snapshot."""
from __future__ import annotations

from algovoi_sanctions_monitor.encryption import HybridPqcEncryptor, generate_mlkem_keypair
from algovoi_sanctions_monitor.monitor import subject_ref
from algovoi_sanctions_monitor.store import WatchlistStore


def test_pqc_roundtrip_and_persistence(tmp_path):
    pk, sk = generate_mlkem_keypair()
    db = str(tmp_path / "monitor.db")
    ref = subject_ref("base", "0xSECRET")

    s = WatchlistStore(db, HybridPqcEncryptor(pk, sk))
    s.add(subject_ref=ref, network="base", address="0xSECRET", first_watched_ms=1)
    s.set_result(ref, "ALLOW", 2)
    s.log_delta(subject_ref=ref, transition="newly_hit", envelope="env-b64", receipt_hash="sha256:x", created_ms=3)
    s.close()

    # reopen with the same key -> state persists, subject decrypts
    s2 = WatchlistStore(db, HybridPqcEncryptor(pk, sk))
    assert s2.count() == 1
    sref, net, addr, last, fw = s2.subjects()[0]
    assert sref == ref and net == "base" and addr == "0xSECRET" and last == "ALLOW"
    snap = s2.status()[0]
    assert snap["subject_ref"] == ref and "address" not in snap and snap["last_result"] == "ALLOW"
    assert s2.recent_deltas()[0]["transition"] == "newly_hit"


def test_address_is_pqc_encrypted_at_rest(tmp_path):
    pk, sk = generate_mlkem_keypair()
    db = str(tmp_path / "monitor.db")
    s = WatchlistStore(db, HybridPqcEncryptor(pk, sk))
    s.add(subject_ref=subject_ref("zzchain", "0xSECRETWALLET"),
          network="zzchain", address="0xSECRETWALLET", first_watched_ms=1)
    s.close()
    raw = open(db, "rb").read()
    assert b"0xSECRETWALLET" not in raw, "counterparty address leaked unencrypted at rest"
    assert b"zzchain" not in raw, "network leaked unencrypted at rest"


def test_wrong_key_cannot_decrypt(tmp_path):
    pk, sk = generate_mlkem_keypair()
    db = str(tmp_path / "monitor.db")
    s = WatchlistStore(db, HybridPqcEncryptor(pk, sk))
    s.add(subject_ref=subject_ref("base", "0xZ"), network="base", address="0xZ", first_watched_ms=1)
    s.close()
    wpk, wsk = generate_mlkem_keypair()
    s2 = WatchlistStore(db, HybridPqcEncryptor(wpk, wsk))   # wrong ML-KEM key
    try:
        s2.subjects()
        raise AssertionError("decrypted with the wrong key")
    except Exception:
        pass


def test_delta_chain_detects_truncation(tmp_path):
    """Security fix 2026-08-19: the delta log is hash-chained + head-pinned, so a deleted receipt
    (a hidden sanctions hit) is detected instead of silently vanishing."""
    pk, sk = generate_mlkem_keypair()
    db = str(tmp_path / "monitor.db")
    s = WatchlistStore(db, HybridPqcEncryptor(pk, sk))
    for i in range(4):
        s.log_delta(subject_ref=f"ref{i}", transition="newly_hit", envelope="e",
                    receipt_hash=f"sha256:{i}", created_ms=i)
    assert s.verify_delta_chain()["valid"] is True
    pinned = s.delta_head()

    # Delete the most recent receipt directly (attacker with DB access hides a sanctions hit).
    s._db.execute("DELETE FROM delta_receipts WHERE chain_seq = 3")
    s._db.commit()
    res = s.verify_delta_chain()
    # head still says 4 rows -> head_mismatch; and the out-of-band pin also rejects it.
    assert res["valid"] is False
    assert s.verify_delta_chain(expected_head=pinned)["valid"] is False

    # Interior deletion leaves a seq gap.
    db2 = str(tmp_path / "m2.db")
    s2 = WatchlistStore(db2, HybridPqcEncryptor(pk, sk))
    for i in range(4):
        s2.log_delta(subject_ref=f"ref{i}", transition="newly_hit", envelope="e",
                     receipt_hash=f"sha256:{i}", created_ms=i)
    s2._db.execute("DELETE FROM delta_receipts WHERE chain_seq = 1")
    s2._db.commit()
    assert s2.verify_delta_chain()["valid"] is False
