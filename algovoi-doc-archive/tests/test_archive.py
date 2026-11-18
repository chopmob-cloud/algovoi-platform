"""Unit tests for algovoi-doc-archive (local filesystem backend; no external services)."""
from __future__ import annotations

import base64
import json
import os

import pytest
from fastapi.testclient import TestClient

from algovoi_doc_archive import signing
from algovoi_doc_archive.app import create_app
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.auth import bearer_token_auth
from algovoi_doc_archive.backend import LocalFsBackend
from algovoi_doc_archive.encryption import (
    AesGcmEncryptor,
    HybridPqcEncryptor,
    generate_mlkem_keypair,
)
from algovoi_doc_archive.verifier import verify_chain, verify_entry

DOC = b"This is a confidential contract. " * 40  # ~1.3 KB


@pytest.fixture
def keys():
    pk, sk = signing.generate_keypair()
    return pk, sk


@pytest.fixture
def enc():
    kpk, ksk = generate_mlkem_keypair()
    return HybridPqcEncryptor(kpk, ksk)


def _archive(tmp_path, pk, sk, enc=None):
    return Archive(secret_key=sk, public_key=pk,
                   storage=LocalFsBackend(str(tmp_path / "arc")), encryptor=enc, issuer_did="did:web:test")


# ---- encryption ----------------------------------------------------------------------------

def test_aesgcm_roundtrip():
    e = AesGcmEncryptor(os.urandom(32))
    blob = e.encrypt(DOC)
    assert blob != DOC and e.decrypt(blob) == DOC


def test_aesgcm_wrong_key_fails():
    e1, e2 = AesGcmEncryptor(os.urandom(32)), AesGcmEncryptor(os.urandom(32))
    with pytest.raises(Exception):
        e2.decrypt(e1.encrypt(DOC))


def test_hybrid_pqc_roundtrip():
    kpk, ksk = generate_mlkem_keypair()
    e = HybridPqcEncryptor(kpk, ksk)
    assert e.alg == "ML-KEM-1024+AES-256-GCM"
    blob = e.encrypt(DOC)
    assert blob != DOC and e.decrypt(blob) == DOC


def test_hybrid_pqc_write_only_node_cannot_decrypt():
    kpk, _ = generate_mlkem_keypair()
    e = HybridPqcEncryptor(kpk)  # no secret key
    blob = e.encrypt(DOC)
    assert e.can_decrypt is False
    with pytest.raises(RuntimeError):
        e.decrypt(blob)


# ---- archive engine ------------------------------------------------------------------------

async def test_notarize_stores_encrypted_and_verifies(tmp_path, keys, enc):
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    out = await arc.notarize(data=DOC, title="MSA v3", content_type="application/pdf")
    assert out["stored"] and out["enc_alg"] == "ML-KEM-1024+AES-256-GCM"
    # the entry receipt verifies
    res = verify_entry(out["receipt"], pk)
    assert res.verified and res.doc_hash == out["doc_hash"] and res.title == "MSA v3"
    # the blob on disk is ciphertext, not the plaintext, and longer (KEM ct + nonce + tag)
    raw = await arc.storage.get(f"blob/{out['doc_hash'].split(':')[1]}")
    assert raw is not None and raw != DOC and len(raw) > len(DOC)


async def test_retrieve_decrypts_and_checks_integrity(tmp_path, keys, enc):
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    out = await arc.notarize(data=DOC, title="doc")
    assert await arc.retrieve(doc_hash=out["doc_hash"]) == DOC


async def test_notarize_by_hash_stores_no_blob(tmp_path, keys, enc):
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    h = "sha256:" + __import__("hashlib").sha256(DOC).hexdigest()
    out = await arc.notarize(doc_hash=h, title="hash-only")
    assert out["stored"] is False and out["enc_alg"] == "none"
    with pytest.raises(FileNotFoundError):
        await arc.retrieve(doc_hash=h)


async def test_chain_is_valid_and_ordered(tmp_path, keys, enc):
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    for i in range(3):
        await arc.notarize(data=DOC + bytes([i]), title=f"doc{i}")
    res = await arc.verify_chain()
    assert res.valid and res.length == 3 and res.head_receipt_hash is not None


async def test_chain_tamper_is_detected(tmp_path, keys, enc):
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    for i in range(3):
        await arc.notarize(data=DOC + bytes([i]), title=f"doc{i}")
    entries = await arc.list_entries()
    env = json.loads(signing.b64u_decode(entries[1]))
    env["payload"]["title"] = "HACKED"  # tamper an entry → its signature no longer matches
    entries[1] = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    res = verify_chain(entries, pk)
    assert res.valid is False and res.broken_at == 1


async def test_truncation_and_hole_detected(tmp_path, keys, enc):
    """A clean prefix is not a clean whole: interior/trailing deletion is caught against the persisted
    head, and a full head-rewrite is caught against an out-of-band anchor (security fix 2026-08-19)."""
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    for i in range(4):
        await arc.notarize(data=DOC + bytes([i]), title=f"doc{i}")
    pinned = await arc.head()                         # {seq_count:4, last_receipt_hash:...}
    entries = await arc.list_entries()
    assert (await arc.verify_chain()).valid

    # Trailing deletion, head blob left intact: the persisted seq_count still counts the dropped entry.
    (tmp_path / "arc" / "entry" / "000000000003.json").unlink()
    res = await arc.verify_chain()
    assert res.valid is False and res.reason == "missing_entry"

    # Out-of-band anchor path: a valid prefix presented with the pinned head is rejected as truncated
    # (covers the case where an attacker also rewrites the head blob to match the shortened chain).
    res_anchor = verify_chain(entries[:3], pk, expected_head=pinned)
    assert res_anchor.valid is False and res_anchor.reason in ("length_mismatch", "head_mismatch")

    # Interior deletion is caught too (fresh archive under a separate root).
    arc2 = _archive(tmp_path / "b", pk, sk, enc)
    for i in range(4):
        await arc2.notarize(data=DOC + bytes([i]), title=f"doc{i}")
    (tmp_path / "b" / "arc" / "entry" / "000000000001.json").unlink()
    resh = await arc2.verify_chain()
    assert resh.valid is False and resh.reason == "missing_entry"


async def test_partial_or_malformed_expected_head_never_passes(tmp_path, keys, enc):
    """An anchor that cannot be checked must FAIL, never silently skip the truncation guard.

    Regression for the fail-open found 2026-08-14: `expected_head={}` returned valid=True because every
    guard was written `if exp_x is not None`, so an empty or partial anchor checked nothing and the caller
    read a green result believing the tail had been pinned. A malformed seq_count raised ValueError out of
    a function documented as "pure, never raises", turning a corrupt anchor into a crash.
    """
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    for i in range(2):
        await arc.notarize(data=DOC + bytes([i]), title=f"doc{i}")
    entries = await arc.list_entries()
    full = await arc.head()

    # a complete anchor over the whole chain still passes
    assert verify_chain(entries, pk, expected_head=full).valid is True

    # incomplete anchors must be refused, not treated as "nothing to check"
    for partial in ({}, {"seq_count": 2}, {"last_receipt_hash": full["last_receipt_hash"]}):
        res = verify_chain(entries, pk, expected_head=partial)
        assert res.valid is False, f"partial anchor {partial} passed verification"
        assert res.reason == "incomplete_expected_head", res.reason

    # malformed seq_count must return a result, not raise (the module is documented never to raise)
    for bad in ("abc", "", [], 1.5):
        res = verify_chain(entries, pk, expected_head={"seq_count": bad,
                                                       "last_receipt_hash": full["last_receipt_hash"]})
        assert res.valid is False, f"malformed seq_count {bad!r} passed verification"
        assert res.reason == "incomplete_expected_head", res.reason



async def test_corrupt_head_is_a_failed_verification_not_a_crash(tmp_path, keys, enc):
    """A persisted head that is not an integer must return valid=False, not raise.

    Regression for 2026-08-14: `int(head.get("seq_count") or 0)` raised ValueError out of
    ``Archive.verify_chain``, so a damaged or hostile head blob produced a traceback. A caller with a
    broad ``except`` then records "could not verify" instead of "tampered", which is the wrong verdict
    for a store that has been written to by someone other than the archiver.
    """
    import json as _json

    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    await arc.notarize(data=DOC, title="doc")

    head_path = tmp_path / "arc" / "archive" / "head.json"
    original = head_path.read_text()

    for poisoned in ("abc", "", None, -1, 1.5, True):
        head_path.write_text(_json.dumps({"seq_count": poisoned,
                                          "last_receipt_hash": None,
                                          "last_entry_id": None}))
        try:
            res = await arc.verify_chain()
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"verify_chain raised {type(exc).__name__} on head seq_count={poisoned!r} "
                f"instead of returning a result") from exc
        assert res.valid is False, f"head seq_count={poisoned!r} verified as valid"
        assert res.reason == "corrupt_head", f"{poisoned!r} -> {res.reason}"

    head_path.write_text(original)
    assert (await arc.verify_chain()).valid is True


async def test_empty_archive_verifies(tmp_path, keys, enc):
    """A brand-new archive with no entries must verify, not fail the anchor guard.

    Regression for 2026-11-14: the incompleteness guard added that day required
    ``last_receipt_hash`` to be a string, but an empty archive's persisted head carries
    ``None`` (there is no previous receipt to hash), so verify_chain returned
    valid=False/incomplete_expected_head on a perfectly healthy empty store.
    """
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)

    head = await arc.head()
    assert head["seq_count"] == 0 and head["last_receipt_hash"] is None

    res = await arc.verify_chain()
    assert res.valid is True, f"empty archive failed verification: {res.reason}"
    assert res.length == 0
    assert res.head_receipt_hash is None


async def test_backend_fault_is_a_failed_verification_not_a_crash(tmp_path, keys, enc):
    """A storage backend that raises must produce valid=False, never propagate the exception.

    Regression for 2026-11-14: ``Archive.verify_chain`` read entries in a loop assuming
    ``get_entry`` returns None for a missing key. A backend raising (I/O error, malformed
    store, a hostile mount) escaped as an exception, so a caller with a broad ``except``
    recorded "could not verify" rather than "verification refused".
    """
    pk, sk = keys

    class FlakyBackend(LocalFsBackend):
        fail_after: int | None = None

        def get(self, key):
            if self.fail_after is not None and f"entry/{self.fail_after:012d}" in key:
                raise KeyError("simulated backend fault")
            return super().get(key)

    storage = FlakyBackend(str(tmp_path / "arc"))
    arc = Archive(secret_key=sk, public_key=pk, storage=storage,
                  encryptor=enc, issuer_did="did:web:test")
    for i in range(3):
        await arc.notarize(data=DOC + bytes([i]), title=f"d{i}")
    assert (await arc.verify_chain()).valid is True

    storage.fail_after = 1
    try:
        res = await arc.verify_chain()
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"verify_chain raised {type(exc).__name__} on a backend fault instead of "
            f"returning a result") from exc
    assert res.valid is False, "a backend fault verified as valid"
    assert res.reason == "backend_error", res.reason
    assert res.length == 1, res.length


async def test_corrupt_head_blames_the_head_not_the_caller_anchor(tmp_path, keys, enc):
    """A corrupted persisted head must report corruption, not a bad caller anchor.

    Regression for 2026-11-14: with no explicit ``expected_head``, Archive.verify_chain builds the
    anchor from the persisted head, so a head missing ``last_receipt_hash`` reached the verifier as an
    incomplete anchor and reported ``incomplete_expected_head``. That blames a caller who supplied
    nothing and sends an operator looking at their own code instead of at a damaged store. The
    converse matters too: an EMPTY store whose head claims a tail hash is equally corrupt, and it
    previously surfaced as head_mismatch for the same reason.
    """
    import json as _json

    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    await arc.notarize(data=DOC, title="doc")

    head_path = tmp_path / "arc" / "archive" / "head.json"
    original = head_path.read_text()

    for drop in ("last_receipt_hash", "both"):
        d = _json.loads(original)
        d.pop("last_receipt_hash", None)
        if drop == "both":
            d.pop("seq_count", None)
        head_path.write_text(_json.dumps(d))
        res = await arc.verify_chain()
        assert res.valid is False, f"corrupt head ({drop}) verified as valid"
        assert res.reason == "corrupt_head", f"({drop}) -> {res.reason}"

    head_path.write_text(original)
    assert (await arc.verify_chain()).valid is True


async def test_empty_store_whose_head_claims_a_tail_hash_is_corrupt(tmp_path, keys, enc):
    """seq_count 0 with a non-None tail hash is a corrupted head, not a caller mistake.

    Regression for 2026-11-14: the empty-archive allowance only checked that count and hash agreed on
    emptiness, so a head claiming ``seq_count: 0`` with a populated ``last_receipt_hash`` fell through
    and reported head_mismatch against an anchor the caller never supplied.
    """
    import json as _json

    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    await arc.notarize(data=DOC, title="doc")
    head_path = tmp_path / "arc" / "archive" / "head.json"
    original = head_path.read_text()

    d = _json.loads(original)
    d["seq_count"] = 0
    d["last_receipt_hash"] = "sha256:" + "0" * 64      # claims a tail that cannot exist
    head_path.write_text(_json.dumps(d))

    res = await arc.verify_chain()
    assert res.valid is False
    assert res.reason == "corrupt_head", res.reason

    head_path.write_text(original)
    assert (await arc.verify_chain()).valid is True


async def test_fatal_errors_propagate_rather_than_becoming_a_verification_result(tmp_path, keys, enc):
    """MemoryError must escape verify_chain, not be reported as a tidy backend_error.

    Regression for 2026-11-14: the `except Exception` that stops a storage fault from crashing
    verification also catches MemoryError, because MemoryError is a subclass of Exception. An
    exhausted process was therefore converted into ``reason="backend_error"``, which reads as a
    store problem and hides the real fault. Fatal, non-recoverable errors are re-raised.
    """
    pk, sk = keys

    class FatalBackend(LocalFsBackend):
        fatal: type[BaseException] | None = None

        def get(self, key):
            if self.fatal is not None and "entry/" in key:
                raise self.fatal("simulated fatal error")
            return super().get(key)

    storage = FatalBackend(str(tmp_path / "arc"))
    arc = Archive(secret_key=sk, public_key=pk, storage=storage,
                  encryptor=enc, issuer_did="did:web:test")
    await arc.notarize(data=DOC, title="doc")

    for exc in (MemoryError, RecursionError):
        storage.fatal = exc
        with pytest.raises(exc):
            await arc.verify_chain()

    # a recoverable fault is still reported as a refusal, not raised
    storage.fatal = None
    assert (await arc.verify_chain()).valid is True


async def test_empty_chain_with_nonempty_anchor_is_refused(tmp_path, keys, enc):
    """An empty chain against a non-empty anchor must be refused, and mislabelled anchors distinguished.

    Complements test_empty_archive_verifies (which allows the legitimate (0, None) anchor). Two shapes
    matter, and they deserve different reasons: a GENUINELY malformed anchor, and a well-formed empty
    anchor that simply does not match a non-empty chain (which is a length mismatch, not a bad anchor).
    """
    pk, sk = keys
    for head in (
        {"seq_count": 0, "last_receipt_hash": "sha256:" + "0" * 64},   # hash present, count 0
        {"seq_count": 3, "last_receipt_hash": "sha256:" + "0" * 64},   # count claims entries
        {"seq_count": 1, "last_receipt_hash": None},                   # count without a hash
    ):
        try:
            res = verify_chain([], pk, expected_head=head)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(
                f"verify_chain raised {type(exc).__name__} on an empty chain with anchor {head}"
            ) from exc
        assert res.valid is False, f"empty chain verified against anchor {head}"
        # a hash at count 0 claims an entry that cannot exist: malformed, matching archive.py
        if head["seq_count"] == 0:
            assert res.reason == "incomplete_expected_head", res.reason


async def test_wellformed_empty_anchor_against_a_nonempty_chain_is_a_length_mismatch(tmp_path, keys, enc):
    """A well-formed (0, None) anchor is VALID but wrong length: report length_mismatch, not a bad anchor.

    Regression for 2026-11-14: the incompleteness guard rejected (0, None) because exp_head was not a
    string, so a caller who pinned an empty anchor against a chain that had grown was told their anchor
    was malformed. The anchor is fine; the chain outgrew it.
    """
    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    await arc.notarize(data=DOC, title="doc")
    entries = await arc.list_entries()

    res = verify_chain(entries, pk, expected_head={"seq_count": 0, "last_receipt_hash": None})
    assert res.valid is False
    assert res.reason == "length_mismatch", res.reason


async def test_stale_head_is_distinguished_from_a_deleted_entry(tmp_path, keys, enc):
    """A head that lags the entries (crash) must not be reported as a deleted entry (tampering).

    Regression for 2026-11-14: both conditions returned "missing_entry", so an operator seeing that
    reason would look for a deletion that never happened when the real cause was a writer that died
    between appending an entry and updating the head blob.
    """
    import json as _json

    pk, sk = keys
    arc = _archive(tmp_path, pk, sk, enc)
    for i in range(4):
        await arc.notarize(data=DOC + bytes([i]), title=f"d{i}")
    head_path = tmp_path / "arc" / "archive" / "head.json"
    original = head_path.read_text()

    # head LAGS: claims 1 entry, 4 are present -> stale_head
    d = _json.loads(original)
    d["seq_count"] = 1
    head_path.write_text(_json.dumps(d))
    res = await arc.verify_chain()
    assert res.valid is False and res.reason == "stale_head", res.reason
    assert res.broken_at == 1, res.broken_at

    # head LEADS: an entry is gone -> missing_entry
    head_path.write_text(original)
    (tmp_path / "arc" / "entry" / "000000000002.json").unlink()
    res = await arc.verify_chain()
    assert res.valid is False and res.reason == "missing_entry", res.reason


async def test_verify_entry_wrong_key_rejected(tmp_path, keys, enc):
    pk, sk = keys
    pk2, _ = signing.generate_keypair()
    arc = _archive(tmp_path, pk, sk, enc)
    out = await arc.notarize(data=DOC, title="doc")
    assert verify_entry(out["receipt"], pk2).verified is False


# ---- app surface ---------------------------------------------------------------------------

def test_app_health_and_pqc_keys(tmp_path, keys, enc):
    pk, sk = keys
    client = TestClient(create_app(_archive(tmp_path, pk, sk, enc), public_key=pk))
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["kid"] == signing.kid_for(pk)
    assert client.get("/.well-known/pqc-keys.json").json()["keys"][0]["alg"] == "Falcon-1024"


def test_app_notarize_verify_retrieve(tmp_path, keys, enc):
    pk, sk = keys
    client = TestClient(create_app(_archive(tmp_path, pk, sk, enc), public_key=pk))
    out = client.post("/v1/archive/notarize", json={
        "data_b64": base64.b64encode(DOC).decode(), "title": "contract", "content_type": "application/pdf"}).json()
    assert out["stored"] is True
    assert client.post("/v1/archive/verify", json={"receipt": out["receipt"]}).json()["verified"] is True
    assert client.get("/v1/archive/verify-chain").json()["valid"] is True
    r = client.get(f"/v1/archive/retrieve/{out['doc_hash'].split(':')[1]}")
    assert r.status_code == 200 and r.content == DOC


def test_app_notarize_auth_required(tmp_path, keys, enc):
    pk, sk = keys
    client = TestClient(create_app(_archive(tmp_path, pk, sk, enc), public_key=pk,
                                   auth_dependency=bearer_token_auth("secret")))
    body = {"data_b64": base64.b64encode(DOC).decode(), "title": "x"}
    assert client.post("/v1/archive/notarize", json=body).status_code == 401
    assert client.post("/v1/archive/notarize", headers={"Authorization": "Bearer wrong"}, json=body).status_code == 403


def test_app_entry_lookup_and_404(tmp_path, keys, enc):
    pk, sk = keys
    client = TestClient(create_app(_archive(tmp_path, pk, sk, enc), public_key=pk))
    client.post("/v1/archive/notarize", json={"data_b64": base64.b64encode(DOC).decode(), "title": "d"})
    assert client.get("/v1/archive/entry/0").json()["payload"]["type"] == "archive_entry"
    assert client.get("/v1/archive/entry/99").status_code == 404
