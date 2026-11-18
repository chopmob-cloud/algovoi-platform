"""Tests for the AlgoVoi Retention App: store, export, and the HTTP API."""
from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

H0 = "sha256:" + "a" * 64
H1 = "sha256:" + "b" * 64
H2 = "sha256:" + "c" * 64


@pytest.fixture()
def store(tmp_path):
    from algovoi_retention_app.store import RetentionStore
    return RetentionStore(dsn=f"sqlite:///{tmp_path / 'r.db'}")


def test_append_derives_seq_prev_and_ref(store):
    from algovoi_retention_chain import retention_chain_ref
    r0 = store.append("acme", H0)
    assert r0.chain_seq == 0 and r0.prev_receipt_hash == ""
    assert r0.chain_ref == retention_chain_ref(
        prev_receipt_hash="", receipt_hash=H0, chain_seq=0, issuer_id="acme")
    r1 = store.append("acme", H1)
    assert r1.chain_seq == 1 and r1.prev_receipt_hash == H0
    # independent per-issuer chains: a new issuer starts at genesis
    o0 = store.append("globex", H0)
    assert o0.chain_seq == 0


def test_duplicate_receipt_rejected(store):
    from algovoi_retention_app.store import DuplicateReceipt
    store.append("acme", H0)
    with pytest.raises(DuplicateReceipt):
        store.append("acme", H0)


def test_stored_chain_verifies(store):
    from algovoi_retention_chain import verify_chain_sequence
    for h in (H0, H1, H2):
        store.append("acme", h)
    assert verify_chain_sequence([r.as_dict() for r in store.chain("acme")]) is True


def test_export_pack_verifies_and_is_ccc_shaped(store, tmp_path):
    from algovoi_retention_app.export import build_retention_pack, verify_retention_pack
    from algovoi_retention_app.signing import LocalSigner
    for h in (H0, H1, H2):
        store.append("acme", h)
    store.append("globex", H0)
    signer = LocalSigner.generate()
    pack = build_retention_pack(store.all_records(), signer, str(tmp_path / "pack"))

    # in-process re-verify (signatures + envelope chain + retention refs)
    res = verify_retention_pack(pack)
    assert res["verified"] is True
    assert res["entries"] == 4
    assert res["issuers"] == ["acme", "globex"]

    # CCC-shape: public_key.b64 is standard-base64; chain is a list of envelope
    # strings whose payloads carry the CCC integrity fields + the type label.
    with open(os.path.join(pack, "public_key.b64")) as fh:
        assert base64.b64decode(fh.read().strip()) == signer.pk
    with open(os.path.join(pack, "retention_chain.json")) as fh:
        envelopes = json.load(fh)
    assert isinstance(envelopes, list) and len(envelopes) == 4

    def b64u(s):
        return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))

    prev = None
    for i, e in enumerate(envelopes):
        env = json.loads(b64u(e))
        p = env["payload"]
        assert p["type"] == "retention_chain_link"
        assert p["seq"] == i
        assert p["prev_entry_hash"] == prev          # CCC integrity link
        assert "prev_receipt_hash" not in p          # must not collide with CCC auto-detect
        assert p["reg_basis"] == ["MiCA-80", "DORA-14", "AMLR-56"]
        prev = "sha256:" + hashlib.sha256(__import__("rfc8785").dumps(p)).hexdigest()


def test_tamper_is_detected(store, tmp_path):
    from algovoi_retention_app.export import build_retention_pack, verify_retention_pack
    from algovoi_retention_app.signing import LocalSigner
    store.append("acme", H0)
    store.append("acme", H1)
    signer = LocalSigner.generate()
    pack = build_retention_pack(store.all_records(), signer, str(tmp_path / "pack"))
    cf = os.path.join(pack, "retention_chain.json")
    with open(cf) as fh:
        envelopes = json.load(fh)
    # corrupt the last envelope string
    envelopes[-1] = envelopes[-1][:-4] + "AAAA"
    with open(cf, "w") as fh:
        json.dump(envelopes, fh)
    assert verify_retention_pack(pack)["verified"] is False


def test_api_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("RETENTION_DSN", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.setenv("RETENTION_DATA_DIR", str(tmp_path))
    # fresh import so module-level store/signer pick up the env
    import importlib

    import algovoi_retention_app.app as appmod
    importlib.reload(appmod)
    from fastapi.testclient import TestClient

    c = TestClient(appmod.app)
    assert c.get("/health").json()["service"] == "retention-app"

    r0 = c.post("/v1/receipts", json={"issuer_id": "acme", "receipt_hash": H0})
    assert r0.status_code == 200 and r0.json()["chain_seq"] == 0
    r1 = c.post("/v1/receipts", json={"issuer_id": "acme", "receipt_hash": H1})
    assert r1.json()["chain_seq"] == 1 and r1.json()["prev_receipt_hash"] == H0
    # duplicate rejected
    assert c.post("/v1/receipts", json={"issuer_id": "acme", "receipt_hash": H0}).status_code == 409

    chain = c.get("/v1/chains/acme").json()
    assert chain["entries"] == 2

    pos = c.get("/v1/posture").json()
    assert pos["all_verified"] is True and pos["total_entries"] == 2

    vr = c.post("/v1/verify", json={"records": chain["records"]})
    assert vr.json()["valid"] is True

    exp = c.get("/v1/export/acme")
    assert exp.status_code == 200 and exp.headers["content-type"] == "application/zip"
    assert exp.content[:2] == b"PK"
