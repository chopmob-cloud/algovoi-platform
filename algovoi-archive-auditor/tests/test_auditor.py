"""Tests for algovoi-archive-auditor (builds a real archive, then audits it read-only)."""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from algovoi_doc_archive import Archive, HybridPqcEncryptor, LocalFsBackend, signing
from algovoi_doc_archive.encryption import generate_mlkem_keypair

from algovoi_archive_auditor import (
    Auditor,
    RetentionPolicy,
    bearer_token_auth,
    create_app,
    exporters,
)


@pytest.fixture
def archive_keys():
    return signing.generate_keypair()  # (public, secret)


@pytest.fixture
def auditor_keys():
    return signing.generate_keypair()


async def _populate(tmp_path):
    apk, ask = signing.generate_keypair()
    enc_pk, enc_sk = generate_mlkem_keypair()
    backend = LocalFsBackend(str(tmp_path / "arc"))
    arc = Archive(secret_key=ask, public_key=apk, storage=backend,
                  encryptor=HybridPqcEncryptor(enc_pk, enc_sk), issuer_did="did:web:archive")
    await arc.notarize(data=b"%PDF-1 contract", title="MSA", content_type="application/pdf")
    await arc.notarize(data=b"<xml>invoice</xml>", title="INV-1", content_type="application/xml")
    await arc.notarize(data=b"%PDF-1 nda", title="NDA", content_type="application/pdf")
    return apk, backend


def _auditor(apk, backend, auditor_keys=None):
    if auditor_keys is None:
        return Auditor(archive_public_key=apk, storage=backend)
    rpk, rsk = auditor_keys
    return Auditor(archive_public_key=apk, storage=backend, report_secret_key=rsk, report_public_key=rpk)


# ---- reports / attestations ----------------------------------------------------------------

async def test_audit_report_signed_and_summarised(tmp_path, auditor_keys):
    apk, backend = await _populate(tmp_path)
    rpk, _ = auditor_keys
    out = await _auditor(apk, backend, auditor_keys).audit_report()
    rep = out["report"]
    assert rep["chain_valid"] is True and rep["entries"] == 3
    assert rep["totals_by_content_type"] == {"application/pdf": 2, "application/xml": 1}
    payload, sig, _ = signing.open_envelope(out["report_envelope"])
    assert signing.verify_payload(payload, sig, rpk) and payload["type"] == "archive_audit_report"


async def test_audit_report_detects_tamper(tmp_path, auditor_keys):
    apk, backend = await _populate(tmp_path)
    raw = await backend.get("entry/000000000001.json")
    env = json.loads(signing.b64u_decode(raw.decode()))
    env["payload"]["title"] = "HACKED"
    await backend.put("entry/000000000001.json",
                      signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()).encode())
    out = await _auditor(apk, backend, auditor_keys).audit_report()
    assert out["report"]["chain_valid"] is False and out["report"]["broken_at"] == 1


async def test_inventory(tmp_path):
    apk, backend = await _populate(tmp_path)
    inv = await _auditor(apk, backend).inventory()
    assert len(inv) == 3
    assert inv[0]["content_type"] == "application/pdf" and inv[0]["stored"] is True
    assert inv[0]["enc_alg"] == "ML-KEM-1024+AES-256-GCM"


async def test_attestation_signed(tmp_path, auditor_keys):
    apk, backend = await _populate(tmp_path)
    rpk, _ = auditor_keys
    out = await _auditor(apk, backend, auditor_keys).attest(prev_attestation_hash="sha256:prev")
    att = out["attestation"]
    assert att["chain_valid"] is True and att["prev_attestation_hash"] == "sha256:prev" and out["attestation_hash"]
    payload, sig, _ = signing.open_envelope(out["attestation_envelope"])
    assert signing.verify_payload(payload, sig, rpk)


async def test_evidence_pack_subset_signed(tmp_path, auditor_keys):
    apk, backend = await _populate(tmp_path)
    rpk, _ = auditor_keys
    out = await _auditor(apk, backend, auditor_keys).evidence_pack(seqs=[0, 2])
    assert out["manifest"]["entry_count"] == 2 and len(out["entries"]) == 2
    assert out["manifest"]["entry_seqs"] == [0, 2]
    payload, sig, _ = signing.open_envelope(out["manifest_envelope"])
    assert signing.verify_payload(payload, sig, rpk)


# ---- retention -----------------------------------------------------------------------------

async def test_retention_over_within_and_per_type(tmp_path):
    apk, backend = await _populate(tmp_path)
    aud = _auditor(apk, backend)
    assert (await aud.retention_report(RetentionPolicy(default_days=0)))["over_retention"] == 3
    assert (await aud.retention_report(RetentionPolicy(default_days=36500)))["within_retention"] == 3
    mixed = await aud.retention_report(RetentionPolicy(default_days=36500, by_content_type={"application/xml": 0}))
    assert mixed["over_retention"] == 1 and mixed["within_retention"] == 2


# ---- exporters -----------------------------------------------------------------------------

def test_exporters():
    events = [{"event": "archive.audit", "result": "valid", "entries": 3, "ts": "2026-06-07T00:00:00Z"}]
    assert "archive.audit" in exporters.to_jsonl(events)
    assert exporters.to_cef(events).startswith("CEF:0|AlgoVoi|ArchiveAuditor|1.0|archive.audit")
    assert exporters.to_syslog(events).startswith("<134>1 2026-06-07T00:00:00Z")
    csv = exporters.to_csv([{"seq": 0, "title": "a"}, {"seq": 1, "title": "b"}])
    assert "seq,title" in csv and "0,a" in csv
    prom = exporters.to_prometheus(archive_kid="k", chain_valid=True, entries=3,
                                   broken_at=None, last_verified_epoch=1_700_000_000, bytes_stored=100)
    assert 'archive_chain_valid{archive_kid="k"} 1' in prom and "archive_entries_total" in prom


# ---- app -----------------------------------------------------------------------------------

def _client(tmp_path, auditor_keys, auth=None):
    apk, backend = asyncio.run(_populate(tmp_path))
    aud = _auditor(apk, backend, auditor_keys)
    return TestClient(create_app(aud, auth_dependency=auth))


def test_app_report_inventory_metrics(tmp_path, auditor_keys):
    client = _client(tmp_path, auditor_keys)
    assert client.get("/health").json()["status"] == "ok"
    rep = client.get("/v1/audit/report").json()
    assert rep["report"]["entries"] == 3 and rep["report"]["chain_valid"] is True
    assert len(client.get("/v1/audit/inventory").json()["entries"]) == 3
    assert "archive_entries_total" in client.get("/metrics").text
    assert "archive.audit" in client.get("/v1/audit/events.jsonl").text


def test_app_retention_and_verify_report(tmp_path, auditor_keys):
    client = _client(tmp_path, auditor_keys)
    assert client.post("/v1/audit/retention", json={"default_days": 0}).json()["over_retention"] == 3
    rep = client.get("/v1/audit/report").json()
    v = client.post("/v1/audit/verify-report", json={"envelope": rep["report_envelope"]}).json()
    assert v["verified"] is True and v["type"] == "archive_audit_report"


def test_app_attest_auth_required(tmp_path, auditor_keys):
    client = _client(tmp_path, auditor_keys, auth=bearer_token_auth("sec"))
    assert client.post("/v1/audit/attest", json={}).status_code == 401
    ok = client.post("/v1/audit/attest", headers={"Authorization": "Bearer sec"}, json={})
    assert ok.json()["attestation"]["chain_valid"] is True
