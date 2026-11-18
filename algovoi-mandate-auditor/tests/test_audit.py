"""Tests for the Mandate Auditor Suite."""
from __future__ import annotations

import hashlib
import pytest
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport

from algovoi_payment_mandate import MandateIssuer, InMemoryStore
from algovoi_payment_mandate import signing
from algovoi_mandate_auditor.audit import build_audit_report, verify_audit_report
from algovoi_mandate_auditor.service import create_auditor_app

GENERATED_AT = "2026-06-17T00:00:00Z"


@pytest.fixture
def store():
    return InMemoryStore()


@pytest.fixture
def keypair():
    pk, sk = signing.generate_keypair()
    return pk, sk


@pytest.fixture
def issuer(store, keypair):
    pk, sk = keypair
    return MandateIssuer(secret_key=sk, public_key=pk, store=store, issuer_did="did:web:test.example")


async def _issue_and_charge(issuer, n_charges: int = 3, amount: int = 10_000_000):
    out = await issuer.issue(payer="acct:alice", payee="merchant:acme",
                             max_amount=500_000_000, period="month")
    mandate = out["mandate"]
    results = []
    for i in range(n_charges):
        r = await issuer.authorize_charge(mandate=mandate, charge_id=f"c{i}", amount=amount)
        assert r.authorized
        results.append(r)
    return out["mandate_id"], mandate, results


# --- chain stamping on the issuer ---

class TestChainStamping:
    async def test_first_charge_is_genesis(self, issuer):
        mid, _, results = await _issue_and_charge(issuer, n_charges=1)
        r = results[0]
        assert r.chain_seq == 0
        assert r.chain_ref is not None
        assert r.chain_ref.startswith("sha256:")
        assert len(r.chain_ref) == 71

    async def test_chain_seq_increments(self, issuer):
        mid, _, results = await _issue_and_charge(issuer, n_charges=3)
        assert [r.chain_seq for r in results] == [0, 1, 2]

    async def test_chain_refs_are_distinct(self, issuer):
        mid, _, results = await _issue_and_charge(issuer, n_charges=3)
        refs = [r.chain_ref for r in results]
        assert len(set(refs)) == 3

    async def test_declined_charge_not_chained(self, issuer):
        out = await issuer.issue(payer="acct:bob", payee="merchant:acme",
                                 max_amount=100, period="month")
        mandate = out["mandate"]
        # First charge authorized
        r1 = await issuer.authorize_charge(mandate=mandate, charge_id="ok", amount=50)
        assert r1.authorized
        assert r1.chain_seq == 0
        # Second charge declines (cap exceeded)
        r2 = await issuer.authorize_charge(mandate=mandate, charge_id="bad", amount=100)
        assert not r2.authorized
        assert r2.chain_seq is None
        assert r2.chain_ref is None
        # Third authorized charge picks up at seq=1, not seq=2
        r3 = await issuer.authorize_charge(mandate=mandate, charge_id="ok2", amount=40)
        assert r3.authorized
        assert r3.chain_seq == 1

    async def test_idempotent_charge_not_double_chained(self, issuer):
        mid, mandate, results = await _issue_and_charge(issuer, n_charges=2)
        # Re-present first charge
        r_again = await issuer.authorize_charge(mandate=mandate, charge_id="c0", amount=10_000_000)
        assert r_again.idempotent
        # List chain records — still only 2 (no duplicate)
        records = await issuer.store.list_chain_records(kid=issuer.kid, mandate_id=mid)
        assert len(records) == 2


# --- build_audit_report ---

class TestBuildAuditReport:
    async def test_empty_mandate_gives_empty_report(self, issuer):
        out = await issuer.issue(payer="acct:nobody", payee="m:x", max_amount=1_000_000, period="month")
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=out["mandate_id"], generated_at=GENERATED_AT)
        assert report.record_count == 0
        assert report.records == []

    async def test_report_has_correct_fields(self, issuer):
        mid, _, _ = await _issue_and_charge(issuer, n_charges=3)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        assert report.mandate_id == mid
        assert report.kid == issuer.kid
        assert report.issuer_id == f"mandate:{mid}"
        assert report.record_count == 3
        assert len(report.records) == 3

    async def test_report_records_ordered_by_chain_seq(self, issuer):
        mid, _, _ = await _issue_and_charge(issuer, n_charges=4)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        seqs = [r.chain_seq for r in report.records]
        assert seqs == sorted(seqs)
        assert seqs[0] == 0

    async def test_report_records_have_all_fields(self, issuer):
        mid, _, _ = await _issue_and_charge(issuer, n_charges=1)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        rec = report.records[0]
        assert rec.chain_seq == 0
        assert rec.chain_ref.startswith("sha256:")
        assert rec.receipt_hash.startswith("sha256:")
        assert rec.charge_id == "c0"
        assert rec.amount == 10_000_000
        assert rec.period_key != ""
        assert rec.ts != ""


# --- verify_audit_report ---

class TestVerifyAuditReport:
    async def test_valid_chain_verifies(self, issuer):
        mid, _, _ = await _issue_and_charge(issuer, n_charges=3)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        ok, reason = verify_audit_report(report)
        assert ok is True
        assert reason is None

    async def test_empty_report_verifies(self, issuer):
        out = await issuer.issue(payer="p", payee="q", max_amount=1_000_000, period="month")
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=out["mandate_id"], generated_at=GENERATED_AT)
        ok, reason = verify_audit_report(report)
        assert ok is True

    async def test_tampered_chain_ref_fails(self, issuer):
        mid, _, _ = await _issue_and_charge(issuer, n_charges=2)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        # Tamper the first record's chain_ref
        report.records[0].chain_ref = "sha256:" + "a" * 64
        ok, reason = verify_audit_report(report)
        assert ok is False
        assert "0" in reason

    async def test_tampered_receipt_hash_fails(self, issuer):
        mid, _, _ = await _issue_and_charge(issuer, n_charges=2)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        # Tamper a receipt_hash — breaks the next link's prev_receipt_hash
        report.records[0].receipt_hash = "sha256:" + "b" * 64
        ok, reason = verify_audit_report(report)
        assert ok is False

    async def test_tampered_amount_fails(self, issuer):
        """Security fix 2026-08-19: the verifier now binds the DISPLAYED fields to the receipt_hash, so
        editing the amount in the report (while leaving the original receipt_hash) is caught, instead of
        showing a green check. Previously this asserted ``ok is True`` — that encoded the vulnerability."""
        mid, _, _ = await _issue_and_charge(issuer, n_charges=2)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        report.records[0].amount = 999  # tamper only the displayed amount; receipt_hash unchanged
        ok, reason = verify_audit_report(report)
        assert ok is False and reason is not None and "receipt_hash_mismatch" in reason

    async def test_tampered_asset_fails(self, issuer):
        """A displayed-asset edit is likewise bound to the receipt_hash and rejected."""
        mid, _, _ = await _issue_and_charge(issuer, n_charges=2)
        report = await build_audit_report(issuer.store, kid=issuer.kid,
                                          mandate_id=mid, generated_at=GENERATED_AT)
        report.records[0].asset = "ATTACKERCOIN"
        ok, reason = verify_audit_report(report)
        assert ok is False and reason is not None and "receipt_hash_mismatch" in reason


# --- HTTP service ---

class TestAuditorService:
    @pytest.fixture
    async def client(self, issuer):
        app = create_auditor_app(issuer.store, kid=issuer.kid)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            yield c, issuer

    async def test_health(self, client):
        c, _ = client
        r = await c.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    async def test_audit_report_valid_chain(self, client):
        c, iss = client
        mid, _, _ = await _issue_and_charge(iss, n_charges=3)
        r = await c.get(f"/v1/audit/{iss.kid}/{mid}")
        assert r.status_code == 200
        body = r.json()
        assert body["record_count"] == 3
        assert body["mandate_id"] == mid
        assert r.headers["x-chain-verified"] == "true"

    async def test_audit_report_empty_mandate(self, client):
        c, iss = client
        out = await iss.issue(payer="p", payee="q", max_amount=1_000_000, period="month")
        r = await c.get(f"/v1/audit/{iss.kid}/{out['mandate_id']}")
        assert r.status_code == 200
        assert r.json()["record_count"] == 0
        assert r.headers["x-chain-verified"] == "true"

    async def test_audit_export_is_attachment(self, client):
        c, iss = client
        mid, _, _ = await _issue_and_charge(iss, n_charges=2)
        r = await c.get(f"/v1/audit/{iss.kid}/{mid}/export")
        assert r.status_code == 200
        assert "attachment" in r.headers.get("content-disposition", "")
        body = r.json()
        assert body["_chain_valid"] is True
        assert body["record_count"] == 2

    async def test_kid_filter_rejects_wrong_kid(self, store, keypair):
        pk, sk = keypair
        iss2 = MandateIssuer(secret_key=sk, public_key=pk, store=store, issuer_did="did:web:x")
        app = create_auditor_app(store, kid="notthiskid")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            out = await iss2.issue(payer="p", payee="q", max_amount=1_000_000, period="month")
            r = await c.get(f"/v1/audit/{iss2.kid}/{out['mandate_id']}")
            assert r.status_code == 403
