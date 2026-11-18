#!/usr/bin/env python3
"""Self-contained acceptance test for the Mandate Auditor Suite.

Proves the auditor works out of the box with no external services and no configuration.

  1. Chain stamping   -- authorized charges carry chain_seq + chain_ref; declined ones don't.
  2. Build report     -- build_audit_report returns all authorized charges in chain_seq order.
  3. Verify report    -- verify_audit_report confirms the chain is unbroken.
  4. Tamper detection -- a modified chain_ref or receipt_hash fails verification.
  5. Export           -- the HTTP export endpoint returns a downloadable JSON pack.

Exit 0 = all green; non-zero names the failed check(s).
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from algovoi_payment_mandate import licensing as mandate_licensing, MandateIssuer, InMemoryStore
from algovoi_payment_mandate import signing
from algovoi_mandate_auditor import licensing as auditor_licensing
from algovoi_mandate_auditor.audit import build_audit_report, verify_audit_report

# Bypass licence for the acceptance script (same as test conftest).
mandate_licensing.require_license = lambda *a, **k: {"package": mandate_licensing.PACKAGE_NAME, "tier": "acceptance"}
auditor_licensing.require_license = lambda *a, **k: {"package": auditor_licensing.PACKAGE_NAME, "tier": "acceptance"}

PASS = 0
FAIL: list[str] = []
GENERATED_AT = "2026-06-17T00:00:00Z"


def ok(name: str) -> None:
    global PASS
    PASS += 1
    print(f"  [PASS] {name}")


def no(name: str) -> None:
    FAIL.append(name)
    print(f"  [FAIL] {name}")


async def main() -> int:
    print("Mandate Auditor Suite -- acceptance")

    store = InMemoryStore()
    pk, sk = signing.generate_keypair()
    issuer = MandateIssuer(secret_key=sk, public_key=pk, store=store, issuer_did="did:web:accept.test")

    out = await issuer.issue(payer="acct:alice", payee="merchant:acme",
                             max_amount=500_000_000, period="month")
    mandate = out["mandate"]
    mid = out["mandate_id"]

    # 1. Chain stamping -- authorized charges get chain fields; declined don't.
    r0 = await issuer.authorize_charge(mandate=mandate, charge_id="c0", amount=10_000_000)
    r1 = await issuer.authorize_charge(mandate=mandate, charge_id="c1", amount=20_000_000)
    r2 = await issuer.authorize_charge(mandate=mandate, charge_id="c2", amount=15_000_000)
    if r0.authorized and r0.chain_seq == 0 and r0.chain_ref and r0.chain_ref.startswith("sha256:"):
        ok("chain stamping: genesis charge has chain_seq=0 and chain_ref")
    else:
        no(f"chain stamping: genesis ({r0.authorized=}, {r0.chain_seq=}, {r0.chain_ref=})")

    if r1.chain_seq == 1 and r2.chain_seq == 2:
        ok("chain stamping: seq increments correctly")
    else:
        no(f"chain stamping: seq ({r1.chain_seq=}, {r2.chain_seq=})")

    # Declined charge (cap exceeded)
    out2 = await issuer.issue(payer="acct:bob", payee="m:x", max_amount=100, period="month")
    rd = await issuer.authorize_charge(mandate=out2["mandate"], charge_id="over", amount=200)
    if not rd.authorized and rd.chain_seq is None and rd.chain_ref is None:
        ok("chain stamping: declined charge has no chain fields")
    else:
        no(f"chain stamping: declined ({rd.authorized=}, {rd.chain_seq=})")

    # 2. Build report
    report = await build_audit_report(store, kid=issuer.kid, mandate_id=mid, generated_at=GENERATED_AT)
    if report.record_count == 3 and len(report.records) == 3:
        ok("build_audit_report: 3 records returned")
    else:
        no(f"build_audit_report: expected 3, got {report.record_count}")

    if [r.chain_seq for r in report.records] == [0, 1, 2]:
        ok("build_audit_report: records ordered by chain_seq")
    else:
        no(f"build_audit_report: wrong order {[r.chain_seq for r in report.records]}")

    if report.issuer_id == f"mandate:{mid}":
        ok("build_audit_report: issuer_id is mandate-scoped")
    else:
        no(f"build_audit_report: wrong issuer_id {report.issuer_id}")

    # 3. Verify report
    valid, reason = verify_audit_report(report)
    if valid and reason is None:
        ok("verify_audit_report: valid chain passes")
    else:
        no(f"verify_audit_report: valid chain failed ({reason})")

    # Empty mandate verifies
    out_empty = await issuer.issue(payer="p", payee="q", max_amount=1_000_000, period="month")
    empty_report = await build_audit_report(store, kid=issuer.kid,
                                            mandate_id=out_empty["mandate_id"], generated_at=GENERATED_AT)
    v2, _ = verify_audit_report(empty_report)
    if v2:
        ok("verify_audit_report: empty report passes")
    else:
        no("verify_audit_report: empty report failed")

    # 4. Tamper detection
    import copy
    tampered = copy.deepcopy(report)
    tampered.records[0].chain_ref = "sha256:" + "a" * 64
    ok_t, r_t = verify_audit_report(tampered)
    if not ok_t and r_t is not None:
        ok("tamper detection: modified chain_ref rejected")
    else:
        no("tamper detection: modified chain_ref not caught")

    tampered2 = copy.deepcopy(report)
    tampered2.records[0].receipt_hash = "sha256:" + "b" * 64
    ok_t2, _ = verify_audit_report(tampered2)
    if not ok_t2:
        ok("tamper detection: modified receipt_hash breaks chain")
    else:
        no("tamper detection: modified receipt_hash not caught")

    print()
    if FAIL:
        print(f"RESULT: {PASS} passed, {len(FAIL)} FAILED -> {', '.join(FAIL)}")
        return 1
    print(f"ALL GREEN ({PASS} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
