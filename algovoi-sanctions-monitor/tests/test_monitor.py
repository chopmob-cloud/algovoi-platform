"""Continuous sanctions monitor tests — baseline, transitions, no-PII delta receipts, offline verify."""
from __future__ import annotations

import json

import pytest

from algovoi_sanctions_monitor import (
    DenylistScreener,
    SanctionsMonitor,
    signing,
    subject_ref,
    verify_monitor_receipt,
)


@pytest.fixture()
def mon():
    pk, sk = signing.generate_keypair()
    scr = DenylistScreener()
    return pk, sk, scr, SanctionsMonitor(secret_key=sk, public_key=pk, screener=scr, monitor_did="did:web:acme")


async def test_baseline_first_sweep_no_delta(mon):
    _pk, _sk, _scr, m = mon
    m.watch(network="base", address="0xAAA")
    assert await m.sweep() == []                       # first sweep establishes baseline, no receipt


async def test_newly_hit_emits_signed_delta(mon):
    pk, _sk, scr, m = mon
    ref = m.watch(network="base", address="0xBAD")
    await m.sweep()                                    # baseline ALLOW
    scr.deny.add("0xBAD")                              # counterparty becomes sanctioned
    deltas = await m.sweep()
    assert len(deltas) == 1
    d = deltas[0]
    assert d["transition"] == "newly_hit" and d["subject_ref"] == ref
    assert d["receipt"]["prior_result"] == "ALLOW" and d["receipt"]["new_result"] == "DENY"
    r = verify_monitor_receipt(d["receipt_envelope"], pk)
    assert r.verified and r.transition == "newly_hit" and r.subject_ref == ref


async def test_receipt_carries_no_pii(mon):
    _pk, _sk, scr, m = mon
    m.watch(network="zzchain", address="0xSECRETWALLET")
    await m.sweep()
    scr.deny.add("0xSECRETWALLET")
    d = (await m.sweep())[0]
    blob = json.dumps(d["receipt"]) + d["receipt_envelope"]
    assert "0xSECRETWALLET" not in blob and "zzchain" not in blob, "PII leaked into the receipt"
    assert d["receipt"]["subject_ref"] == subject_ref("zzchain", "0xSECRETWALLET")
    assert d["receipt"]["subject_ref"].startswith("sha256:")


async def test_cleared_transition(mon):
    _pk, _sk, scr, m = mon
    scr.deny.add("0xX")
    m.watch(network="base", address="0xX")
    await m.sweep()                                    # baseline DENY
    scr.deny.discard("0xX")                            # delisted
    d = (await m.sweep())[0]
    assert d["transition"] == "cleared" and d["receipt"]["new_result"] == "ALLOW"


async def test_escalation_and_de_escalation(mon):
    _pk, _sk, scr, m = mon
    scr.refer.add("0xY")
    m.watch(network="base", address="0xY")
    await m.sweep()                                    # baseline REFER
    scr.refer.discard("0xY"); scr.deny.add("0xY")      # REFER -> DENY
    assert (await m.sweep())[0]["transition"] == "escalated"
    scr.deny.discard("0xY"); scr.refer.add("0xY")      # DENY -> REFER
    assert (await m.sweep())[0]["transition"] == "de-escalated"


async def test_no_change_no_delta(mon):
    _pk, _sk, _scr, m = mon
    m.watch(network="base", address="0xAAA")
    await m.sweep()
    assert await m.sweep() == []                       # steady state -> nothing


async def test_verify_rejects_wrong_key_and_kind(mon):
    pk, sk, scr, m = mon
    m.watch(network="base", address="0xZ")
    await m.sweep(); scr.deny.add("0xZ")
    d = (await m.sweep())[0]
    wrong, _ = signing.generate_keypair()
    assert verify_monitor_receipt(d["receipt_envelope"], wrong).verified is False      # wrong key
    bogus = signing.make_envelope({"kind": "not-a-monitor-receipt"}, sk, pk)
    assert verify_monitor_receipt(bogus, pk).verified is False                          # wrong kind


async def test_unwatch_and_watchlist_no_pii(mon):
    _pk, _sk, _scr, m = mon
    ref = m.watch(network="base", address="0xAAA")
    snap = m.watchlist()
    assert snap[0]["subject_ref"] == ref and "address" not in snap[0]
    assert m.unwatch(ref) is True and m.watchlist() == []


def test_free_for_any_suite_licence():
    from algovoi_sanctions_monitor import licensing
    assert licensing.INCLUDED_FREE_FOR_ANY_SUITE_LICENCE is True


def test_sweep_health_flags_dead_feed():
    """Security fix 2026-08-19: a screener that throws makes the sweep degraded/visible (dead feed)."""
    import asyncio
    from algovoi_sanctions_monitor import signing
    from algovoi_sanctions_monitor.monitor import SanctionsMonitor
    from algovoi_sanctions_monitor import licensing
    licensing.require_license = lambda *a, **k: {"tier": "test"}

    class _DeadScreener:
        provider_did = "did:web:dead"
        async def screen(self, *, network, address, context=None):
            raise RuntimeError("feed down")

    pk, sk = signing.generate_keypair()
    m = SanctionsMonitor(secret_key=sk, public_key=pk, screener=_DeadScreener())
    m.watch(network="base", address="0xabc")
    asyncio.run(m.sweep())
    h = m.sweep_health()
    assert h["degraded"] is True and h["failed"] == 1 and h["screened"] == 0
