"""Tests for the additive ``settlement_round`` field on the settlement builder.

Same discipline as ``settlement_chain_caip`` (see test_caip.py): the field is
opt-in and additive. A settlement attestation built without it must serialise
to the exact bytes it did before the parameter existed — every already-anchored
record must keep recomputing — and a positive round must be emitted verbatim as
its own key while everything else is untouched.
"""
from __future__ import annotations

import hashlib

import pytest

from substrate2.canon import canonicalize_bytes
from substrate2.receipts.settlement import (
    SettlementAttestationError,
    build_settlement_attestation,
)

# Same pinned digest as test_caip.py: the pre-change serialisation.
_PRE_CHANGE_SHA256 = "0e2ae364499ad36ffe86d1ac0431bc58a3a14ee0c7f385a5d86be10a6139893c"


def _settlement(**over):
    kw = dict(
        settled_payment_ref="sha256:" + "a" * 64,
        settlement_result="SETTLED",
        settlement_timestamp_ms=1721030000000,
        settlement_provider_did="did:web:algovoi.co.uk",
        settlement_amount={"amount_minor": "1000000", "asset_id": "USDC"},
        settlement_chain="algorand",
        jurisdiction_flags=["UK", "EU"],
    )
    kw.update(over)
    return build_settlement_attestation(**kw)


def _sha(obj):
    return hashlib.sha256(canonicalize_bytes(obj)).hexdigest()


# ── additive property ─────────────────────────────────────────────────────────

def test_omitting_round_reproduces_pre_change_bytes():
    """No round passed -> byte-identical to before the parameter existed."""
    assert _sha(_settlement()) == _PRE_CHANGE_SHA256


def test_omitting_round_emits_no_new_key():
    assert "settlement_round" not in _settlement()


def test_supplying_round_changes_the_digest():
    assert _sha(_settlement(settlement_round=12345)) != _PRE_CHANGE_SHA256


def test_supplied_round_is_emitted_verbatim():
    body = _settlement(settlement_round=12345)
    assert body["settlement_round"] == 12345
    assert body["settlement_chain"] == "algorand"  # legacy label untouched


def test_round_and_caip_are_independent():
    """Both additive fields can coexist; each is emitted as its own key."""
    body = _settlement(settlement_round=99, settlement_chain_caip="eip155:1")
    assert body["settlement_round"] == 99
    assert body["settlement_chain_caip"] == "eip155:1"


# ── fail-closed before the digest ─────────────────────────────────────────────

@pytest.mark.parametrize("bad", [0, -1, -1000])
def test_non_positive_round_is_refused(bad):
    """Round 0 is the genesis allocation and can carry no settlement; negatives
    are nonsense. Both must be rejected before any record is returned."""
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_round=bad)


def test_bool_round_is_refused():
    """bool is an int subclass — must be rejected (Substrate Rule 2)."""
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_round=True)


@pytest.mark.parametrize("bad", ["12345", 12345.0, None.__class__])
def test_non_int_round_is_refused(bad):
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_round=bad)


def test_none_round_is_the_omitted_case():
    """Explicit None is treated as 'not supplied' — byte-stable, no key."""
    body = _settlement(settlement_round=None)
    assert "settlement_round" not in body
    assert _sha(body) == _PRE_CHANGE_SHA256
