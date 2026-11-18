"""Tests for substrate2.caip and the additive CAIP gate on the receipt builders.

Two things are being protected here:

1. That the opt-in gate is genuinely additive. A settlement attestation built without
   ``settlement_chain_caip`` must serialise to the exact bytes it did before the parameter
   existed, or every already-anchored record stops recomputing. The expected digest is
   pinned as a literal so a regression cannot pass quietly.
2. That the anchor discipline survived the port from the Apache-2.0 module. ``"eip155:1\\n"``
   is the canary: it validates under ``^...$`` in Python and must not validate here.
"""
from __future__ import annotations

import hashlib

import pytest

from substrate2 import caip
from substrate2.canon import canonicalize_bytes
from substrate2.receipts._common import STRICT_ENV, ReceiptError, require_amount
from substrate2.receipts.settlement import (
    SettlementAttestationError,
    build_settlement_attestation,
)

AMOUNT = {"amount_minor": "1000000", "asset_id": "USDC"}
CAIP_AMOUNT = {"amount_minor": "1000000", "asset_id": "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"}
FLAGS = ["UK", "EU"]

# Captured from substrate2 at the commit BEFORE settlement_chain_caip was introduced.
_PRE_CHANGE_SHA256 = "0e2ae364499ad36ffe86d1ac0431bc58a3a14ee0c7f385a5d86be10a6139893c"


def _settlement(**over):
    kw = dict(
        settled_payment_ref="sha256:" + "a" * 64,
        settlement_result="SETTLED",
        settlement_timestamp_ms=1721030000000,
        settlement_provider_did="did:web:algovoi.co.uk",
        settlement_amount=AMOUNT,
        settlement_chain="algorand",
        jurisdiction_flags=FLAGS,
    )
    kw.update(over)
    return build_settlement_attestation(**kw)


def _sha(obj):
    return hashlib.sha256(canonicalize_bytes(obj)).hexdigest()


@pytest.fixture
def strict(monkeypatch):
    monkeypatch.setenv(STRICT_ENV, "1")


@pytest.fixture(autouse=True)
def _lax(monkeypatch):
    """Default every test to the shipped posture; `strict` overrides it."""
    monkeypatch.delenv(STRICT_ENV, raising=False)


# ── 1) the additive property ──────────────────────────────────────────────────────────

def test_omitting_caip_reproduces_pre_change_bytes():
    """The load-bearing one: no CAIP passed -> byte-identical to before the parameter existed."""
    assert _sha(_settlement()) == _PRE_CHANGE_SHA256


def test_omitting_caip_emits_no_new_key():
    assert "settlement_chain_caip" not in _settlement()


def test_supplying_caip_changes_the_digest():
    """Opting in is a different record, by design: the identifier is part of the preimage."""
    assert _sha(_settlement(settlement_chain_caip="eip155:1")) != _PRE_CHANGE_SHA256


def test_supplied_caip_is_emitted_verbatim():
    body = _settlement(settlement_chain_caip="eip155:1")
    assert body["settlement_chain_caip"] == "eip155:1"
    assert body["settlement_chain"] == "algorand"  # the legacy label is untouched


# ── 2) fail-closed before the digest ──────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "algorand",        # a bare label, not a CAIP-2
    "algorand_mainnet",
    "algo",
    "eip155",          # no reference
    "",
    "EIP155:1",        # namespace must be lowercase
    "eip155:1 ",       # trailing space
])
def test_non_caip_chain_is_refused(bad):
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_chain_caip=bad)


def test_trailing_newline_is_refused():
    r"""The \A...\Z anchor trap. Under ^...$ Python would accept this, and the record would
    then differ byte-for-byte from the clean identifier on the verifying side."""
    assert not caip.is_caip2("eip155:1\n")
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_chain_caip="eip155:1\n")


def test_rejection_happens_before_any_hashing():
    """A refused identifier must never reach a digest -- no partial record is returned."""
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_chain_caip="not a chain")


# ── 3) strict mode ────────────────────────────────────────────────────────────────────

def test_strict_mode_requires_the_caip_chain(strict):
    with pytest.raises(SettlementAttestationError):
        _settlement(settlement_amount=CAIP_AMOUNT)


def test_strict_mode_accepts_a_fully_caip_record(strict):
    body = _settlement(settlement_chain_caip="eip155:1", settlement_amount=CAIP_AMOUNT)
    assert body["settlement_chain_caip"] == "eip155:1"


def test_strict_mode_requires_caip19_asset(strict):
    with pytest.raises(ReceiptError):
        require_amount("settlement_amount", AMOUNT)  # bare "USDC" names no chain


def test_lax_mode_still_accepts_a_bare_ticker():
    assert require_amount("settlement_amount", AMOUNT)["asset_id"] == "USDC"


# ── 4) the three tiers came across intact ─────────────────────────────────────────────

def test_tier1_grammar_is_namespace_agnostic():
    """An unregistered namespace still passes the grammar tier -- that is the point: a
    chain that does not exist yet must not be rejected by the substrate."""
    assert caip.is_caip2("newchain:1")
    assert not caip.is_registered_caip2("newchain:1")
    # ...but the namespace length bound is still enforced (3-8 chars).
    assert not caip.is_caip2("notachain:1")


def test_tier2_registered_namespace():
    assert caip.is_registered_caip2("eip155:1")
    assert caip.require_registered_caip2("avax:43114") == "avax:43114"


def test_tier3_reference_format():
    assert caip.is_valid_caip2("eip155:1")
    assert not caip.is_valid_caip2("eip155:abc")  # eip155 references are decimal
    with pytest.raises(caip.CaipError):
        caip.require_valid_caip2("eip155:abc")


def test_constructors_round_trip():
    assert caip.caip10_of("eip155:1", "0xAb16") == "eip155:1:0xAb16"
    assert caip.caip19_slip44("eip155:1", 60) == "eip155:1/slip44:60"


def test_free_and_paid_engines_agree():
    """substrate2.caip is a relicensed mirror of algovoi_substrate.caip. If the two ever
    disagree, records built by the paid engine stop matching the free verifier."""
    free = pytest.importorskip("algovoi_substrate.caip")
    for probe in ("eip155:1", "eip155:1\n", "algorand", "EIP155:1", "eip155:abc",
                  "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "swift:iso4217"):
        assert caip.is_caip2(probe) == free.is_caip2(probe), probe
        assert caip.is_valid_caip2(probe) == free.is_valid_caip2(probe), probe


# ── zkp.PaymentReceipt: the same additive CAIP rule, in the commercial-only module ─────

def test_zkp_receipt_without_caip_is_byte_stable():
    """A ZK envelope built without the CAIP fields must serialise exactly as it did before
    they existed, or every envelope already issued stops verifying."""
    from substrate2 import zkp

    legacy = dict(payment_id="pay-1", chain="solana", amount_microusd=1000000,
                  recipient="7xKX", tx_id="0xdead", settled_at="2026-01-01T00:00:00Z")
    assert set(zkp.PaymentReceipt(**legacy).as_dict()) == set(legacy)
    assert _sha(zkp.PaymentReceipt(**legacy).as_dict()) == _sha(legacy)


def test_zkp_receipt_caip_is_gated_before_signing():
    from substrate2 import zkp

    legacy = dict(payment_id="pay-1", chain="solana", amount_microusd=1000000,
                  recipient="7xKX", tx_id="0xdead", settled_at="2026-01-01T00:00:00Z")
    for bad in ({"chain_caip2": "solana"},            # a bare label is not a CAIP-2
                {"chain_caip2": "eip155:1\n"},        # the anchor trap
                {"recipient_caip10": "not-an-account"}):
        with pytest.raises(ValueError):
            zkp.PaymentReceipt(**legacy, **bad).as_dict()


def test_zkp_receipt_accepts_conformant_caip():
    from substrate2 import zkp

    r = zkp.PaymentReceipt(
        payment_id="pay-1", chain="solana", amount_microusd=1000000, recipient="7xKX",
        tx_id="0xdead", settled_at="2026-01-01T00:00:00Z",
        chain_caip2="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        recipient_caip10="solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX")
    d = r.as_dict()
    assert d["chain_caip2"].startswith("solana:")
    assert d["chain"] == "solana"          # the legacy label is untouched


def test_zkp_strict_mode_requires_both(strict):
    from substrate2 import zkp

    with pytest.raises(ValueError):
        zkp.PaymentReceipt(payment_id="p", chain="solana", amount_microusd=1, recipient="r",
                           tx_id="t", settled_at="2026-01-01T00:00:00Z").as_dict()
