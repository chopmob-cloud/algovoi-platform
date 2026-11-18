"""Tests for substrate2.timestamp — RFC 3161 trusted timestamps over the retention chain.

Runs entirely offline against a REAL token recorded from freetsa.org
(tests/fixtures/tsa_freetsa_response.der, with its metadata alongside). Using a real token
rather than a synthetic one matters: a hand-built fixture would only prove the parser agrees
with itself, whereas this proves it agrees with a TSA that has no idea we exist.

The live round-trip is opt-in via SUBSTRATE2_TSA_LIVE=1 so the suite stays deterministic and
network-free by default.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib

import pytest

from substrate2 import timestamp as ts
from substrate2.retention_chain import retention_chain_ref

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
TOKEN_DER = FIXTURES / "tsa_freetsa_response.der"
TOKEN_META = FIXTURES / "tsa_freetsa_response.json"

ISSUER = "did:web:algovoi.co.uk"


@pytest.fixture(scope="module")
def meta() -> dict:
    return json.loads(TOKEN_META.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def der() -> bytes:
    return TOKEN_DER.read_bytes()


@pytest.fixture(scope="module")
def chain_ref(meta) -> str:
    """Recompute the chain head the fixture covers, rather than reading it from the metadata.

    If retention_chain_ref ever changed, this would stop matching the token and the suite
    would fail loudly -- which is the correct outcome, because every timestamp already issued
    would then cover a digest the code no longer produces.
    """
    ref = retention_chain_ref(prev_receipt_hash="sha256:" + "a" * 64,
                              receipt_hash="sha256:" + "b" * 64,
                              chain_seq=meta["chain_seq"], issuer_id=meta["issuer_id"])
    assert ref == meta["covers_chain_ref"], "retention_chain_ref no longer reproduces the stamped head"
    return ref


# ── request construction ──────────────────────────────────────────────────────────────

def test_request_accepts_a_chain_ref_directly():
    """A retention_chain_ref goes in unmodified: no reformatting step means no opportunity
    to stamp a differently-encoded value than the one that was anchored."""
    ref = retention_chain_ref(prev_receipt_hash="", receipt_hash="sha256:" + "b" * 64,
                              chain_seq=0, issuer_id=ISSUER)
    req, nonce = ts.timestamp_request(ref)
    assert isinstance(req, bytes) and len(req) > 0
    assert isinstance(nonce, int)


def test_request_rejects_a_mis_sized_digest():
    with pytest.raises(ts.TimestampError):
        ts.timestamp_request("sha256:abcd")           # too short for sha256
    with pytest.raises(ts.TimestampError):
        ts.timestamp_request("sha256:" + "z" * 64)    # not hex


def test_request_nonce_is_returned_for_checking():
    """RFC 3161 makes the nonce the client's replay defence; one that is never returned to
    the caller could never be checked."""
    _, n1 = ts.timestamp_request("sha256:" + "a" * 64)
    _, n2 = ts.timestamp_request("sha256:" + "a" * 64)
    assert n1 != n2


# ── parsing a real token ──────────────────────────────────────────────────────────────

def test_parses_a_real_tsa_response(der, meta):
    t = ts.parse_timestamp_response(der)
    assert t.serial == meta["serial"]
    assert t.policy_oid == meta["policy_oid"]
    assert t.gen_time_ms == meta["gen_time_ms"]
    assert t.signature_alg == meta["signature_alg"]
    assert t.tsa_name == meta["tsa_name"]


def test_gen_time_is_integer_ms_not_a_string(der):
    """Substrate Rule 2: times are integer milliseconds. An RFC 3339 string here would
    produce a different preimage and therefore a different ref."""
    t = ts.parse_timestamp_response(der)
    assert isinstance(t.gen_time_ms, int)
    assert not isinstance(t.gen_time_ms, bool)
    assert t.gen_time_ms > 1_600_000_000_000


# ── verification, and the checks that carry the weight ────────────────────────────────

def test_token_verifies_against_the_head_it_covers(der, chain_ref):
    res = ts.verify_timestamp_token(der, expected_digest=chain_ref)
    assert res.valid, res.failure_reason


def test_parsed_is_not_reported_as_verified(der, chain_ref):
    """Without trust anchors the TSA signature is NOT checked. The result must say so, or a
    caller could read 'the token says this' as 'the TSA vouched for this'."""
    res = ts.verify_timestamp_token(der, expected_digest=chain_ref)
    assert res.valid is True
    assert res.signature_verified is False


def test_token_does_not_verify_against_a_different_head(der):
    """THE negative control. A token is evidence only about the digest it covers; if it
    verified against any digest it would be worthless."""
    other = retention_chain_ref(prev_receipt_hash="sha256:" + "c" * 64,
                                receipt_hash="sha256:" + "d" * 64, chain_seq=8, issuer_id=ISSUER)
    res = ts.verify_timestamp_token(der, expected_digest=other)
    assert not res.valid
    assert "messageImprint" in res.failure_reason


def test_nonce_mismatch_is_refused(der, chain_ref, meta):
    res = ts.verify_timestamp_token(der, expected_digest=chain_ref, nonce=meta["request_nonce"] + 1)
    assert not res.valid
    assert "nonce" in res.failure_reason


def test_corrupted_token_is_refused(der, chain_ref):
    for mangled in (der[:200], der[:-1], b"\x00" * 64, der[:100] + b"\xff" * 20 + der[120:]):
        res = ts.verify_timestamp_token(mangled, expected_digest=chain_ref)
        assert not res.valid


# ── the sidecar record ────────────────────────────────────────────────────────────────

def test_sidecar_ref_recomputes(der, chain_ref, meta):
    t = ts.parse_timestamp_response(der)
    rec = ts.build_chain_timestamp(chain_ref=chain_ref, chain_seq=meta["chain_seq"],
                                   issuer_id=ISSUER, token=t)
    assert rec["chain_timestamp_ref"] == ts.chain_timestamp_ref(rec["preimage"])
    assert ts.verify_chain_timestamp(rec, chain_ref=chain_ref).valid


def test_sidecar_preimage_excludes_the_raw_token(der, chain_ref, meta):
    """The token travels as base64 alongside the record, never inside the preimage: the
    preimage stays small and canonical, and the token's identifying fields are what bind."""
    t = ts.parse_timestamp_response(der)
    rec = ts.build_chain_timestamp(chain_ref=chain_ref, chain_seq=meta["chain_seq"],
                                   issuer_id=ISSUER, token=t)
    assert "token_b64" not in rec["preimage"]
    assert base64.b64decode(rec["token_b64"]) == t.raw


def test_sidecar_refuses_a_different_head(der, chain_ref, meta):
    t = ts.parse_timestamp_response(der)
    rec = ts.build_chain_timestamp(chain_ref=chain_ref, chain_seq=meta["chain_seq"],
                                   issuer_id=ISSUER, token=t)
    other = retention_chain_ref(prev_receipt_hash="sha256:" + "c" * 64,
                                receipt_hash="sha256:" + "d" * 64, chain_seq=8, issuer_id=ISSUER)
    assert not ts.verify_chain_timestamp(rec, chain_ref=other).valid


def test_sidecar_detects_a_tampered_preimage(der, chain_ref, meta):
    t = ts.parse_timestamp_response(der)
    rec = ts.build_chain_timestamp(chain_ref=chain_ref, chain_seq=meta["chain_seq"],
                                   issuer_id=ISSUER, token=t)
    rec["preimage"] = dict(rec["preimage"], gen_time_ms=rec["preimage"]["gen_time_ms"] - 86_400_000)
    res = ts.verify_chain_timestamp(rec, chain_ref=chain_ref)
    assert not res.valid and "recompute" in res.failure_reason


def test_sidecar_rejects_bad_inputs(der, chain_ref):
    t = ts.parse_timestamp_response(der)
    for kw in ({"chain_seq": -1}, {"issuer_id": ""}, {"chain_ref": "not-a-ref"}):
        with pytest.raises(ts.TimestampError):
            ts.chain_timestamp_preimage(**{**{"chain_ref": chain_ref, "chain_seq": 7,
                                              "issuer_id": ISSUER, "token": t}, **kw})


# ── the retention chain itself must be untouched ──────────────────────────────────────

def test_timestamping_does_not_alter_the_chain(chain_ref, der, meta):
    """The whole design rests on the chain preimage being untouched, so every chain_ref
    already anchored keeps recomputing. Assert it directly."""
    before = retention_chain_ref(prev_receipt_hash="sha256:" + "a" * 64,
                                 receipt_hash="sha256:" + "b" * 64, chain_seq=7, issuer_id=ISSUER)
    t = ts.parse_timestamp_response(der)
    ts.build_chain_timestamp(chain_ref=chain_ref, chain_seq=7, issuer_id=ISSUER, token=t)
    after = retention_chain_ref(prev_receipt_hash="sha256:" + "a" * 64,
                                receipt_hash="sha256:" + "b" * 64, chain_seq=7, issuer_id=ISSUER)
    assert before == after == meta["covers_chain_ref"]


# ── live TSA, opt-in ──────────────────────────────────────────────────────────────────

@pytest.mark.skipif(os.environ.get("SUBSTRATE2_TSA_LIVE") != "1",
                    reason="set SUBSTRATE2_TSA_LIVE=1 to exercise a real TSA round-trip")
def test_live_round_trip():
    ref = retention_chain_ref(prev_receipt_hash="sha256:" + "e" * 64,
                              receipt_hash="sha256:" + "f" * 64, chain_seq=1, issuer_id=ISSUER)
    req, nonce = ts.timestamp_request(ref)
    resp = ts.fetch_timestamp("https://freetsa.org/tsr", req, timeout=25)
    res = ts.verify_timestamp_token(resp, expected_digest=ref, nonce=nonce)
    assert res.valid, res.failure_reason
    rec = ts.build_chain_timestamp(chain_ref=ref, chain_seq=1, issuer_id=ISSUER, token=res.token)
    assert ts.verify_chain_timestamp(rec, chain_ref=ref).valid
