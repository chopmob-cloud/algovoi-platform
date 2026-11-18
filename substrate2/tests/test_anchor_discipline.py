r"""Every reference validator in substrate2 must anchor with \A/\Z, never ^/$.

Python's `$` also matches just before a trailing newline. A validator written `^...$`
therefore ACCEPTS "sha256:<64 hex>\n", and that value goes on to be folded into a
canonicalised, content-addressed record. The counterparty recomputes over the clean
reference, gets a different digest, and the record stops recomputing. Nothing looks wrong
at either end; the receipt is simply unverifiable.

This was not a one-off. A sweep on 2026-07-21 found five instances in substrate2
(settlement_binding, execution, keystone_secure, transactional, zkp), each of which was
confirmed to produce a divergent digest, not merely to accept a bad string.

Two layers of protection:

  1. A static sweep over the whole package, so a NEW module written with `^...$` fails here
     even if nobody thinks to add a behavioural test for it.
  2. Behavioural checks that the known entry points actually reject the dirty reference,
     because a regex can be right while the call site never consults it.
"""
from __future__ import annotations

import pathlib
import re

import pytest

import substrate2

PKG = pathlib.Path(substrate2.__file__).parent

# Matches a compiled regex literal that opens with ^ or closes with $.
_CARET_DOLLAR = re.compile(r"re\.compile\(\s*r?[\"'](\^[^\"']*|[^\"']*\$)[\"']")

DIRTY_REF = "sha256:" + "b" * 64 + "\n"
DIRTY_HEX = "a" * 64 + "\n"
CLEAN_REF = "sha256:" + "b" * 64
CLEAN_HEX = "a" * 64
T = 1721030000000


def _sources():
    return [p for p in PKG.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_caret_dollar_anchors_anywhere():
    """Static sweep: no reference validator may be anchored with ^ or $."""
    offenders = []
    for path in _sources():
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _CARET_DOLLAR.search(line):
                offenders.append(f"{path.relative_to(PKG)}:{i}: {line.strip()}")
    assert not offenders, (
        "use \\A and \\Z, not ^ and $ -- `$` also matches before a trailing newline:\n  "
        + "\n  ".join(offenders)
    )


def test_sweep_is_not_vacuous():
    """Guard the guard: the sweep must actually be looking at the package."""
    assert len(_sources()) > 20
    assert (PKG / "settlement_binding.py") in _sources()


# ── behavioural: the dirty reference must be refused at each entry point ──────────────

def test_settlement_binding_rejects_dirty_ref():
    from substrate2 import settlement_binding as sb

    with pytest.raises(sb.SettlementBindingError):
        sb.settlement_action_binding(DIRTY_HEX, CLEAN_HEX, CLEAN_HEX, CLEAN_REF)
    with pytest.raises(sb.SettlementBindingError):
        sb.settlement_action_binding(CLEAN_HEX, CLEAN_HEX, CLEAN_HEX, DIRTY_REF)


def test_transactional_rejects_dirty_action_ref():
    from substrate2 import transactional as tx

    with pytest.raises(Exception):
        tx.transition_hash(DIRTY_HEX, "COMMITTED", T, T, T)


def test_execution_rejects_dirty_ref():
    from substrate2 import execution

    with pytest.raises(Exception):
        execution.screen_binding_ref(DIRTY_REF, CLEAN_REF)


def test_keystone_secure_rejects_dirty_ref():
    from substrate2 import keystone_secure as ks

    with pytest.raises(Exception):
        ks.decision_audit_ref(
            DIRTY_REF,
            passport_credential_ref=CLEAN_REF,
            mandate_ref=CLEAN_REF,
            policy_bound_ref=CLEAN_REF,
        )


def test_clean_references_still_work():
    """The fix is a validation tightening, not a construction change: anything already
    well-formed must behave exactly as before."""
    from substrate2 import execution, settlement_binding as sb, transactional as tx

    assert sb.settlement_action_binding(CLEAN_HEX, CLEAN_HEX, CLEAN_HEX, CLEAN_REF).startswith("sha256:")
    assert execution.screen_binding_ref(CLEAN_REF, CLEAN_REF).startswith("sha256:")
    assert len(tx.transition_hash(CLEAN_HEX, "COMMITTED", T, T, T)) == 64


# ── GA criterion 5: no unfinished surfaces ────────────────────────────────────────────

def test_no_notimplemented_in_public_surface():
    """Every name the package exports must actually do something.

    `substrate2.verify_request` shipped through 2.0.0a6 raising
    NotImplementedError("Phase 3 (verifier half)") while the verifier it should have been
    calling was already complete in rfc9421_verifier. A stub advertising unfinished work
    that is finished is worse than a missing name: it tells a reader the package is less
    capable than it is.
    """
    import inspect

    import substrate2

    stubs = []
    for name in substrate2.__all__:
        obj = getattr(substrate2, name, None)
        if not callable(obj) or inspect.isclass(obj):
            continue
        try:
            src = inspect.getsource(obj)
        except (OSError, TypeError):
            continue
        if "raise NotImplementedError" in src:
            stubs.append(name)
    assert not stubs, f"exported names that raise NotImplementedError: {stubs}"


def test_rfc9421_sign_verify_round_trips_at_package_level():
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import substrate2

    seed = bytes(range(32))
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk_raw = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    body = b'{"amount":"1.00"}'
    common = dict(method="POST", authority="api.algovoi.co.uk", path="/v1/pay")

    res = substrate2.sign_request(
        headers={"content-type": "application/json"}, body=body,
        private_key=seed, keyid="k1", **common)
    hdrs = {"content-type": "application/json", "signature-input": res.signature_input,
            "signature": res.signature, "content-digest": res.content_digest}

    assert substrate2.verify_request(headers=hdrs, body=body, public_key=pk_raw, **common).valid
    # a changed body must not verify against the same signature
    assert not substrate2.verify_request(
        headers=hdrs, body=b'{"amount":"9.00"}', public_key=pk_raw, **common).valid
