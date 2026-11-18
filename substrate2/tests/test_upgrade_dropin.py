"""The drop-in claim: code written against the free package runs unchanged on substrate2.

This is the central promise of the L1 -> substrate2 upgrade ramp, and the first objection a
buyer raises: *will the records I have already anchored still verify?* If a single byte
differs, every historical record they hold becomes unverifiable under the engine they just
paid for -- not a regression, a total loss of their evidence base.

So it is tested rather than asserted. `_customer_workload` imports ONLY `algovoi_substrate`
names -- no substrate2 anywhere -- and is executed twice in-process: once against the real
open package, once with the v1 compat shim installed. Every value must match.

Complements `conformance/byte_parity.py` section G, which proves the two canonicalisers agree
on 166 vector inputs. This proves the *call sites* agree too, which is what a customer
actually experiences.
"""
from __future__ import annotations

import json

import pytest

from substrate2.compat import v1_shim

T = 1721030000000
DID = "did:web:customer.example"


def _customer_workload() -> dict:
    """Ordinary customer code. Only free-package names appear here, deliberately."""
    import algovoi_substrate as sub
    from algovoi_substrate import audit_chain, compliance_receipt, transactional

    aref = sub.action_ref("agent-7", "transfer", "eu-west", T)
    receipt = compliance_receipt.build_compliance_receipt(
        payer_ref="sha256:" + "a" * 64, screen_result="ALLOW",
        screen_timestamp_ms=T, screen_provider_did=DID, jurisdiction_flags=["UK", "EU"])
    r1 = audit_chain.append_to_chain(payload={"event": "screened"}, prev_row=None)
    r2 = audit_chain.append_to_chain(payload={"event": "settled"}, prev_row=r1)

    return {
        "action_ref": aref,
        "receipt_hash": sub.sha256_jcs(dict(receipt)),
        "receipt_keys": sorted(dict(receipt)),
        "transition_hash": transactional.transition_hash(aref, "COMMITTED", T, T, T),
        # dict(...) compares by value; repr(...) additionally pins key insertion order, which
        # is what a customer diffing logs would notice.
        "chain_row1": dict(r1),
        "chain_row2": dict(r2),
        "chain_row1_repr": repr(dict(r1)),
        "chain_row2_repr": repr(dict(r2)),
        "canonical_bytes": sub.canonicalize_bytes(
            {"b": [1, {"z": None, "a": True}], "a": "x", "v": 1.0}).decode(),
    }


@pytest.fixture
def _clean_shim():
    v1_shim.uninstall()
    yield
    v1_shim.uninstall()


def test_unchanged_customer_code_gives_identical_results(_clean_shim):
    pytest.importorskip("algovoi_substrate")
    import sys

    # 1) against the real open package
    v1_shim.uninstall()
    for m in [k for k in sys.modules if k.startswith("algovoi_substrate")]:
        del sys.modules[m]
    on_open = _customer_workload()

    # 2) the same function, with the shim standing in for the open package
    for m in [k for k in sys.modules if k.startswith("algovoi_substrate")]:
        del sys.modules[m]
    v1_shim.install()
    on_substrate2 = _customer_workload()

    assert on_open == on_substrate2, "customer-visible output diverged between engines"
    # and byte-identical once serialised, which is the form a customer would store or diff
    assert (json.dumps(on_open, sort_keys=True) == json.dumps(on_substrate2, sort_keys=True))


def test_audit_row_key_order_matches_the_open_package():
    """Key insertion order affects no digest (JCS sorts, dict equality ignores order) but it
    is what repr and tuple(row) follow. Aligned so the drop-in claim carries no asterisk."""
    pytest.importorskip("algovoi_substrate")
    from algovoi_substrate import audit_chain as open_ac

    from substrate2 import audit as s2_ac

    a = open_ac.append_to_chain(payload={"event": "x"}, prev_row=None)
    b = s2_ac.append_to_chain(payload={"event": "x"}, prev_row=None)
    assert list(a) == list(b)
    assert tuple(a.values()) == tuple(b.values())
