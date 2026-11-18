"""
Section 7 — action_ref exactly-once lifecycle invariants + adversarial isolation (Claim 2).

7a. action_ref_exactly_once_v1 pair invariants
    Recompute each vector hash with substrate2 primitives, then assert every
    same_hash_as / different_hash_from pair invariant holds.

7b. adversarial_isolation_v1 Claim 2 (reference-impl rejection PoR)
    Each reject vector must raise the exact substrate2 exception named in
    expected_error; the control vector must be accepted without error.
    Claim 1 (JCS input bytes) is already covered by Section 1 / jcs_vectors.run.
"""
from __future__ import annotations

import json
from pathlib import Path

from .._paths import vector_set_path

# Both sets are bundled inside the installer (see _bundled_vectors/), so Section 7
# binds from first boot without the external corpus; resolver falls back to the
# corpus if the bundled copy is ever absent.
_EO_FILE = vector_set_path("action_ref_exactly_once_v1", "action_ref_exactly_once_v1.json")
_ADV_FILE = vector_set_path("adversarial_isolation_v1", "adversarial_isolation_v1.json")


# ---------------------------------------------------------------------------
# Hash computers
# ---------------------------------------------------------------------------

def _eo_hash(vector: dict) -> str | None:
    """Compute substrate2 hash for an exactly-once vector from its preimage."""
    from substrate2.action import action_ref as _ar
    from substrate2.transactional import transition_hash as _th

    p = vector.get("preimage")
    if not isinstance(p, dict):
        return None
    if "agent_id" in p:
        return _ar(p["agent_id"], p["action_type"], p["scope"], p["timestamp_ms"])
    if "action_ref" in p and "state" in p:
        return _th(
            p["action_ref"], p["state"],
            p["transition_timestamp_ms"], p["authority_verified_at_ms"],
            p["revocation_check_at_ms"],
        )
    return None


# ---------------------------------------------------------------------------
# 7a — pair invariants
# ---------------------------------------------------------------------------

def _section_7a() -> tuple[bool, str]:
    data = json.loads(_EO_FILE.read_text(encoding="utf-8"))
    vecs = {v["vector_id"]: v for v in data.get("vectors", [])}

    hashes: dict[str, str] = {}
    for vid, vec in vecs.items():
        h = _eo_hash(vec)
        if h is not None:
            hashes[vid] = h

    fails: list[str] = []
    passed = 0
    for pair in data.get("pair_invariants", []):
        pid = pair["id"]
        lh = hashes.get(pair["left"])
        rh = hashes.get(pair["right"])
        if lh is None or rh is None:
            fails.append(f"{pid}: hash not computed")
            continue
        ptype = pair["type"]
        if ptype == "same_hash_as" and lh == rh:
            passed += 1
        elif ptype == "different_hash_from" and lh != rh:
            passed += 1
        elif ptype == "same_hash_as":
            fails.append(f"{pid}: expected same, got different ({lh[:8]}... vs {rh[:8]}...)")
        elif ptype == "different_hash_from":
            fails.append(f"{pid}: expected different, got same hash")
        else:
            fails.append(f"{pid}: unknown pair type {ptype!r}")

    total = len(data.get("pair_invariants", []))
    ok = not fails
    detail = f"{passed}/{total} exactly-once pair invariants (SKIP-on-retry + replay-binding)"
    if fails:
        detail += " | FAIL: " + "; ".join(fails)
    return ok, detail


# ---------------------------------------------------------------------------
# 7b — adversarial isolation Claim 2
# ---------------------------------------------------------------------------

_ERROR_MAP = {
    "TransactionalError": None,   # filled lazily
    "ActionRefError": None,
    "AuditChainError": None,
}


def _get_exc(name: str):
    from substrate2.transactional import TransactionalError
    from substrate2.action import ActionRefError
    from substrate2.audit import AuditChainError
    return {"TransactionalError": TransactionalError,
            "ActionRefError": ActionRefError,
            "AuditChainError": AuditChainError}[name]


def _run_check(check: str, inp):
    from substrate2.action import action_ref_object
    from substrate2.transactional import transition_preimage
    from substrate2.audit import verify_audit_chain

    if check == "transition_preimage":
        transition_preimage(**inp)
    elif check == "action_ref":
        action_ref_object(**inp)
    elif check == "audit_chain":
        verify_audit_chain(inp)
    else:
        raise ValueError(f"unknown check: {check!r}")


def _section_7b() -> tuple[bool, str]:
    data = json.loads(_ADV_FILE.read_text(encoding="utf-8"))
    fails: list[str] = []
    passed = 0

    for vec in data.get("vectors", []):
        vid = vec["vector_id"]
        check = vec["check"]
        inp = vec["input"]
        expectation = vec.get("expectation")
        expected_error = vec.get("expected_error")

        if expectation == "reference":
            # control — must be accepted
            try:
                _run_check(check, inp)
                passed += 1
            except Exception as exc:
                fails.append(f"{vid}: control raised unexpectedly: {type(exc).__name__}: {exc}")
        elif expectation == "reject":
            exc_cls = _get_exc(expected_error)
            try:
                _run_check(check, inp)
                fails.append(f"{vid}: expected {expected_error}, got no exception")
            except exc_cls:
                passed += 1
            except Exception as exc:
                fails.append(f"{vid}: expected {expected_error}, got {type(exc).__name__}: {exc}")
        else:
            fails.append(f"{vid}: unknown expectation {expectation!r}")

    total = len(data.get("vectors", []))
    ok = not fails
    detail = f"{passed}/{total} adversarial isolation (Claim 2: rejection PoR)"
    if fails:
        detail += " | FAIL: " + "; ".join(fails)
    return ok, detail


# ---------------------------------------------------------------------------
# Combined section entry point
# ---------------------------------------------------------------------------

def run() -> tuple[bool, str]:
    ok7a, d7a = _section_7a()
    ok7b, d7b = _section_7b()
    ok = ok7a and ok7b
    detail = f"7a {d7a}  ||  7b {d7b}"
    return ok, detail
