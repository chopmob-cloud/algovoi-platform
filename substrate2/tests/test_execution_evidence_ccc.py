"""
e2e: execution_evidence chain is CCC-ingestable, hybrid-signed, tamper-evident.

Builds a signed, hash-linked execution_evidence chain over real keystone
decision_refs, exports a CCC pack, and proves the Compliance Command Center
verifies it offline, labels it "Keystone · execution evidence", and that
tampering any entry breaks verification.

Run (from the worktree root):
  PYTHONPATH=substrate2/src:algovoi-command-center/src \
    python substrate2/tests/test_execution_evidence_ccc.py
or via pytest with the same PYTHONPATH.
"""
from __future__ import annotations

import base64
import json
import os
import tempfile

import pytest

from substrate2 import pqc
from substrate2.execution_evidence import (
    ENTRY_TYPE,
    build_execution_evidence_chain,
    execution_evidence_core,
    export_execution_evidence_pack,
)
# algovoi_command_center is a SIBLING package, not a substrate2 dependency. A bare import
# here made the whole suite uncollectable on any machine without it -- pytest interrupts on a
# collection error, so one missing sibling took out all 68 tests, including the ones that
# prove GA. importorskip skips this module and lets the rest run.
engine = pytest.importorskip("algovoi_command_center.engine")
posture = pytest.importorskip("algovoi_command_center.posture")

# Real keystone decision_refs (spend_decision_v1 sd-allow / sd-refer).
DEC_ALLOW = "sha256:2a444c629892f44fde1bd004aba9be01dd6cc7fe251eecdd545b82dca9f0bf97"
DEC_REFER = "sha256:914ea5fb17d6ee423d5724f18388af003aabf64d7fb162492bcadc0d93b2a872"
# execution_ref ex-allow-committed from execution_ref_v1.
EXEC_ALLOW = "sha256:f6e2bfc15b085ed51c4c972de81d1c6b00f4e55b272e2aa12e56bb7c521fc65a"

_CORES = [
    execution_evidence_core(DEC_ALLOW, "payment", "bilateral", "COMMITTED", 1716460800000),
    execution_evidence_core(DEC_REFER, "payment", "bilateral", "FAILED", 1716460801000),
]


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _keys():
    fpk, fsk = pqc.generate_falcon_1024_keypair()
    mpk, msk = pqc.generate_ml_dsa_65_keypair()
    return fpk, fsk, mpk, msk


def test_chain_verifies_in_ccc_hybrid():
    fpk, fsk, mpk, msk = _keys()
    chain = build_execution_evidence_chain(_CORES, fsk, fpk, msk, mpk)
    res = engine.verify_chain(chain, fpk)
    assert res.verified, res.reason
    assert res.entry_type == ENTRY_TYPE
    assert res.entries == len(_CORES)
    # the recomputable execution_ref is carried in each payload
    assert res.payloads[0]["execution_ref"] == EXEC_ALLOW
    assert res.payloads[0]["decision_ref"] == DEC_ALLOW


def test_pack_and_posture_label():
    fpk, fsk, mpk, msk = _keys()
    with tempfile.TemporaryDirectory() as d:
        pack_dir = os.path.join(d, "execpack")
        export_execution_evidence_pack(_CORES, pack_dir, fsk, fpk, msk, mpk)
        assert os.path.exists(os.path.join(pack_dir, "execution_evidence_chain.json"))
        pr = engine.verify_pack(pack_dir)
        assert pr.verified
        post = posture.build_posture([pr], estate="keystone")
        labels = _posture_labels(post)
        # match on the ascii tail to avoid middot encoding noise across consoles
        assert any("execution evidence" in s for s in labels), labels
        assert any("execution_evidence" in s for s in labels), labels


def test_tamper_breaks_chain():
    fpk, fsk, mpk, msk = _keys()
    chain = build_execution_evidence_chain(_CORES, fsk, fpk, msk, mpk)
    # tamper: rewrite entry 0's outcome inside the envelope
    env = json.loads(_b64u_dec(chain[0]))
    env["payload"]["outcome"] = "REVERSED"
    tampered = base64.urlsafe_b64encode(
        json.dumps(env, separators=(",", ":"), sort_keys=True).encode()
    ).decode().rstrip("=")
    chain[0] = tampered
    res = engine.verify_chain(chain, fpk)
    assert not res.verified


def _posture_labels(post) -> list[str]:
    """Collect human labels from a Posture object across plausible shapes."""
    out: list[str] = []
    for attr in ("metrics", "services", "lines", "items", "chains"):
        seq = getattr(post, attr, None)
        if seq:
            for m in seq:
                for f in ("label", "name", "title", "entry_type"):
                    v = getattr(m, f, None)
                    if isinstance(v, str):
                        out.append(v)
    # ascii-safe dump of the whole object (unicode escaped) as a fallback haystack
    out.append(json.dumps(_to_jsonable(post), default=str))
    return out


def _to_jsonable(o):
    if hasattr(o, "__dict__"):
        return {k: _to_jsonable(v) for k, v in vars(o).items()}
    if isinstance(o, (list, tuple)):
        return [_to_jsonable(x) for x in o]
    return o


if __name__ == "__main__":
    test_chain_verifies_in_ccc_hybrid()
    print("[1/3] PASS  execution_evidence chain verifies in CCC (Falcon, hybrid co-signed)")
    test_pack_and_posture_label()
    print("[2/3] PASS  CCC pack verifies + posture labels 'Keystone · execution evidence'")
    test_tamper_breaks_chain()
    print("[3/3] PASS  tampering an entry breaks chain verification")
    print("ALL 3/3 PASS")
