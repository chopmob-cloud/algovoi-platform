"""Compliance Command Center test (standalone, runnable).

Builds a small synthetic evidence pack with real Falcon-1024 signatures, then exercises the full
pipeline: ingest -> verify -> posture -> dashboard -> export, plus the tamper-is-caught guarantee.

Run: python tests/test_command_center.py   (needs pqcrypto + rfc8785)
"""
import base64
import hashlib
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from algovoi_command_center import licensing as _lic  # noqa: E402
_lic.require_license = lambda: {"test": True}

import rfc8785  # noqa: E402
from pqcrypto.sign.falcon_1024 import generate_keypair, sign  # noqa: E402

from algovoi_command_center.engine import ingest, verify_pack  # noqa: E402
from algovoi_command_center.posture import build_posture  # noqa: E402
from algovoi_command_center.dashboard import render_dashboard  # noqa: E402
from algovoi_command_center.export import build_auditor_pack  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _phash(payload):
    return "sha256:" + hashlib.sha256(rfc8785.dumps(payload)).hexdigest()


def _chain(pk, sk, etype, rows):
    """Build a signed, hash-linked chain (list of base64 envelopes) for the given rows."""
    envs, prev = [], None
    for i, fields in enumerate(rows):
        payload = {**fields, "type": etype, "seq": i, "prev_entry_hash": prev}
        sig = sign(sk, rfc8785.dumps(payload))
        env = {"payload": payload, "sig": _b64u(sig), "kid": hashlib.sha256(pk).hexdigest()[:16]}
        envs.append(_b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()))
        prev = _phash(payload)
    return envs


def _make_pack(d):
    pk, sk = generate_keypair()
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "public_key.b64"), "w").write(base64.b64encode(pk).decode())
    json.dump(_chain(pk, sk, "archive_entry", [{"doc_hash": "sha256:aa"}, {"doc_hash": "sha256:bb"}]),
              open(os.path.join(d, "archive_chain.json"), "w"))
    json.dump(_chain(pk, sk, "vault_access_event", [{"decision": "granted"}, {"decision": "denied"}, {"decision": "granted"}]),
              open(os.path.join(d, "access_chain.json"), "w"))
    json.dump(_chain(pk, sk, "vault_legal_hold", [{"action": "set", "matter_id": "M-1"}]),
              open(os.path.join(d, "holds_chain.json"), "w"))
    return pk


def main():
    work = tempfile.mkdtemp(prefix="cc-test-")
    pack = os.path.join(work, "estate-a")
    _make_pack(pack)

    packs = ingest(work)
    check("ingest finds the pack", len(packs) == 1)
    check("pack verifies (real Falcon signatures)", packs[0].verified)

    post = build_posture(packs, estate="estate-a")
    check("posture all_verified", post.all_verified)
    mv = {m.key: m.value for m in post.metrics}
    check("records_preserved == 2", mv.get("records_preserved") == 2)
    check("access_events == 3", mv.get("access_events") == 3)
    check("active_holds == 1", mv.get("active_holds") == 1)

    html = render_dashboard(post)
    check("dashboard renders the title", "Compliance Command Center" in html)
    check("dashboard shows the verifiable pill", "all evidence offline-verifiable" in html)

    blob = build_auditor_pack(work, packs, post)
    import io, zipfile
    z = zipfile.ZipFile(io.BytesIO(blob))
    check("auditor pack includes the verification summary", "VERIFICATION-SUMMARY.json" in z.namelist())

    # tamper: flip a field in a signed entry -> must be caught
    hp = os.path.join(pack, "holds_chain.json")
    arr = json.load(open(hp))
    raw = json.loads(base64.urlsafe_b64decode(arr[0] + "==" * 2))
    raw["payload"]["matter_id"] = "FORGED"
    arr[0] = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    json.dump(arr, open(hp, "w"))
    tampered = verify_pack(pack)
    check("tampered chain fails verification", not tampered.verified)
    check("tampered posture is not all_verified", not build_posture([tampered]).all_verified)

    print(f"\n=== COMMAND-CENTER RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
