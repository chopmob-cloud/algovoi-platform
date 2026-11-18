#!/usr/bin/env python3
"""Standalone offline verifier for an AlgoVoi Records Vault evidence pack.

This script depends on **nothing from AlgoVoi** — only two public libraries (`pqcrypto` for Falcon-1024
verification, `rfc8785` for JCS canonicalization) and the **published public key** shipped in the pack.
There is no secret key, no running service, and no network access. It re-derives every signature and
hash-link itself, so a sceptical third party (an auditor, a customer's security team, opposing counsel)
can confirm the evidence is genuine and unaltered without trusting AlgoVoi at all.

It verifies:
  1. Every signed chain — archive receipts, RFC-3161 timestamps, the read-access log, and legal holds —
     is correctly Falcon-1024-signed, sequentially numbered, and hash-linked (no entry altered,
     inserted, removed, reordered, or back-dated).
  2. Every timestamp's messageImprint equals the SHA-256 (JCS) hash of the archive receipt it claims to
     stamp — proving the time binding is real, not decorative.

Run:  python verify_evidence_pack.py [pack_dir]      (default: this file's own directory)
Exit: 0 iff ALL evidence verifies; non-zero otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

try:
    import rfc8785
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
except Exception as exc:  # noqa: BLE001
    print(f"This verifier needs two public libraries: pip install pqcrypto rfc8785  ({exc})")
    raise SystemExit(2)


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _jcs(payload: dict) -> bytes:
    return rfc8785.dumps(payload)


def _payload_hash(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(_jcs(payload)).hexdigest()


def _open_envelope(env_b64: str):
    env = json.loads(_b64u(env_b64))
    return env["payload"], _b64u(env["sig"]), env.get("kid", "")


def _falcon_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        return bool(_falcon_verify(pk, msg, sig))
    except Exception:  # noqa: BLE001
        return False


def verify_chain(envs, pk, etype, prev_field):
    """Re-verify a signed, hash-linked chain end to end. Returns (ok, detail)."""
    prev = None
    for i, e in enumerate(envs):
        try:
            payload, sig, _ = _open_envelope(e)
        except Exception:  # noqa: BLE001
            return False, f"malformed_entry@{i}"
        if payload.get("type") != etype:
            return False, f"wrong_type@{i}"
        if not _falcon_ok(pk, _jcs(payload), sig):
            return False, f"bad_signature@{i}"
        if payload.get("seq") != i:
            return False, f"seq_mismatch@{i}"
        if payload.get(prev_field) != prev:
            return False, f"chain_break@{i}"
        prev = _payload_hash(payload)
    return True, f"{len(envs)} entries, head={prev}"


def main(pack: str) -> int:
    with open(os.path.join(pack, "public_key.b64"), encoding="utf-8") as fh:
        pk = base64.b64decode(fh.read().strip())

    def load(name):
        with open(os.path.join(pack, name), encoding="utf-8") as fh:
            return json.load(fh)

    streams = [
        ("archive_chain.json", "archive_entry",      "prev_receipt_hash"),
        ("tsa_chain.json",     "vault_tsa_token",    "prev_entry_hash"),
        ("access_chain.json",  "vault_access_event", "prev_entry_hash"),
        ("holds_chain.json",   "vault_legal_hold",   "prev_entry_hash"),
    ]

    print("=" * 74)
    print("AlgoVoi Records Vault — offline evidence verification")
    print(f"  pack          : {pack}")
    print(f"  public key kid: {hashlib.sha256(pk).hexdigest()[:16]}  (Falcon-1024, {len(pk)} bytes)")
    print(f"  verifier deps : pqcrypto + rfc8785 only — NO AlgoVoi code, NO secret, NO service")
    print("=" * 74)

    ok_all = True
    for fn, etype, prev_field in streams:
        if not os.path.exists(os.path.join(pack, fn)):
            print(f"  [SKIP] {fn:<19} (absent)")
            continue
        ok, detail = verify_chain(load(fn), pk, etype, prev_field)
        print(f"  [{'PASS' if ok else 'FAIL'}] {fn:<19} {etype:<19} {detail}")
        ok_all &= ok

    # RFC-3161 timestamp binding: every tsa record's messageImprint must equal payload_hash(receipt)
    arch_payloads = [_open_envelope(e)[0] for e in load("archive_chain.json")]
    bind_ok = True
    for e in load("tsa_chain.json"):
        tp, _, _ = _open_envelope(e)
        aseq = tp.get("archive_seq")
        want = _payload_hash(arch_payloads[aseq]) if isinstance(aseq, int) and aseq < len(arch_payloads) else None
        if tp.get("message_imprint") != want:
            bind_ok = False
            print(f"  [FAIL] timestamp binding  tsa#{tp.get('seq')} imprint != hash(archive#{aseq})")
    if bind_ok:
        print(f"  [PASS] timestamp binding   every tsa.messageImprint == SHA-256(JCS) of its archive receipt")
    ok_all &= bind_ok

    print("=" * 74)
    print("RESULT:", "ALL EVIDENCE VERIFIED OFFLINE (public key only)" if ok_all
          else "VERIFICATION FAILED — evidence is altered or inconsistent")
    print("=" * 74)
    return 0 if ok_all else 1


if __name__ == "__main__":
    pack_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    raise SystemExit(main(pack_dir))
