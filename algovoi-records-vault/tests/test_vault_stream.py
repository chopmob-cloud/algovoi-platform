"""_VaultStream unit test (standalone, runnable): the generic signed evidence chain.

Run: python algovoi-records-vault/tests/test_vault_stream.py
"""
import asyncio
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402

from algovoi_records_vault.vault import _VaultStream, verify_stream  # noqa: E402

PASS = 0
FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


def tamper(path):
    """Rewrite an entry file so its stored signature no longer matches its payload."""
    import json
    with open(path, "rb") as fh:
        outer = json.loads(signing.b64u_decode(fh.read().decode()))
    outer["payload"]["reason"] = "TAMPERED"
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-stream-")
    pk, sk = signing.generate_keypair()
    storage = LocalFsBackend(os.path.join(tmp, "vault"))
    s = _VaultStream(storage=storage, public_key=pk, secret_key=sk,
                     entry_type="vault_demo", prefix="demo")

    # empty stream verifies vacuously
    vr = await s.verify_chain()
    check("empty stream verifies (length 0)", vr.valid and vr.length == 0)

    r0 = await s.append({"reason": "first", "n": 1})
    r1 = await s.append({"reason": "second", "n": 2})
    r2 = await s.append({"reason": "third", "n": 3})
    check("append assigns sequential seq", [r0["seq"], r1["seq"], r2["seq"]] == [0, 1, 2])
    check("first entry has null prev_entry_hash", r0["prev_entry_hash"] is None)
    check("entries chain (prev == payload_hash of predecessor)",
          r1["prev_entry_hash"] == signing.payload_hash(r0["payload"]) and
          r2["prev_entry_hash"] == signing.payload_hash(r1["payload"]))

    payloads = await s.list_payloads()
    check("payloads carry the feature fields + reserved fields",
          payloads[0]["reason"] == "first" and payloads[0]["type"] == "vault_demo"
          and "recorded_at" in payloads[0] and payloads[0]["kid"] == signing.kid_for(pk))

    vr = await s.verify_chain()
    check("3-entry chain verifies valid", vr.valid and vr.length == 3)

    # ── #7 read-path guard: a corrupt stored entry surfaces a clear MalformedEntryError ───────
    from algovoi_records_vault.vault import MalformedEntryError
    cdir = os.path.join(tmp, "corrupt")
    cs = _VaultStream(storage=LocalFsBackend(cdir), public_key=pk, secret_key=sk,
                      entry_type="vault_demo", prefix="demo")
    await cs.append({"reason": "ok"})
    with open(os.path.join(cdir, "demo", "000000000000.json"), "wb") as fh:
        fh.write(b"}{ not a valid envelope")
    gp_raised = False
    try:
        await cs.get_payload(0)
    except MalformedEntryError:
        gp_raised = True
    check("get_payload raises MalformedEntryError on a corrupt entry", gp_raised)
    lp_raised = False
    try:
        await cs.list_payloads()
    except MalformedEntryError:
        lp_raised = True
    check("list_payloads raises MalformedEntryError on a corrupt entry", lp_raised)

    # reserved-key guard
    try:
        await s.append({"seq": 99})
        check("append refuses to override a reserved key", False)
    except ValueError:
        check("append refuses to override a reserved key", True)

    # read-only stream cannot append
    ro = _VaultStream(storage=storage, public_key=pk, secret_key=None,
                      entry_type="vault_demo", prefix="demo")
    try:
        await ro.append({"x": 1})
        check("read-only stream refuses append", False)
    except RuntimeError:
        check("read-only stream refuses append", True)

    # tamper detection — flip the middle entry, chain breaks at that index
    tamper(os.path.join(tmp, "vault", "demo", "000000000001.json"))
    vr = await s.verify_chain()
    check("tampered entry fails verification at its index",
          (not vr.valid) and vr.broken_at == 1 and vr.reason in ("bad_signature", "malformed_entry"))

    # verify_stream is pure and matches a wrong-key check
    fresh = _VaultStream(storage=LocalFsBackend(os.path.join(tmp, "vault2")),
                         public_key=pk, secret_key=sk, entry_type="vault_demo", prefix="demo")
    await fresh.append({"reason": "x"})
    envs = await fresh.list_entries()
    other_pk, _ = signing.generate_keypair()
    check("verify_stream rejects under the wrong public key",
          verify_stream(envs, other_pk, "vault_demo").valid is False)
    check("verify_stream rejects a type mismatch",
          verify_stream(envs, pk, "wrong_type").valid is False)

    # ── truncation guard (security fix 2026-08-19): a clean prefix is not a clean whole ──────────
    tdir = os.path.join(tmp, "trunc")
    ts = _VaultStream(storage=LocalFsBackend(tdir), public_key=pk, secret_key=sk,
                      entry_type="vault_demo", prefix="demo")
    for i in range(4):
        await ts.append({"reason": f"e{i}"})
    pinned = await ts.head()                                   # {seq_count:4, last_entry_hash:...}
    tenvs = await ts.list_entries()
    check("full 4-entry stream verifies", (await ts.verify_chain()).valid)
    # trailing deletion, head blob intact -> persisted seq_count still counts the dropped entry
    os.remove(os.path.join(tdir, "demo", "000000000003.json"))
    tr = await ts.verify_chain()
    check("trailing deletion detected (missing_entry)", (not tr.valid) and tr.reason == "missing_entry")
    # out-of-band anchor catches a prefix even if the head blob were also rewritten
    ta = verify_stream(tenvs[:3], pk, "vault_demo", expected_head=pinned)
    check("pinned head rejects a truncated prefix",
          (not ta.valid) and ta.reason in ("length_mismatch", "head_mismatch"))
    # interior deletion caught too (fresh stream)
    idir = os.path.join(tmp, "interior")
    isr = _VaultStream(storage=LocalFsBackend(idir), public_key=pk, secret_key=sk,
                       entry_type="vault_demo", prefix="demo")
    for i in range(4):
        await isr.append({"reason": f"e{i}"})
    os.remove(os.path.join(idir, "demo", "000000000001.json"))
    ir = await isr.verify_chain()
    check("interior deletion detected (missing_entry)", (not ir.valid) and ir.reason == "missing_entry")

    print(f"\n=== VAULT-STREAM RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
