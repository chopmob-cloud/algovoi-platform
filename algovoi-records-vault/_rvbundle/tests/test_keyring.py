"""F7 keyring + rotation-proof test (standalone, runnable): the 30-year continuity story.

Run: python algovoi-records-vault/tests/test_keyring.py
"""
import asyncio
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"test": True}

from algovoi_records_vault import (  # noqa: E402
    RecordsVault, make_rotation_proof, verify_key_chain, verify_rotation_proof,
)

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
    with open(path, "rb") as fh:
        outer = json.loads(signing.b64u_decode(fh.read().decode()))
    outer["payload"]["new_valid_to"] = "TAMPERED"
    with open(path, "wb") as fh:
        fh.write(signing.b64u_encode(json.dumps(outer, separators=(",", ":"), sort_keys=True).encode()).encode())


async def main() -> int:
    tmp = tempfile.mkdtemp(prefix="rv-keyring-")
    pk, sk = signing.generate_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "archive")))
    vault = RecordsVault(archive=archive)
    kr = vault.keyring()

    # three-generation key lineage k1 -> k2 -> k3
    k1pk, k1sk = signing.generate_keypair()
    k2pk, k2sk = signing.generate_keypair()
    k3pk, k3sk = signing.generate_keypair()

    await kr.register_key(public_key=k1pk, valid_from="2026-01-01T00:00:00Z")
    await kr.rotate(old_public_key=k1pk, old_secret_key=k1sk, new_public_key=k2pk, new_secret_key=k2sk,
                    rotated_at="2027-01-01T00:00:00Z")
    await kr.rotate(old_public_key=k2pk, old_secret_key=k2sk, new_public_key=k3pk, new_secret_key=k3sk,
                    rotated_at="2028-01-01T00:00:00Z")

    proofs = await kr.rotation_proofs()
    check("two rotation proofs recorded", len(proofs) == 2)
    check("each rotation proof verifies (dual cross-signature)",
          all(verify_rotation_proof(p) for p in proofs))

    ok, detail = await kr.verify_key_chain()
    check("key chain verifies as unbroken k1->k2->k3",
          ok and signing.kid_for(k3pk) in detail)

    # a single forged proof fails (flip the new key's signature)
    bad = dict(proofs[0])
    bad["new_sig"] = signing.b64u_encode(b"\x00" * 64)
    check("a forged rotation proof is rejected", verify_rotation_proof(bad) is False)

    # a broken lineage (gap between proofs) is detected
    xpk, xsk = signing.generate_keypair()
    ypk, ysk = signing.generate_keypair()
    gap = make_rotation_proof(old_public_key=xpk, old_secret_key=xsk,
                              new_public_key=ypk, new_secret_key=ysk)
    ok2, detail2 = verify_key_chain([proofs[0], gap]), None
    check("verify_key_chain detects a lineage gap", verify_key_chain([proofs[0], gap])[0] is False)

    # published /.well-known/pqc-keys.json: all 3 historical keys, oldest retired with a valid_to
    pub = await kr.published_keys()
    kids = {k["kid"]: k for k in pub["keys"]}
    check("published key set lists all 3 historical keys", len(kids) == 3)
    check("rotated-away keys are retired with a valid_to",
          kids[signing.kid_for(k1pk)]["status"] == "retired"
          and kids[signing.kid_for(k1pk)]["valid_to"] == "2027-01-01T00:00:00Z")
    check("current key is active",
          kids[signing.kid_for(k3pk)]["status"] == "active")
    check("published set embeds the rotation proofs", len(pub["rotation_proofs"]) == 2)

    # stream integrity + tamper-evidence
    vr = await kr.verify_chain()
    check("keyring stream verifies valid", vr.valid and vr.length == 3)
    tamper(os.path.join(tmp, "archive", "keyring", "000000000001.json"))
    vr = await kr.verify_chain()
    check("tampered keyring entry detected", (not vr.valid) and vr.broken_at == 1)

    print(f"\n=== KEYRING RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
