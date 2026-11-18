"""Free-verifier test (standalone, runnable): the public verifier checks real vault artifacts offline.

Generates genuine artifacts with the vault, then verifies them with algovoi_verify (which imports NO
AlgoVoi code), and confirms tampering is caught.
Run: python algovoi-records-vault/free-verifier/test_free_verifier.py
"""
import asyncio
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # platform dir
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")
sys.path.insert(0, HERE)

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"test": True}

from algovoi_records_vault import Principal, RecordsVault  # noqa: E402
from algovoi_records_vault.vault import (  # noqa: E402
    ACCESS_PREFIX, ACCESS_TYPE, TSA_PREFIX, TSA_TYPE, _VaultStream,
)

# the public verifier — NOTE: zero algovoi imports inside it
import algovoi_verify as V  # noqa: E402

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


async def main() -> int:
    # prove the verifier really has no AlgoVoi dependency
    src = open(os.path.join(HERE, "algovoi_verify.py"), encoding="utf-8").read()
    check("verifier imports no AlgoVoi code",
          "algovoi_doc_archive" not in src and "algovoi_records_vault" not in src)

    tmp = tempfile.mkdtemp(prefix="rv-freever-")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    storage = LocalFsBackend(os.path.join(tmp, "archive"))
    archive = Archive(public_key=pk, secret_key=sk, storage=storage,
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    os.environ.pop("VAULT_TSA_URL", None)
    vault = RecordsVault(archive=archive)

    out = await vault.notarize(data=b"a record under test", title="rec-1")
    await vault.retrieve(doc_hash=out["archive"]["doc_hash"], principal=Principal(did="did:web:reader"))

    # export a pack the public verifier understands
    pack = os.path.join(tmp, "pack")
    os.makedirs(pack)

    async def export(etype, prefix, name):
        s = _VaultStream(storage=storage, public_key=pk, secret_key=None, entry_type=etype, prefix=prefix)
        with open(os.path.join(pack, name), "w", encoding="utf-8") as fh:
            json.dump(await s.list_entries(), fh)

    with open(os.path.join(pack, "archive_chain.json"), "w", encoding="utf-8") as fh:
        json.dump(await archive.list_entries(), fh)
    await export(TSA_TYPE, TSA_PREFIX, "tsa_chain.json")
    await export(ACCESS_TYPE, ACCESS_PREFIX, "access_chain.json")
    with open(os.path.join(pack, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(signing.public_key_b64(pk))

    # 1) standalone CLI verifies the pack (subprocess — exactly what a customer runs)
    genuine_kid = V._kid(pk)
    r = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "pack", pack, genuine_kid],
                       capture_output=True, text=True)
    check("CLI `pack` verifies a genuine evidence pack anchored to its kid (exit 0)", r.returncode == 0)
    check("CLI prints VERIFIED AND ANCHORED", "VERIFIED AND ANCHORED" in r.stdout)

    # 1b) without an expected kid the pack is intact but the key is self-asserted -> exit 3
    r1b = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "pack", pack],
                         capture_output=True, text=True)
    check("CLI `pack` without an expected kid is intact-not-anchored (exit 3)", r1b.returncode == 3)
    check("CLI says KEY NOT ANCHORED", "KEY NOT ANCHORED" in r1b.stdout)

    # 1c) REGRESSION: a wholly fabricated pack, signed by an attacker key shipped inside it,
    #     is internally perfect but must NOT verify against the genuine kid.
    forged = os.path.join(tmp, "forged_pack")
    os.makedirs(forged)
    fpk, fsk = signing.generate_keypair()
    fake = [{"type": "archive_entry", "seq": 0, "prev_receipt_hash": None,
             "detail": "board minutes archived", "ts": "2026-01-05T09:00:00Z"}]
    envs_f = []
    for step in fake:
        sig = signing.sign_bytes(fsk, V.jcs(step))
        envs_f.append(signing.b64u_encode(json.dumps(
            {"payload": step, "sig": signing.b64u_encode(sig), "kid": V._kid(fpk)}).encode()))
    with open(os.path.join(forged, "archive_chain.json"), "w", encoding="utf-8") as fh:
        json.dump(envs_f, fh)
    with open(os.path.join(forged, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(signing.public_key_b64(fpk))
    r1c = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "pack", forged, genuine_kid],
                         capture_output=True, text=True)
    check("CLI REJECTS a forged pack whose embedded key is not the anchored kid (exit 1)",
          r1c.returncode == 1 and "does not match expected" in r1c.stdout)

    # 2) receipt + chain functions
    receipt = (await archive.list_entries())[0]
    ok, payload = V.verify_receipt(receipt, pk)
    check("verify_receipt TRUE for a genuine receipt", ok and payload.get("type") == "archive_entry")
    other_pk, _ = signing.generate_keypair()
    check("verify_receipt FALSE under the wrong key", V.verify_receipt(receipt, other_pk)[0] is False)
    tsa_envs = json.load(open(os.path.join(pack, "tsa_chain.json")))
    check("verify_chain TRUE for the tsa stream", V.verify_chain(tsa_envs, pk)[0] is True)

    # 3) F7 key lineage
    k1pk, k1sk = signing.generate_keypair()
    k2pk, k2sk = signing.generate_keypair()
    k3pk, k3sk = signing.generate_keypair()
    kr = vault.keyring()
    await kr.register_key(public_key=k1pk)
    await kr.rotate(old_public_key=k1pk, old_secret_key=k1sk, new_public_key=k2pk, new_secret_key=k2sk)
    await kr.rotate(old_public_key=k2pk, old_secret_key=k2sk, new_public_key=k3pk, new_secret_key=k3sk)
    proofs_doc = (await kr.published_keys())["rotation_proofs"]
    pf = os.path.join(tmp, "rotation_proofs.json")
    with open(pf, "w", encoding="utf-8") as fh:
        json.dump(proofs_doc, fh)
    r2 = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "keys", pf, V._kid(k1pk)],
                        capture_output=True, text=True)
    check("CLI `keys` verifies an F7 rotation lineage anchored to its genesis kid",
          r2.returncode == 0 and "PASS" in r2.stdout)
    r2b = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "keys", pf],
                         capture_output=True, text=True)
    check("CLI `keys` without a genesis kid is intact-not-anchored (exit 3)",
          r2b.returncode == 3 and "NOT ANCHORED" in r2b.stdout)
    r2c = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "keys", pf, V._kid(k3pk)],
                         capture_output=True, text=True)
    check("CLI `keys` REJECTS a lineage whose genesis is not the anchored kid",
          r2c.returncode == 1 and "genesis_mismatch" in r2c.stdout)

    # 4) tamper -> the pack fails
    accp = os.path.join(pack, "access_chain.json")
    envs = json.load(open(accp))
    env = json.loads(signing.b64u_decode(envs[0]))
    env["payload"]["decision"] = "denied" if env["payload"].get("decision") == "granted" else "granted"
    envs[0] = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    with open(accp, "w", encoding="utf-8") as fh:
        json.dump(envs, fh)
    r3 = subprocess.run([sys.executable, os.path.join(HERE, "algovoi_verify.py"), "pack", pack],
                        capture_output=True, text=True)
    check("CLI fails a tampered pack (non-zero exit + VERIFICATION FAILED)",
          r3.returncode != 0 and "VERIFICATION FAILED" in r3.stdout)

    print(f"\n=== FREE-VERIFIER RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
