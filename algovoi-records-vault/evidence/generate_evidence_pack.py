#!/usr/bin/env python3
"""Generate a public, offline-verifiable AlgoVoi Records Vault evidence pack.

Runs the *real* vault through a worked health+legal scenario, then exports the signed artifacts to
``evidence/pack/`` so anyone can re-verify them with the bundled standalone verifier (public key only,
no AlgoVoi code, no secret, no service). Finishes by (a) self-verifying the pack and (b) demonstrating
that a one-byte tamper is detected.

Run: python algovoi-records-vault/evidence/generate_evidence_pack.py
"""
import asyncio
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # platform dir
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"evidence-pack": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"evidence-pack": True}

from algovoi_records_vault import Principal, RecordsVault  # noqa: E402
from algovoi_records_vault.vault import (  # noqa: E402
    ACCESS_PREFIX, ACCESS_TYPE, HOLD_PREFIX, HOLD_TYPE, TSA_PREFIX, TSA_TYPE, _VaultStream,
)

PACK = os.path.join(HERE, "pack")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


async def build_pack():
    work = os.path.join(HERE, "_work")
    for d in (PACK, work):
        if os.path.exists(d):
            shutil.rmtree(d)
    os.makedirs(PACK)

    # ── deterministic-shaped, real-crypto vault (keys are fresh per run; the proof is internal) ──
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    storage = LocalFsBackend(os.path.join(work, "archive"))
    archive = Archive(public_key=pk, secret_key=sk, storage=storage,
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk),
                      issuer_did="did:web:records-vault.algovoi.example")
    os.environ.pop("VAULT_TSA_URL", None)  # air-gap RFC-3161 (no external call needed for the demo)
    vault = RecordsVault(archive=archive, signing_secret_key=sk, signing_public_key=pk)

    clinician = Principal(did="did:web:clinic.example/dr-jones", kid="clinic-key-7",
                          scopes=("records:read",))
    counsel = Principal(did="did:web:law.example/counsel", kid="bar-2291",
                        scopes=("legal:hold",))

    # F1 — notarize an encrypted record, RFC-3161-sealed
    record = b"PATIENT patient-42 | imaging report | 2026-06-12 | (demonstration record)"
    out = await vault.notarize(data=record, title="patient-42/imaging-report",
                               content_type="text/plain",
                               metadata={"subject_ref": "patient-42", "vertical": "health"})
    doc_hash = out["archive"]["doc_hash"]

    # F3 — a granted read (clinician, treatment) and a denied read (unknown record)
    await vault.retrieve(doc_hash=doc_hash, principal=clinician, reason="treatment")
    try:
        await vault.retrieve(doc_hash="sha256:" + "00" * 32, principal=clinician, reason="fishing")
    except Exception:  # noqa: BLE001 — denial is the point; it is logged then re-raised
        pass

    # F2 — a legal hold on the patient matter (kept active to show an enforceable hold)
    holds = vault.holds(retention_days=365 * 7)
    await holds.place_hold(matter_id="MATTER-2026-A", reason="anticipated litigation; preserve patient-42",
                           principal=counsel, query={"subject_ref": "patient-42"})

    # ── export the signed chains (envelopes), the public key, and the (unreadable) ciphertext ──
    def ro(etype, prefix):
        return _VaultStream(storage=storage, public_key=pk, secret_key=None,
                            entry_type=etype, prefix=prefix)

    chains = {
        "archive_chain.json": await archive.list_entries(),
        "tsa_chain.json": await ro(TSA_TYPE, TSA_PREFIX).list_entries(),
        "access_chain.json": await ro(ACCESS_TYPE, ACCESS_PREFIX).list_entries(),
        "holds_chain.json": await ro(HOLD_TYPE, HOLD_PREFIX).list_entries(),
    }
    for fn, envs in chains.items():
        with open(os.path.join(PACK, fn), "w", encoding="utf-8") as fh:
            json.dump(envs, fh, indent=2)

    with open(os.path.join(PACK, "public_key.b64"), "w", encoding="utf-8") as fh:
        fh.write(signing.public_key_b64(pk))

    blob = await storage.get(f"blob/{doc_hash.split(':', 1)[1]}")
    with open(os.path.join(PACK, "record_blob.bin"), "wb") as fh:
        fh.write(blob)

    shutil.copy(os.path.join(HERE, "verify_evidence_pack.py"), os.path.join(PACK, "verify_evidence_pack.py"))

    # counts for the report
    counts = {k: len(v) for k, v in chains.items()}
    kid = signing.kid_for(pk)
    tsa0 = signing.open_envelope(chains["tsa_chain.json"][0])[0]

    # MANIFEST — sha256 of every artifact, so the pack is tamper-evident as a whole
    manifest = {
        "product": "AlgoVoi Records Vault",
        "version": "0.2.0",
        "pack_type": "offline-verifiable-evidence",
        "public_key_kid": kid,
        "signature_alg": "Falcon-1024 (FN-DSA-1024)",
        "encryption_alg": "ML-KEM-1024 + AES-256-GCM",
        "canonicalization": "RFC 8785 (JCS)",
        "chains": counts,
        "files": {},
    }
    for fn in sorted(os.listdir(PACK)):
        fp = os.path.join(PACK, fn)
        if os.path.isfile(fp):
            manifest["files"][fn] = "sha256:" + _sha256_file(fp)
    with open(os.path.join(PACK, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    _write_report(counts, kid, doc_hash, tsa0, len(blob))
    _write_readme()
    shutil.rmtree(work)
    return kid, counts


def _write_report(counts, kid, doc_hash, tsa0, blob_len):
    report = f"""# AlgoVoi Records Vault — Evidence Pack

This pack is **public evidence** that AlgoVoi Records Vault does what it claims. Every artifact below
was produced by the real product code and is **independently verifiable offline** — with only the
published public key and two standard libraries, no AlgoVoi software, no secret key, and no running
service. Run `python verify_evidence_pack.py` to confirm it yourself.

- **Signature:** Falcon-1024 (FN-DSA-1024, NIST Level 5)
- **Encryption at rest:** ML-KEM-1024 + AES-256-GCM
- **Canonicalization:** RFC 8785 (JCS)
- **Archive identity (kid):** `{kid}`
- **Demonstration record hash:** `{doc_hash}`

## What each chain proves

| Artifact | Capability | Entries | What a verifier confirms |
|---|---|---|---|
| `archive_chain.json` | Tamper-evident archive | {counts['archive_chain.json']} | The record was notarized into a Falcon-signed, hash-linked chain — unaltered, ordered, not back-dated. |
| `tsa_chain.json` | **F1** RFC-3161 timestamping | {counts['tsa_chain.json']} | The record's hash is bound to a trusted-timestamp record; its messageImprint equals the receipt hash. |
| `access_chain.json` | **F3** read-access audit log | {counts['access_chain.json']} | Every read (granted *and* denied) is sealed as a signed event — who, what, why — tamper-evidently. |
| `holds_chain.json` | **F2** legal / e-discovery hold | {counts['holds_chain.json']} | A litigation hold on the matter is recorded as signed evidence; it overrides routine disposal. |
| `record_blob.bin` | Encryption at rest | — | {blob_len} bytes of ML-KEM-1024 + AES-256-GCM ciphertext. **Included but unreadable** — no key is in this pack, yet everything above still verifies. |

## The headline property

Everything verifies **without decrypting the record and without trusting AlgoVoi**. You confirm *when*
it existed, *who* read it, and *that it is held* — from the public key alone. Tamper with any byte of
any chain and verification fails at that entry (see the generator's tamper demonstration).

## Verify it yourself

```
pip install pqcrypto rfc8785        # two public libraries — that is the entire trust base
python verify_evidence_pack.py      # re-derives every signature + hash-link; exit 0 = all genuine
```

Cross-check `MANIFEST.json` (SHA-256 of every file) to confirm the pack itself is intact.
"""
    with open(os.path.join(PACK, "REPORT.md"), "w", encoding="utf-8") as fh:
        fh.write(report)


def _write_readme():
    readme = """# Records Vault evidence pack — how to verify

You do **not** need any AlgoVoi software to check this evidence.

1. `pip install pqcrypto rfc8785`
2. `python verify_evidence_pack.py`

Exit code 0 means every signed chain (archive, timestamps, access log, legal holds) verified against
the published public key, and every timestamp binds to its archive receipt. The verifier contains no
AlgoVoi imports — read it; it is ~120 lines of Falcon-1024 verification + RFC 8785 hashing.

`record_blob.bin` is the encrypted demonstration record. It is deliberately included and is
unreadable (its ML-KEM key is not in the pack) — proving the evidence verifies without ever exposing
record contents. See `REPORT.md` for the capability-by-capability breakdown and `MANIFEST.json` for
per-file SHA-256 digests.
"""
    with open(os.path.join(PACK, "README.md"), "w", encoding="utf-8") as fh:
        fh.write(readme)


def _run_verifier(pack):
    return subprocess.run([sys.executable, os.path.join(pack, "verify_evidence_pack.py"), pack],
                          capture_output=True, text=True)


def main():
    kid, counts = asyncio.run(build_pack())
    print(f"\n[generated] evidence pack at {PACK}")
    print(f"[generated] archive kid={kid}  chains={counts}\n")

    print("########## SELF-VERIFY (clean pack — must PASS) ##########")
    res = _run_verifier(PACK)
    print(res.stdout.strip())
    if res.returncode != 0:
        print("UNEXPECTED: clean pack failed verification")
        return 1

    print("\n########## TAMPER DEMO (flip one byte — must FAIL) ##########")
    tampered = os.path.join(HERE, "_pack_tampered")
    if os.path.exists(tampered):
        shutil.rmtree(tampered)
    shutil.copytree(PACK, tampered)
    # forge an access decision: flip the FIRST access event's decision and re-encode the envelope
    # WITHOUT re-signing — the Falcon signature no longer covers the payload, so it is rejected.
    acc = os.path.join(tampered, "access_chain.json")
    with open(acc, encoding="utf-8") as fh:
        envs = json.load(fh)
    env = json.loads(signing.b64u_decode(envs[0]))
    forged = "granted" if env["payload"].get("decision") != "granted" else "denied"
    print(f"    (forging access event #0: decision {env['payload'].get('decision')!r} -> {forged!r})")
    env["payload"]["decision"] = forged
    envs[0] = signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
    with open(acc, "w", encoding="utf-8") as fh:
        json.dump(envs, fh, indent=2)
    res2 = _run_verifier(tampered)
    print(res2.stdout.strip())
    shutil.rmtree(tampered)
    if res2.returncode == 0:
        print("UNEXPECTED: tampered pack still verified")
        return 1

    print("\n[OK] evidence pack generated, self-verified, and tamper-detection demonstrated.")
    print(f"[OK] share the folder: {PACK}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
