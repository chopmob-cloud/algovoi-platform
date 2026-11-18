# HOWTO: produce a validation pack from a standalone Records Vault

Goal: a customer running Records Vault on their own infrastructure can generate a
signed System Validation Evidence Pack and hand it to an auditor, who verifies it
offline with no AlgoVoi software.

## 1. Run the suite and capture the result

Records Vault ships its test and conformance suite. Run it and record the summary
(the customer's own CI already does this):

```bash
cd algovoi-records-vault
python -m pytest -q            # full suite, for example 283 passed
```

Turn that into one dict per suite. The `result_digest` is the SHA-256 of the run
log, so the OQ section points at an immutable record of the run:

```python
suite_results = [
    {"name": "records_vault", "total": 283, "passed": 283, "failed": 0,
     "run_at": "2026-06-15T01:00:00Z", "result_digest": "sha256:<digest of pytest log>"},
]
```

## 2. Read the vault's chain head (PQ)

A standalone vault is its own system of record, so the performance evidence is the
head of its signed archive chain:

```python
from algovoi_records_vault import RecordsVault
vault = RecordsVault(...)                 # the live deployment
head = vault.archive_chain_head()         # -> {chain, head, rows, attested_at}
```

If a deployment does not expose a helper, take the last entry of the archive
stream and its `payload_hash` as the head.

## 3. Build the pack

```python
from validation.adapters import collect_standalone_rv
from validation.validation_pack import build_validation_pack
from algovoi_doc_archive import signing

iq, oq, pq = collect_standalone_rv(
    suite_results=suite_results,
    chain_head=head,
    config_paths=["./records_vault.toml"],   # optional fingerprint
    sbom_ref="artifacts/sbom.cdx.json",        # optional
)

pk, sk = signing.load_key_b64(PUBKEY_B64, SECKEY_B64)   # the vault's signing key
build_validation_pack(
    iq=iq, oq=oq, pq=pq,
    public_key=pk, secret_key=sk,
    out_dir="./validation-pack",
    artifact_id="urn:algovoi:validation:records-vault",
    generator="algovoi-records-vault",
)
```

The pack directory now contains the manifest, the three sections, the control
mapping, the public key, and the bundled verifier with VERIFY.md.

## 4. Hand it to the auditor

Zip `validation-pack/` and send it. The auditor needs nothing from AlgoVoi:

```bash
pip install pqcrypto rfc8785
python verify_validation_pack.py .
```

Exit 0 means the manifest signature and every file hash verify, and the auditor
can read the IQ/OQ/PQ summary and the Part 11 / ALCOA+ control coverage straight
from the output.

## 5. Keep it current

Re-run steps 1 to 3 whenever the vault is upgraded or on the validation review
cadence. Each pack is a point-in-time, signed snapshot, so a sequence of packs is
itself a validation history.

## What to tell the customer

- The pack proves installation (IQ), operation (OQ) and production performance
  (PQ) of the system, signed with post-quantum Falcon-1024 and verifiable offline.
- It supports their Part 11 section 11.10(a) and ALCOA+ obligations as the
  records-integrity and validation-evidence layer. It is not, and should not be
  described as, a turnkey electronic-signature (Part 11 Subpart C) system.
