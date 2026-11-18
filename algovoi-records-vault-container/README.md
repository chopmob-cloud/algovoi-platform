# algovoi-records-vault-container

Sealed, portable, post-quantum **encrypted records containers** (`.acv`) for
[AlgoVoi Records Vault](https://docs.algovoi.co.uk/records-vault), with **create and revoke from the
Compliance Command Center**.

Licensed product (runtime-enforced, fail-closed). Not open source.

## What it does

Take a set of records and seal them into one movable, self-contained encrypted file that only a named
recipient can open, offline, with no AlgoVoi software:

- **ML-KEM-1024 to a named recipient** — the AES-256 content key is wrapped to the recipient's
  post-quantum public key, so only that recipient's secret opens the container.
- **AES-256-GCM content**, bound to a **Falcon-1024-signed header** (the header is verified before
  anything is decrypted; the ciphertext cannot be paired with a different header).
- **Offline revocation** — the issuer publishes a Falcon-signed revocation list; the recipient's
  extractor refuses to open a revoked (or, when required, an uncovered) container.
- **Key-loss recovery (Shamir k-of-n)** — optionally split the content key into `n` custodian shares at
  seal time; any `k` reconstruct it and open the container even if the recipient's ML-KEM secret is lost.
  Reuses the audited SLIP-39 recovery primitive; revocation is still enforced on the recovery path.
- **Offline extractor** (`acv_unseal.py`) that imports no AlgoVoi packages, only `pqcrypto`, `rfc8785`,
  `cryptography` (and `shamir-mnemonic` for the recovery path).

## Seal and open

```python
from algovoi_records_vault_container import seal_from_archive, open_container

# seal selected records straight out of a Records Vault archive, to a recipient's ML-KEM public key
await seal_from_archive(archive, doc_hashes, recipient_public_key=recipient_pk,
                        issuer_public_key=issuer_pk, issuer_secret_key=issuer_sk,
                        container_id="acv-2026-0007", out_path="disclosure.acv")

# recipient side, fully offline
header, docs = open_container("disclosure.acv", recipient_secret_key=recipient_sk, crl_env=signed_crl)
```

Or from the shell, on the recipient's machine:

```bash
python acv_unseal.py --key @recipient_sk.b64 --revocation-list @crl.txt --out ./unsealed disclosure.acv
```

## Create and revoke from the Command Center

The Compliance Command Center drives a `ContainerRegistry` signed by the console key:

- **Create** — `POST /v1/containers` (or the console panel at `/containers`): seal a set of documents to
  a recipient public key and record the issuance.
- **Revoke** — `POST /v1/containers/{id}/revoke` (or the panel's Revoke button): mark it revoked; the
  updated signed revocation list at `GET /v1/containers/crl` then refuses that container everywhere.
- **Posture** — issued / active / revoked counts, recomputed from the signed registry.

## Licence

Commercial add-on to Records Vault. Requires a valid AlgoVoi licence (the on-prem bundle licence or a
standalone key); set `ALGOVOI_LICENSE_KEY` (or `ALGOVOI_LICENSE_FILE`). Fail-closed: no valid licence, no
sealing.
