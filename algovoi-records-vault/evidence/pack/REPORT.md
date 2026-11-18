# AlgoVoi Records Vault — Evidence Pack

This pack is **public evidence** that AlgoVoi Records Vault does what it claims. Every artifact below
was produced by the real product code and is **independently verifiable offline** — with only the
published public key and two standard libraries, no AlgoVoi software, no secret key, and no running
service. Run `python verify_evidence_pack.py` to confirm it yourself.

- **Signature:** Falcon-1024 (FN-DSA-1024, NIST Level 5)
- **Encryption at rest:** ML-KEM-1024 + AES-256-GCM
- **Canonicalization:** RFC 8785 (JCS)
- **Archive identity (kid):** `8bd26d25651adb39`
- **Demonstration record hash:** `sha256:a70ac8c528a04eee0a58326eb8b1ac8f8049f4fae94cabbe70ea768324af1e7c`

## What each chain proves

| Artifact | Capability | Entries | What a verifier confirms |
|---|---|---|---|
| `archive_chain.json` | Tamper-evident archive | 1 | The record was notarized into a Falcon-signed, hash-linked chain — unaltered, ordered, not back-dated. |
| `tsa_chain.json` | **F1** RFC-3161 timestamping | 1 | The record's hash is bound to a trusted-timestamp record; its messageImprint equals the receipt hash. |
| `access_chain.json` | **F3** read-access audit log | 2 | Every read (granted *and* denied) is sealed as a signed event — who, what, why — tamper-evidently. |
| `holds_chain.json` | **F2** legal / e-discovery hold | 1 | A litigation hold on the matter is recorded as signed evidence; it overrides routine disposal. |
| `record_blob.bin` | Encryption at rest | — | 1671 bytes of ML-KEM-1024 + AES-256-GCM ciphertext. **Included but unreadable** — no key is in this pack, yet everything above still verifies. |

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
