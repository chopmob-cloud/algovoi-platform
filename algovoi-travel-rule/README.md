# algovoi-travel-rule

**FATF Travel Rule (Recommendation 16) as signed, no-PII, post-quantum-confidential evidence.**

Every regulated VASP must exchange originator/beneficiary information for crypto transfers above the
de-minimis threshold — and *prove* it did. `algovoi-travel-rule` does both, the AlgoVoi way: the
regulated PII is exchanged **post-quantum** between VASPs, and what you keep is a **Falcon-1024-signed,
content-addressed receipt that contains no PII** and verifies offline.

## What it does
- **Determines applicability** — is a transfer at/above the configured FATF de-minimis (default
  ~$1,000)? The Travel Rule applies, or it doesn't, and the determination is part of the signed record.
- **Exchanges the IVMS101 payload post-quantum** — originator/beneficiary data is sealed to the
  counterparty VASP's **ML-KEM-1024** key (+ AES-256-GCM). Confidential and quantum-resistant in transit.
- **Emits a no-PII Travel Rule receipt** — `Falcon-1024`-signed, `canon_version: jcs-rfc8785-v1`,
  carrying only `ivms101_hash = sha256(JCS(ivms101))`, the VASP DIDs, the threshold determination, and
  the result (`PREPARED / SENT / RECEIVED / ACKNOWLEDGED`). **Binds into the Substrate 2 evidence chain.**
- **Verifies offline** — the issuer public key alone confirms the signature; the beneficiary checks the
  decrypted IVMS101 hashes to the receipt's `ivms101_hash`, binding the PII to the attestation without
  the receipt ever carrying it.

## Why it matters
A signed, no-PII, offline-verifiable Travel Rule receipt is the artifact a regulator or counterparty
wants — proof the obligation was met, with no customer PII to disclose or retain in the evidence, and
post-quantum confidentiality on the wire. It is the **origination + proof side** of the suite's
compliance story, paired with [Compliance Gate](../algovoi-compliance-gate) and
[Proofs](../algovoi-proofs).

## Embed
```python
from algovoi_travel_rule import TravelRule, IVMS101, Person, verify_travel_rule_receipt, signing
from algovoi_travel_rule.encryption import generate_mlkem_keypair

pk, sk = signing.generate_keypair()                      # originating VASP signing key
tr = TravelRule(secret_key=sk, public_key=pk, originating_vasp_did="did:web:vasp.acme")

ivms = IVMS101(originator=Person(name="Alice Smith", account="0x.."),
               beneficiary=Person(name="Bob Jones", account="0x.."))

out = tr.certify(transfer_ref="tx-1", beneficiary_vasp_did="did:web:vasp.beta",
                 amount_minor=250000, currency="USD", ivms101=ivms, result="SENT")
assert verify_travel_rule_receipt(out["receipt_envelope"], pk).verified      # offline

# PQC-seal the PII to the beneficiary VASP, exchange, open, and confirm it matches the receipt:
bpk, bsk = generate_mlkem_keypair()
sealed   = tr.seal_ivms101(ivms101=ivms, beneficiary_mlkem_pubkey=bpk)
received = TravelRule.open_ivms101(sealed_b64=sealed, mlkem_secret=bsk)
```

## Guarantees
- **No PII in the receipt** — only `sha256(JCS(ivms101))`. Verified in the test suite.
- **Post-quantum exchange** — ML-KEM-1024 + AES-256-GCM for the IVMS101 payload; Falcon-1024 receipts.
- **Offline-verifiable** — no service, no callback; issuer public key is sufficient.
- **Free for every Substrate 2 customer** — *any* valid AlgoVoi suite licence unlocks it
  (`ALGOVOI_LICENSE_KEY`); there is no separate Travel-Rule purchase. Still fail-closed without a
  licence, so it stays commercial and non-redistributable — just not separately metered.
- **Bring your own messaging transport** — emits/verifies the evidence; plug into TRP/TRISA/any rail.

## Licence
Commercial — `LicenseRef-AlgoVoi-Commercial-1.0`. **Included free for every AlgoVoi Substrate 2
customer** (any valid suite licence unlocks it). Not open source; not published to public registries.
Contact **chopmob@gmail.com**.
