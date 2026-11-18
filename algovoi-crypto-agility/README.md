# algovoi-crypto-agility

**Migrate a signing + encryption estate classical -> post-quantum, with provable continuity.**

The hard part of post-quantum adoption is not the primitive, it is the migration: a corpus of artifacts
signed under a legacy (quantum-vulnerable) key must stay trustable after you rotate to a PQC key.
`algovoi-crypto-agility` re-attests each legacy-signed artifact forward under **Falcon-1024** and emits a
signed migration attestation, so past evidence stays verifiable once the legacy key is retired. It also
hybrid-signs during the transition window and re-wraps encrypted data to **ML-KEM-1024**.

## What it does
- **Classifies your estate.** Label every key against the post-quantum transition (`classical` /
  `post-quantum` / `hybrid`), flag what is `quantum_vulnerable`, and list the active keys that still need
  migrating.
- **Re-attests signatures forward (continuity).** Verify a legacy signature (Ed25519 built in, others out
  of band), then emit a `Falcon-1024`-signed migration attestation binding `{legacy alg + kid, content
  hash, new PQC kid, migrated_at}`. Past evidence stays trustable without the legacy key.
- **Hybrid-signs the transition window.** Sign under the new PQC key while carrying a legacy signature
  alongside, so verifiers on either side keep working until everyone has cut over.
- **Re-wraps encryption to PQC.** Re-encrypt data from a classical KEM to ML-KEM-1024 and emit a re-wrap
  attestation that records only the content hash and the old/new key ids -- never the plaintext.
- **Verifies offline.** Every attestation is content-addressed (`canon_version: jcs-rfc8785-v1`) and
  checks from the authority's PQC public key alone. Binds into the Substrate 2 evidence chain.

## Why it matters
"We are PQC-ready" is table stakes; "we migrate your estate to PQC and prove the old evidence still
holds" is the differentiator. This is the tool that turns a risky, all-at-once key rotation into a
staged, attested, offline-verifiable migration -- the piece most PQC stories are missing.

## Embed
```python
from algovoi_crypto_agility import (CryptoAgility, classify, verify_legacy_ed25519,
                                     verify_migration_attestation, signing)

pk, sk = signing.generate_keypair()                       # the NEW post-quantum authority key
ca = CryptoAgility(secret_key=sk, public_key=pk, authority_did="did:web:acme")

classify("Ed25519").quantum_vulnerable        # True
classify("ML-KEM-1024").quantum_vulnerable    # False

# verify a legacy Ed25519 signature, then re-attest the artifact forward under PQC:
ok  = verify_legacy_ed25519(message=msg, signature=legacy_sig, public_key=legacy_pk)
out = ca.migrate_signature(content_hash="sha256:...", legacy_alg="Ed25519",
                           legacy_kid="old-1", legacy_signature_verified=ok)
assert verify_migration_attestation(out["attestation_envelope"], pk).verified   # offline
```

## Guarantees
- **Continuity, not breakage** -- legacy-signed evidence stays trustable via a PQC-signed attestation.
- **No plaintext in re-wrap receipts** -- only `sha256` of the content and the old/new key ids.
- **Offline-verifiable** -- the authority PQC public key is sufficient; no service, no callback.
- **Free for every Substrate 2 customer** -- any valid AlgoVoi suite licence unlocks it; fail-closed
  without one, so it stays commercial and non-redistributable, just not separately metered.

## Licence
Commercial -- `LicenseRef-AlgoVoi-Commercial-1.0`. **Included free for every AlgoVoi Substrate 2
customer.** Not open source; not published to public registries. Contact **chopmob@gmail.com**.
