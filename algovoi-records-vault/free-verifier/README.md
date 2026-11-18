# AlgoVoi Free Verifier

**Don't trust AlgoVoi — verify it yourself.**

A single, self-contained tool that checks any AlgoVoi signed receipt, evidence chain, evidence pack, or
key-rotation lineage — **offline, from the published public key alone**. It contains *no AlgoVoi code*.
Its entire trust base is two public, audited-primitive libraries:

```bash
pip install pqcrypto rfc8785
```

## Use it

```bash
# a full evidence pack (the bundle a Records Vault / Verifiable Archive deployment exports)
python algovoi_verify.py pack ./evidence-pack/ <expected_kid>

# one signed receipt
python algovoi_verify.py receipt receipt.txt public_key.b64

# a signed-chain stream (JSON array of envelopes)
python algovoi_verify.py chain access_chain.json public_key.b64

# a key-rotation lineage (F7 — proves a decades-old key was legitimately succeeded)
python algovoi_verify.py keys rotation_proofs.json <genesis_kid>
```

### Anchor the key, or you only get integrity

A pack, a `.epi` and a key lineage carry the signing public key **inside the artifact**. Re-deriving
their signatures proves the artifact is internally consistent and unaltered; it does not prove *who*
signed it, because anyone can generate a keypair and build a fabricated pack that is internally
perfect. That last step is out-of-band, exactly as it is for any signer including X.509: take the
`kid` fingerprint published at `https://api.algovoi.co.uk`, and pass it as `<expected_kid>`.

A receipt or chain has no such gap: you supply the public key yourself, so it is anchored by
construction.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | every signature and hash-link re-derived **and** the key matched the kid you pinned |
| `1` | verification failed: bad signature, broken chain, or the kid did not match |
| `2` | usage error, or the artifact was not recognised |
| `3` | cryptographically intact, but the key is self-asserted — you passed no expected kid |

Change a single byte of any receipt and it fails at exactly that entry. Treat `3` as "not yet
evidence": it is the correct result for a pack you have not anchored, and it must never be scripted
as success.

## Why this exists

Evidence is only as good as your ability to check it **without** trusting the vendor. This verifier is
~150 lines you can read in full; it never calls home, never needs a secret key, and never needs an
AlgoVoi service running. Use it to satisfy an auditor, a court, or your own security team that an
AlgoVoi receipt is genuine and unaltered — years after it was signed, into the post-quantum era.

> Free to use and redistribute. It verifies the integrity of AlgoVoi evidence; it does not create it.
> The signing/sealing engine is the commercial [Verifiable Archive](https://docs.algovoi.co.uk/verifiable-archive)
> / [Records Vault](https://docs.algovoi.co.uk/records-vault).
