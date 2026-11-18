# AlgoVoi ↔ `.epi` field mapping (PQC profile)

Mapping of AlgoVoi Verifiable Archive / Records Vault evidence onto the `.epi` portable-evidence format
(microsoft/agent-governance-toolkit Discussion #806; epilabs.org). The structures align almost 1:1; the
only addition is an **optional post-quantum signature suite**. This answers the discussion's feedback
ask #1 (field-level mapping) and #4 (external vs adapter — this is an *external optional profile*, no AGT
runtime change).

## Container / structure

| `.epi` element | AlgoVoi equivalent | Notes |
|---|---|---|
| `manifest.json` (`sha256`, `files`, `signature`) | the evidence-pack `MANIFEST.json` (per-file sha256) + a signed manifest | identical intent; we sign the manifest's JCS bytes |
| `steps.jsonl` (hash-linked, `← prev`) | any `_VaultStream` (`prev_entry_hash` link) flattened to a step timeline | both are SHA-256 hash-linked append-only chains |
| `signature: ed25519:prod:…` | Falcon-1024 envelope → `signature: falcon1024:<kid>:<b64url>` | **PQC profile delta** (see below) |
| DID:WEB identity | `issuer_did: did:web:…` (already used) | same scheme |
| SHA-256 hashing | SHA-256 throughout | same |
| JCS (RFC 8785) canonicalization | RFC 8785 via `rfc8785` | same — AlgoVoi maintains the JCS conformance vectors |
| `artifacts/sbom/` (CycloneDX) | `artifacts/` (extensible) | compatible; SBOM optional |
| COSE Sign1 + SCITT anchoring | optional `scitt_receipt` field | AlgoVoi can anchor identically |

## Evidence-stream → control mapping (`control_mapping.json`)

| AlgoVoi stream | Framework | Requirement | What it evidences |
|---|---|---|---|
| `access` (F3) | HIPAA | §164.312(b) | record/examine access (audit controls) |
| `consent` (F5) | HIPAA / GDPR | §164.508 / Art.6 | authorization / lawful basis |
| `holds` (F2) | FRCP / GDPR | 37(e) / Art.17(3)(e) | litigation hold overrides erasure |
| `tsa` (F1) | eIDAS | Art.42 | qualified electronic time stamp |
| `custody` (F6) | FRCP | chain-of-custody | unbroken custody for admissibility |
| `keyring` (F7) | ETSI / NIST | key lifecycle | long-horizon key validity + rotation |
| `redaction` (F4) | GDPR / HIPAA | Art.5(1)(c) / min-necessary | data minimisation on disclosure |
| `acl` (F8) | ISO 27001 | A.9 | access control to records |

## The PQC profile delta (the contribution)

`.epi` targets **decades-long** audit windows but seals with **Ed25519 (classical)** — evidence signed
that way is not safe against a future quantum adversary. The profile adds, *without changing any other
semantics*:

1. **Signature suite `falcon1024`** — `signature: "falcon1024:<kid>:<b64url-sig>"`, Falcon-1024 (NIST
   FN-DSA) over the JCS bytes of the manifest with its `signature` field removed. Ed25519 stays the
   default; this is an opt-in suite (interop, not replacement).
2. **`key_lineage` block (F7)** — cross-signed rotation proofs (old key authorises new, new
   counter-signs) + published validity windows, so a verifier can validate an artifact whose signing key
   was retired years ago. This is what makes `.epi` actually verifiable across the PQC migration.

## The five checks (unchanged)

| `.epi` check | AlgoVoi free verifier (`algovoi_verify.py epi`) |
|---|---|
| Structure valid | manifest + steps.jsonl + public_key present and parse |
| Hashes match | each `files[*].sha256` recomputed |
| Signature valid | Falcon-1024 (or Ed25519) over JCS(manifest sans signature) |
| Chain intact | `steps.jsonl` `prev` links + `steps_head` |
| SCITT anchored | optional `scitt_receipt` |

Reference implementation: `algovoi_verify.py` — ~200 lines, **zero AlgoVoi dependencies** (only
`pqcrypto` + `rfc8785`); proves the profile is independently verifiable, matching the `.epi` goal of
no-trust, no-service verification.
