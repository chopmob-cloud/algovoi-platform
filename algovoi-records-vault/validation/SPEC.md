# System Validation Evidence Pack, specification and design

## What it is

A small, signed, offline-verifiable artifact that proves a deployed AlgoVoi
system was installed correctly, operates to specification, and performs in
production. It is the free, control-plane-standard answer to computerised-system
validation: the evidence a regulated customer would otherwise commission as a
manual IQ/OQ/PQ project is instead generated and signed by the system itself,
kept current, and checkable by anyone with two public libraries and the
published public key.

It reuses, byte for byte, the Records Vault `.epi` evidence-pack pattern: a
`manifest.json` whose per-file SHA-256 hashes are committed by a Falcon-1024
signature over the RFC 8785 (JCS) canonical bytes of the manifest with its own
`signature` field removed. Tamper with any file and its hash stops matching the
manifest. Tamper with the manifest and the signature stops verifying.

## The three sections

| Section | Question | Contents |
|---|---|---|
| **IQ** installation qualification | installed as specified? | component versions, optional CycloneDX SBOM reference, configuration fingerprint, install time |
| **OQ** operational qualification | operates to specification? | test and conformance suite results: name, total, passed, failed, run time, signed result digest |
| **PQ** performance qualification | performs in production? | the head of the tamper-evident integrity-attestation chain: chain name, head hash, row count, attestation time |

## Pack layout

```
validation-pack/
  manifest.json              signed: schema, kid, per-file sha256, signature suite:kid:b64url
  iq.json                    installation qualification
  oq.json                    operational qualification
  pq.json                    performance qualification
  control_mapping.json       which control each section evidences (Part 11, ALCOA+, SOC 2)
  public_key.b64             the published Falcon-1024 public key
  verify_validation_pack.py  the standalone offline verifier (bundled)
  VERIFY.md                  how an auditor verifies, in three lines
```

## Trust and security properties

- **Offline.** Verification needs only `pqcrypto`, `rfc8785` and the public key.
  No AlgoVoi code, no secret key, no running service, no network.
- **Post-quantum.** Falcon-1024 (NIST FN-DSA) so the evidence outlives the
  classical-signature safety margin across multi-year retention.
- **Canonical.** RFC 8785 means the signed bytes are reconstructible by the
  verifier from the manifest's logical content, independent of serialisation.
- **Tamper-evident.** Proven by the self-test: an edited section is caught on the
  file hash, an edited manifest is caught on the signature.

## Module layout

```
validation/
  validation_pack.py          build_validation_pack(...) -> manifest   (the collector)
  verify_validation_pack.py   the standalone verifier (also bundled into each pack)
  adapters.py                 collect_standalone_rv(...) / collect_control_plane(...)
  selftest.py                 builds, verifies, and proves tamper detection
  SPEC.md / HOWTO-*.md        this spec and the two integration guides
```

## Design choices

- The collector signs with `algovoi_doc_archive.signing` (it holds the key); the
  verifier depends on nothing AlgoVoi. Collection happens inside the product,
  verification happens anywhere. This is the same split as the `.epi` and the
  Records Vault free verifier.
- The adapters are thin and take the live values (suite results, attestation
  head) as arguments rather than reaching into a specific runtime, so the same
  collector serves both the control plane and a standalone vault. Where each live
  value comes from is documented in the two HOWTO files.
- `control_mapping.json` is per-vertical. The default targets pharma 21 CFR
  Part 11 section 11.10(a) and ALCOA+; swap it for SOC 2, EU AI Act Article 12,
  or another framework without touching the evidence.
