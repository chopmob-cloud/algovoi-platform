# PR draft — algovoi-jcs-conformance-vectors  (branch `epi-pqc-v0` → `main`)

> Review before pushing. Branch committed locally as `2c17377` (unpushed). No AI trailer.

## Title
Add `epi_pqc_v0`: proposed PQC signature profile for `.epi` (AGT Discussion #806)

## Summary
A **single-implementation proposal set** companion to `epi_interop_v0`. Where `epi_interop_v0` pins the
JCS canonicalisation `.epi` and AlgoVoi agree on, `epi_pqc_v0` pins an **optional post-quantum signature
suite** (`falcon1024`, NIST FIPS 206 FN-DSA) + an **F7 cross-signed key-lineage**, on top of the same
canonicalisation.

**Rationale:** `.epi` targets decades-long audit but seals with classical **Ed25519**; this proposes a
post-quantum suite + lineage continuity so artefacts stay verifiable past the PQC migration. Ed25519
stays the `.epi` default — interop, not replacement.

## Contents
- `vectors/epi_pqc_v0/epi_pqc_v0.json` — 4 JCS canon vectors (same fields as `epi_interop_v0`) + a
  `signature_suite_anchor` (Falcon-1024 over the canonical manifest, with public key) + a
  `key_lineage_anchor` (k1→k2→k3 cross-signed rotation).
- `vectors/epi_pqc_v0/runner_python.py` — standalone (`rfc8785` + `pqcrypto`, zero AlgoVoi deps).
- `vectors/epi_pqc_v0/README.md` — scope + the timestamp boundary (same as `epi_interop_v0`).
- `manifest.json` — bumped to `0.7.0`; new **`proposal_sets`** section (NOT folded into the conformance
  or interop totals — proposal = single-impl, not externally cross-validated).

## Validation
`cd vectors/epi_pqc_v0 && python runner_python.py` → **7/7 reproduce** (4 JCS + 1 signature anchor + 2
lineage proofs).

## Honesty notes (kept explicit)
- Marked **PROPOSED**, single-impl, not cross-validated — separate `proposal_sets`, distinct from the
  8-impl conformance totals and the 2-impl interop totals.
- Canonicalisation anchored to `draft-hopley-x402-canonicalisation-jcs-v1`; `timestamp_encoding`
  declared per vector (ISO-8601 string boundary, same as `epi_interop_v0`).
- No private keys in the fixture; only public keys + signatures.
