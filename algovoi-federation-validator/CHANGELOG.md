# Changelog

## 0.1.0 — 2026-06-03

Initial release.

- `FederationValidator` — compose independent PQC credentials without shared trust root
- `verify_pqc_credential()` — Falcon-1024 sig + Bulletproofs field shape check
- `compose_commitments()` — domain-separated SHA-256 commitment composition
- `issue_federation_token()` / `verify_federation_token()` — HMAC-SHA256 token lifecycle
- Full test suite (structural, no Falcon extras required for most tests)
- IETF anchors: `draft-hopley-x402-pqc-credential-binding-00`,
  `draft-hopley-x402-federation-zkp-00`
