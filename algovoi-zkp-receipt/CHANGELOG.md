# Changelog

## 0.1.0 — 2026-06-03

Initial release.

- `build_zkp_receipt_payload()` — construct unsigned ZKP receipt payload
- `verify_zkp_receipt()` — Falcon-1024 sig + ZKP field structural verification
- `PaymentReceipt`, `ZkpReceiptEnvelope`, `ZkpReceiptVerifyResult` models
- IETF anchor: `draft-hopley-x402-pqc-credential-binding-00`
- v0.2 will add payment-bound Bulletproofs transcript domain separation
