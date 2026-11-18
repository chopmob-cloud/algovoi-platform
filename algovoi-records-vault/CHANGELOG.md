# Changelog

## 0.5.0
- Suite bundle licence support: a single AlgoVoi Substrate 2 on-prem bundle licence now unlocks Records
  Vault as part of the whole suite, in addition to the standalone Records Vault OEM licence. Still
  fail-closed with no licence at all.

## 0.4.x
- Hardened commercial release: runtime licence enforcement (fail-closed), plus packaging for the
  token-gated private index and a verified air-gapped install.

## 0.2.0 and earlier
- Regulated-records preservation on the AlgoVoi PQC Verifiable Archive. `migrate` in bridge mode
  (notarize content hashes without moving bytes) or store mode (pull, ML-KEM-encrypt, store),
  idempotent and content-addressed. Falcon-1024-signed `reconcile` / `sign_manifest` /
  `verify_manifest` proving the migrated set is complete, and `detect_drift` for bridged records whose
  source changed after notarisation.
- Eight offline-verifiable signed streams: RFC 3161 timestamps, read-access log, legal hold, consent
  receipts, custody manifest, key-rotation lineage, ACL grants, and redaction / crypto-shred ledger.
  Health and Legal editions, plus a zero-dependency public verifier. No cryptography is reimplemented
  in this package; it composes `algovoi-doc-archive`.
