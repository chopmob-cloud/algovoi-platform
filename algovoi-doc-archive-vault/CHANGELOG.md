# Changelog

## 0.1.1
- HashiCorp Vault (transit engine) key custody for the AlgoVoi Verifiable Archive / Records Vault.
  Hold the Falcon-1024 signing key and the ML-KEM encryption key in Vault transit; AlgoVoi holds only
  the transit ciphertext. Each key unwraps via transit only at sign or decrypt time and is zeroized
  after, and the key-encryption-key never leaves Vault. The evidence format is unchanged, so
  verification is unaffected. API: `vault_wrap`, `vault_signer`, `vault_encryptor`.
