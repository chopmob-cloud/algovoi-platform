# Changelog

## 0.1.0
- Initial release. `export_epi(...)` emits a Records Vault evidence set as a portable `.epi` artifact
  (the AlgoVoi Falcon-1024 post-quantum profile of the `.epi` compliance-evidence format):
  `manifest.json`, a hash-linked `steps.jsonl`, `control_mapping.json`, and `verification.md`, signed
  with Falcon-1024 over the RFC 8785 (JCS) manifest bytes.
- Ships a redistributable offline verifier (`verifier/epi_verify.py`) that a buyer can hand to auditors
  or counterparties. It checks structure, file hashes, Falcon-1024 signature, and the step chain on the
  public `pqcrypto` + `rfc8785` libraries only, with no AlgoVoi software or service. Runtime licence
  enforced, fail-closed.
