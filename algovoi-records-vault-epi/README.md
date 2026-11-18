# algovoi-records-vault-epi — `.epi` portable-evidence export add-on

A **commercial add-on** to [AlgoVoi Records Vault](https://docs.algovoi.co.uk/records-vault). It
exports a Records Vault evidence set as a portable **`.epi`** artifact — the AlgoVoi post-quantum
(Falcon-1024) profile of the `.epi` compliance-evidence format — that a third party can verify
**offline, with no AlgoVoi software or service**.

Licensed product (runtime-enforced, fail-closed). Not open source — see `LICENSE.md`.

## What you get
- **`export_epi(...)`** — emit a `.epi` artifact (`manifest.json` + hash-linked `steps.jsonl` +
  `control_mapping.json` + `verification.md`), Falcon-1024-signed.
- **A redistributable verifier** at `algovoi_records_vault_epi/verifier/` (`epi_verify.py` + its
  licence + a recipient README). You may pass this to your auditors / counterparties so they can
  verify a `.epi` artifact you hand them — offline, on the public `pqcrypto` + `rfc8785` libraries
  only. See `verifier/LICENSE.txt` for the redistribution terms.

## Licence
Requires a valid AlgoVoi `.epi` export add-on licence (on top of a Records Vault licence). Provide it
via `ALGOVOI_LICENSE_KEY` or `ALGOVOI_LICENSE_FILE`; enforced offline at export time.
