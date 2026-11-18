<!-- Post to: https://github.com/microsoft/agent-governance-toolkit/discussions/806  (new comment, under chopmob-cloud) -->

Thanks for driving this.

One gap stands out for the long-term audit `.epi` is built for: artefacts are sealed with **Ed25519**. That's fine today, but evidence meant to stay verifiable for *decades* needs a signature — and a key — that survive the post-quantum migration.

Proposing a small, **optional** extension (the default doesn't change):

**1. A post-quantum signature suite** — one more `signature_suite`: `signature: "falcon1024:<kid>:<b64url-sig>"` (Falcon-1024 over the JCS bytes of the manifest). Ed25519 stays the default; this is opt-in.

**2. Key-lineage** — a cross-signed rotation block (old key authorises the new key, new key counter-signs) so a verifier can validate an artefact whose signing key was retired years earlier.

Published as a runnable fixture — **`epi_pqc_v0`**: https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors/tree/main/vectors/epi_pqc_v0 (4 JCS canon vectors + a `falcon1024` signature anchor + a 2-step key-lineage; standalone runner, `rfc8785` + `pqcrypto`, zero other deps). Marked **proposed / optional**, kept out of the cross-validated totals.

Happy to map the fields onto the `.epi` `manifest.json` / `steps.jsonl` if useful, or leave it as an optional profile — your call on where the boundary sits.

---
<sub>Built on **AlgoVoi Substrate 2** — post-quantum evidence for agentic systems · **[Adopt the Substrate →](https://docs.algovoi.co.uk/substrate-2)**</sub>
