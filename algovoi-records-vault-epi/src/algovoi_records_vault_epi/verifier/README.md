# Verify this `.epi` evidence — yourself, offline

You've been given an AlgoVoi **`.epi`** artifact — a portable, tamper-evident package of compliance
evidence — and this verifier so you can confirm it is **genuine and unaltered without trusting AlgoVoi
or the party who gave it to you.** No AlgoVoi software, service, account, or network is involved.

## 1. Install the two public dependencies

```bash
pip install pqcrypto rfc8785
```

That is the entire trust base: `pqcrypto` (post-quantum Falcon-1024 signature verification) and
`rfc8785` (RFC 8785 / JCS canonicalization). No AlgoVoi code takes part in verification.

## 2. Run the verifier against the `.epi` folder

```bash
python epi_verify.py path/to/the/.epi-folder
```

## 3. Read the result

```
  [PASS] Structure valid   manifest.json + steps.jsonl + public_key.b64
  [PASS] Hashes match       4 files
  [PASS] Signature valid    falcon1024 / kid 8bd26d25651adb39
  [PASS] Chain intact       12 steps linked
  [PASS] Anchored           not anchored (optional)
RESULT: .epi VERIFIED
```

- **`.epi VERIFIED`** — every file matches its recorded hash, the manifest carries a valid
  **Falcon-1024 (post-quantum)** signature from the key embedded in the artifact, and the event log is
  an unbroken hash-linked chain. The evidence is authentic and has not been altered.
- **Any `[FAIL]` / `.epi VERIFICATION FAILED`** — the artifact has been changed, is incomplete, or was
  not signed by the key it claims. Treat it as untrustworthy and ask the provider.

Exit code is `0` only if the artifact verifies — so it can be wired into an automated check.

## What it proves (and what it doesn't)

It proves the artifact's **integrity and origin**: these exact files, signed by this key, unchanged.
It does not, by itself, tell you *who* controls that key — confirm the signing key's identity through
your normal channel with the party who issued the evidence.

---
*Licensed redistributable verifier — see `LICENSE.txt`. You may pass this verifier on, unmodified,
alongside the `.epi` artifacts it checks.*
