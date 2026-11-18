# rfc9421_hardening_v1 — conformance vectors

Deterministic conformance vectors for the RFC 9421 Hardening Profile: one positive
control plus one negative vector per attack class. Signed with the RFC 8032 §7.1
Ed25519 keypair and a fixed `created`, so the corpus is byte-reproducible and
implementation-neutral.

- `rfc9421_hardening_v1.json` — the vectors (16).
- `generate.py` — regenerates the JSON from the substrate2 signer (deterministic).
- `validate.py` — runs the vectors against any verifier: `python validate.py <json> <module:verify_request>`.
- `run_clean_room.sh` — installs both verifiers from source in a fresh container and validates each.

## Vectors

| id | attack class | control | expect |
|----|--------------|---------|--------|
| positive_baseline | none | RC-8 | valid |
| body_swapped | body binding | RC-2 | reject |
| content_digest_not_covered | body binding | RC-2 | reject |
| duplicate_alg_param | parser strictness | RC-9 | reject |
| duplicate_created_param | parser strictness | RC-9 | reject |
| duplicate_covered_component | parser strictness | RC-9 | reject |
| multiple_signatures | parser strictness | RC-9 | reject |
| label_mismatch | parser strictness | RC-9 | reject |
| noncanonical_base64_signature | malleability | RC-9 | reject |
| missing_alg | algorithm binding | RC-6 | reject |
| disallowed_alg | algorithm binding | RC-6 | reject |
| stale_created | freshness | RC-4 | reject |
| future_created | freshness | RC-4 | reject |
| replayed_nonce | freshness | RC-4 | reject |
| required_component_missing | coverage policy | RC-1 | reject |
| unknown_mode | mode pin | RC-7 | reject |

The corpus asserts the **verdict** (accept / reject). The rejection *layer* is
implementation-specific: because both reference verifiers sign the
`@signature-params` block verbatim, a post-signing tamper of `Signature-Input`
is caught either at the parser (defense in depth) or at signature verification —
both give the same verdict. `validate.py` reports that difference as advisory
"reason drift", never a failure.

## Clean-room cross-implementation result

Run on VM2 (Fasthosts clean-room box) in a fresh `python:3.11-slim` container,
both verifiers pip-installed from source with `--no-cache-dir`:

```
substrate2 2.0.0                : 16/16 supported matched, 0 unsupported, 0 failed
algovoi-rfc9421-verifier 0.4.2  : 15/15 supported matched, 1 unsupported, 0 failed  (before RC-1 fix)
algovoi-rfc9421-verifier + RC-1 : 16/16 supported matched, 0 unsupported, 0 failed  (after RC-1 fix, PR #2)
```

**Verdict parity holds on every vector both implementations support**, and after the
RC-1 fix both implementations reach full 16/16 parity.

Findings surfaced by the run:

1. **substrate2 gap (now fixed):** `noncanonical_base64_signature` initially
   verified as valid on substrate2 — it decoded non-canonical base64 (validate=True
   checks the alphabet, not the pad bits). Fixed by adding the canonical round-trip
   check in `parse_signature_value`, matching the standalone package. Regression
   test: `tests/test_rfc9421_parser_hardening.py::test_noncanonical_base64_rejected`.

2. **standalone gap (RESOLVED):** `required_component_missing` was UNSUPPORTED on
   `algovoi-rfc9421-verifier` 0.4.2 — it had no `required_components` policy hook
   (RC-1), so a cryptographically valid signature over a narrow covered set was
   accepted. Ported to the standalone package in
   [PR #2](https://github.com/chopmob-cloud/algovoi-rfc9421-verifier/pull/2); the
   package now passes the vector and both implementations reach 16/16.

3. **defense-in-depth divergence (advisory):** the standalone package rejects the
   parser-strictness vectors at signature verification (or alg-not-allowed) rather
   than at parse. Verdict is correct; adding explicit duplicate/multi-signature
   rejection would make it fail closed earlier and independently of the signature
   check.

## Reproduce

```bash
# regenerate (deterministic)
PYTHONPATH=../../src python generate.py rfc9421_hardening_v1.json
# validate against the hardened substrate2 verifier
PYTHONPATH=../../src python validate.py rfc9421_hardening_v1.json substrate2.rfc9421_verifier:verify_request
```
