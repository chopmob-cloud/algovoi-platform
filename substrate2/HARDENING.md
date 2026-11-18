# RFC 9421 verifier — hardening profile status

This records how `substrate2.rfc9421_verifier` implements the RFC 9421 Hardening
Profile controls, and where a control is deliberately the integrator's or a
roadmap item. A control is only "enforced" when a test demonstrates the PASS
criterion in `tests/`.

Companion signer: `substrate2.httpsig`. Verdict-parity source for the ported
suites: `algovoi-rfc9421-verifier`.

## Control status

| ID | Control | Status | Where | Tests |
|----|---------|--------|-------|-------|
| RC-1 | Request-line / covered-component completeness | Enforced (opt-in) | `verify_request(required_components=...)` | `test_rfc9421_parser_hardening.py` |
| RC-2 | Body binding (content-digest covered + verifies) | Enforced (default on) | `verify_request(require_content_digest=True)` | `test_rfc9421_freshness.py`, conformance |
| RC-3 | Query coverage (`@query` / `@query-param`) | Roadmap | derived component not yet supported | — |
| RC-4 | Freshness + single-use nonce | Enforced (caller sets window/store) | `freshness.py`, `nonce_seen` callback | `test_rfc9421_freshness.py` |
| RC-5 | Key pinning + resolution SSRF safety | Integrator | caller supplies `public_key`; no key fetch in-library | — |
| RC-6 | Algorithm binding (no wire-trusted `alg`) | Enforced | `verify_request` alg allow-list, missing-alg rejected | `test_rfc9421_alg_hardening.py` |
| RC-7 | Signing-base mode pin | Enforced | `mode` validated against `{rfc9421, algovoi-v0}` | `test_rfc9421_parser_hardening.py` |
| RC-8 | Canonical signing-base parity | Enforced | fixtures `FIXTURE_SIGNING_BASE_*`, cross-impl vectors | conformance suite |
| RC-9 | Parser strictness | Enforced | `parse_signature_input` / `parse_signature_value` | `test_rfc9421_parser_hardening.py` |
| RC-10 | Enforcement, not advisory | Integrator | deployment must deny on `valid == False` | gateway policy |
| RC-11 | ECDSA low-s malleability | Roadmap (inert) | Ed25519-only today; non-malleable by construction | — |

## What RC-9 now rejects

Added on top of the existing freshness/alg/tag hardening:

- **Duplicate parameters** in `Signature-Input` (e.g. two `created`, two `alg`) —
  a last-wins ambiguity and downgrade vector. Rejected, not overwritten.
- **Duplicate covered components** (RFC 9421 §2.1: a component MUST NOT appear
  more than once) — makes the signing base ambiguous.
- **Multiple signatures** in one `Signature-Input` — the verifier refuses to
  silently pick one when an attacker can append a second it controls. Detected by
  a quote-aware, bracket-depth scan (`_count_top_level_component_lists`), so a
  `(` inside a quoted parameter value does not cause a false positive.
- **`Signature` vs `Signature-Input` label mismatch** — the label is not part of
  the signing base, so a valid signature under a swapped label would still verify
  cryptographically; the cross-check blocks that confusion. The lenient
  unlabelled `Signature-Input` form is covered by the single-signature guard.
- **Non-alphabet base64** in the `Signature` value (`validate=True`), which also
  turns a multi-member `Signature` header into an error rather than a truncated
  decode.
- **Non-canonical base64** (non-zero pad bits): the canonical encoding must
  round-trip exactly, else many distinct header strings decode to the same
  signature bytes (signature-string malleability that breaks any replay/idempotency
  key derived from the raw header). Added after `rfc9421_hardening_v1` surfaced the
  gap against the standalone package. Test: `test_noncanonical_base64_rejected`.

## Conformance vectors

`vectors/rfc9421_hardening_v1/` holds a deterministic vector set (16 vectors, one
positive control + one per attack class) plus `validate.py` and a clean-room
runner. It was validated cross-implementation on VM2 in a fresh `python:3.11-slim`
container against both this verifier (16/16) and the standalone
`algovoi-rfc9421-verifier` 0.4.2 (15/15 supported; `required_components` / RC-1 was
not a param there). RC-1 has since been ported to the standalone package
(chopmob-cloud/algovoi-rfc9421-verifier PR #2), bringing both implementations to
full 16/16 parity. See that folder's README for the parity matrix and findings.

## Caller policy hooks (RC-1, RC-4, RC-7)

The library stays stateless and mode-pinned by the caller. To grade a deployment
as "not bypassable", the integrator supplies:

```python
verify_request(
    ...,
    mode="rfc9421",                                   # RC-7: pin the base
    require_content_digest=True,                       # RC-2
    required_components=["@method", "@authority", "@path"],  # RC-1
    require_created=True, max_age_seconds=300,          # RC-4 freshness window
    nonce_seen=store.seen,                              # RC-4 single-use nonce
    allowed_algorithms={"ed25519"},                    # RC-6
)
```

## Adversarial checks performed

Beyond the unit tests, the guards were exercised against: quoted-paren false
positives, appended second-signature injection, label-swap replay with unchanged
signature bytes, duplicate-`alg` downgrade, and nonce replay — all fail closed.

## Not in library scope (by design)

- **RC-5 key resolution / SSRF**: the verifier takes a pinned `public_key`. DID /
  `jku` resolution, allow-listing, and internal-range refusal belong to the
  integrator's key resolver.
- **RC-10 enforcement**: the library returns a `VerifyResult`; denying on failure
  is the calling route's responsibility.
- **RC-3, RC-11**: roadmap. Adding `@query` support and enabling ECDSA-P256 each
  require their own conformance vectors (query coverage; high-`s` rejection scoped
  to the ECDSA path only) before they can be marked enforced.
