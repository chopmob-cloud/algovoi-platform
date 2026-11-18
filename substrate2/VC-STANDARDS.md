# Verifiable Credentials in substrate2

**INTERNAL.** How substrate2 expresses its credentials in ratified standards, and the one
line that must never be blurred: **VC 2.0 is ratified, SD-JWT VC is a draft.**

---

## The problem it closes

substrate2's cryptographic primitives are all ratified standards, but its credential
*semantics* were self-authored. The ATB reputation credential is a bespoke Falcon envelope
shaped by `draft-hopley-x402-atb-reputation-credential-00`. To a regulated buyer whose job is
checking conformance to *other people's* standards, a bespoke credential format is a
liability no matter how cryptographically sound it is.

`substrate2.vc` re-expresses the same attested facts in the **W3C Verifiable Credentials Data
Model 2.0**, a W3C Recommendation ratified 2025-05-15. The credential a customer hands their
auditor is now a `VerifiableCredential`, not an AlgoVoi shape.

This replaces two of the twelve `draft-hopley-*` record semantics with a ratified standard,
which is the actual objective of the standards thread — deeper timestamping would not have.

---

## Additive: no digest moves, no signature replaced

This is a **presentation mapping**. `atb_credential.build_atb_envelope_b64` and the Falcon
signature it produces are untouched. A VC is a second view of an already-signed payload,
derived from it, carrying a content-addressed reference (`algovoiEnvelopeRef`) back to the
signed source:

```
credentialSubject.algovoiEnvelopeRef = "sha256:" + SHA-256(JCS(atb_payload))
```

`verify_vc_binding` recomputes that ref, so a VC cannot be re-pointed at a different or
tampered payload than the issuer actually signed. The chain of trust still runs through the
Falcon envelope; the VC references it rather than restating it.

Because nothing that was ever anchored changes, no content hash moves. A test asserts the ATB
envelope hash is identical before and after producing a VC.

---

## The timestamp exception, on purpose

Everywhere else in substrate2, times are **integer milliseconds** (Substrate Rule 2), because
they are folded into content-addressed preimages. VC 2.0 mandates `validFrom` / `validUntil`
as **XSD dateTime strings** (RFC 3339). So `vc.py` deliberately emits string timestamps.

That is correct here and wrong anywhere a ref is computed. The two rules do not conflict —
they govern different artifacts (a VC is not content-addressed). The ATB payload already
carries RFC 3339 `issued_at` / `expires_at`, so the values pass straight through, and an
integer timestamp is rejected rather than silently producing an invalid VC.

---

## Ratified vs draft — the line

| | Standard | Status | May we claim conformance? |
|---|---|---|---|
| `to_vc()` | W3C VC 2.0 Data Model | **Recommendation** (2025-05-15) | **Yes** |
| `secure_vc_jose()` | VC-JOSE-COSE enveloped proof | W3C Recommendation | Yes |
| `to_sd_jwt_vc()` | SD-JWT VC | **Internet-Draft** (`draft-ietf-oauth-sd-jwt-vc-17`) | **No — it is a draft** |

The SD-JWT VC serialisation is built because it is genuinely useful (selective disclosure,
and the pieces already exist: `jws.py` signing, SD-JWT anchoring in `jws_anchor_v1`). But the
whole point of this thread is replacing self-authored drafts with **ratified** standards.
Adopting someone else's unratified draft as if it were settled would repeat the mistake in
other colours. So:

- `to_sd_jwt_vc` is **opt-in**, and its docstring and `SD_JWT_VC_DRAFT` constant name the
  tracked draft.
- Never describe its output as "SD-JWT VC conformant" or "standards-based". It **tracks a
  draft**.
- When the draft becomes an RFC, this table is the one place to update.

The SD-JWT anchoring discipline it relies on IS settled: `jws_anchor_v1` pins that the
issuer-signed JWT (the segment before the first `~`) is the disclosure-invariant anchor.
`sd_jwt_vc_issuer_jwt()` returns exactly that, and a test confirms it is stable across
presentations.

---

## Usage

```python
from substrate2 import vc, atb_credential

payload = atb_credential.decode_payload(envelope_b64)   # the signed ATB facts

# ratified: a conformant VC 2.0 credential
credential = vc.to_vc(payload)
assert vc.is_vc2(credential)
assert vc.verify_vc_binding(credential, payload)         # binds to the signed source

# ratified: secure it as an enveloped EdDSA JWS (same signing base as every other JWS here)
jws_vc = vc.secure_vc_jose(credential, private_key=ed25519_seed)

# DRAFT: SD-JWT VC issuance with selective disclosure
sd_jwt = vc.to_sd_jwt_vc(payload, private_key=ed25519_seed)
anchor = vc.sd_jwt_vc_issuer_jwt(sd_jwt)                  # disclosure-invariant anchor
```

No new dependency — VC output is plain JSON, and signing reuses `substrate2.jws`.

---

## Verify it yourself

```
python -m pytest tests/test_vc.py -q
```

The load-bearing test is `test_binding_fails_against_a_tampered_payload`: a VC asserts nothing
the Falcon envelope did not sign, so it must fail to bind against any changed payload. If that
passes, the VC can never launder an unsigned claim.
