# AlgoVoi ↔ Asqav — Integration Option

> **Status: DRAFT — nothing posted, nothing pushed.** Read-only verification done; all
> outward actions (the note to jagmarques, the corpus push, any spec text) are held pending
> founder go. **DISTRIBUTION-ONLY mode is active:** Tier 1 + outreach qualify as
> outbound/collateral; **Tier 2 (binding-fix build) needs explicit founder override.**
>
> Author worked from local data only. Asqav source: `github.com/jagmarques/asqav-sdk` ·
> home `asqav.com`. Cross-validation evidence: mg `validation.asqav_jcs_20of20_independent_2026-06-12` (id 4132).

---

## 1. What's already proven (the foundation)

| Fact | Evidence |
|---|---|
| We share the JCS canonical form, byte-for-byte | Asqav's `conformance/vectors.json` (sha256 `c1f87953fd17143780a07ddade63d715a7dab7a328b2080fafb9c791ef87d68a`, 20 vectors, declares `RFC 8785 JCS`) run through **our** canonicaliser → **20/20 canonical bytes identical AND 20/20 SHA-256 identical**. Same canonicaliser behind our 576/576 corpus. |
| His algorithm is already first-class on our side | `ML-DSA-65` is registered in our `KNOWN_SIGNATURE_ALGORITHMS` (FIPS 204 / draft-ietf-cose-dilithium). No registry work. |
| Our own PQC fixture is on the right side of the binding question | `epi_pqc_v0` binds `signature_suite` + `hash_alg` **inside** the signed JCS preimage — so the fix we offer Asqav is one we already ship, not a do-as-I-say. |

The one real technical issue is on **his** side, not ours (§4).

---

## 2. The integration — two tiers

### Tier 0 — done, zero work
- Canonicalisation compatibility proven (20/20).
- ML-DSA-65 already registered.

### Tier 1 — the interop set *(mechanical, ~half a day, mirrors `epi_interop_v0`; ALLOWED under distribution-only)*
1. **`asqav_interop_v0`** in `algovoi-jcs-conformance-vectors` — pin the 20 reconciled vectors as an
   interop set (`id`, `input`, `expected_jcs_bytes_b64`, `frame_id`, `timestamp_encoding`),
   **byte-locked to his `vectors.json` sha `c1f87953…`**.
2. **README** stating the boundary plainly: *we attest the JCS canonical form is identical — not
   Asqav's signature or binding semantics.*
3. **`runner_python.py`** that recomputes every `frame_id`/JCS from `input` (same shape as the
   `epi_*` runners, no AlgoVoi code in the trust base).
4. **Multi-impl cross-validation** — run his 20 through our **JS + Go** canonicalisers too, so the
   attestation is multi-impl-backed like `epi_interop_v0` (toolchains are local).
5. **`manifest.json`** registration (+1 interop set).
6. Backup-first → branch → validate byte-for-byte → push. **Corpus repo only**, zero blast radius.

### Tier 2 — the binding fix *(the real value + the one decision; needs founder override under distribution-only)*
7. Offer the binding-fix pattern (§4) and, optionally, an **`asqav_pqc_v0`** fixture demonstrating
   ML-DSA-65 bound-in-bytes the same way `epi_pqc_v0` demonstrates Falcon-1024.
8. A short joint-profile note anchored to `draft-hopley-x402-canonicalisation-jcs`.

---

## 3. What's required from us (scope summary)

| Item | Effort | Risk | Gated by |
|---|---|---|---|
| Canonicalisation proof | **done** | — | — |
| ML-DSA-65 registry | **done** (already registered) | — | — |
| `asqav_interop_v0` set + README + runner | ~half day | low (corpus-only) | founder go to push |
| JS + Go multi-impl cross-val | ~1 hr | low | — |
| Binding-fix proposal (the offer) | drafting only | none | his agreement |
| `asqav_pqc_v0` demonstrator (optional) | ~half day | low (corpus-only) | founder override (Tier 2) |
| Outreach note to jagmarques | drafting only | reputational — review before send | founder go |

---

## 4. The binding fix — the offer

**The gap (his side, mg id 4127):** in Asqav v2 the `signature_algorithm` identifier sits in the
*unsigned receipt envelope*, outside the signed canonical bytes. A verifier therefore learns which
algorithm to use from unauthenticated data — the classic algorithm-confusion / downgrade surface.

**The fix — one structural move:** put the algorithm identifier **inside** the signed canonical
bytes, so the verifier reconstructs the preimage *including* the declared algorithm and any swap
breaks the signature.

What we already do in `epi_pqc_v0` (inside the SIGNED JCS preimage):
```json
"signature_suite": "falcon1024",
"hash_alg": "SHA-256"
```

What Asqav would do — same shape, his values (moved from the receipt envelope into the signed body):
```json
"signature_algorithm": "ML-DSA-65",
"hash_alg": "SHA-256"
```

Two differences from the EPI case, both already handled:
- **His algorithm, not ours** — ML-DSA-65 (already registered).
- **His custody layer stays on top** — the Asqav issuer-custody receipt wraps the now-bound
  signature; we don't touch it. We fix only the inner binding.

**Posture (important):** this is a *recommendation + a runnable reference*, not us rewriting his SDK.
It remains **his call** whether the algorithm moves into the signed body or he addresses it via the
custody layer. We propose in-signed-bytes because it's the cleaner, downgrade-proof option and it's
what we already ship — we do **not** assert it as the only valid answer.

---

## 5. Boundaries & posture

- **Sell, don't run.** We provide the substrate, the interop fixture, and the pattern. We do not take
  custody of Asqav's pipeline or operate anything on his behalf.
- **Local-only validation.** Cross-validation used a fetched public file run through our local
  canonicaliser; no operational dependency on his infrastructure.
- **His call on the fix.** §4 is an offer, not a verdict on his design.
- **Distribution-only.** Tier 1 + outreach = outbound/collateral (allowed). Tier 2 build = development
  (needs founder override).
- **Provenance.** Credit lands durably where it's verifiable: the corpus set + any I-D section.
  No AI-authorship trailers on anything that ships.

---

## 6. Outreach sequence (on founder go)

1. **Note to jagmarques** — lead with the proof (*"ran your conformance set through our RFC 8785
   canonicaliser: 20/20 byte-identical, canonical + hash"*), then offer the interop fixture, then
   raise the binding observation as a *recommendation with a worked reference* (`epi_pqc_v0`).
   Draft for founder review; **send only on go.**
2. **Push `asqav_interop_v0`** — backup-first, validate, push (corpus only).
3. **Joint-profile note** — short, anchored to `draft-hopley-x402-canonicalisation-jcs`.

---

## 7. Open decisions for founder

1. **Tier 1 only** (interop fixture + outreach) **vs Tier 1 + Tier 2** (also build the `asqav_pqc_v0`
   binding demonstrator — needs distribution-only override).
2. **Tone of the binding note** — soft recommendation vs joint-profile proposal.
3. **Send order** — note first (gauge interest), or note + fixture together (proof in hand).

---

*Nothing in this document has been sent, pushed, or published. It is a planning artifact for review.*
