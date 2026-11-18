# Substrate 2 — Provenance / authorship log

Append-only. One row per module. Each module is implemented from AlgoVoi's own published
IETF Internet-Drafts and public conformance vectors. v1 source is **not** a source of
implementation; it is consulted only to confirm a public function *signature* (name,
arguments, return type), with the body unread.

## Clean-room attestation

> The modules below were written from the cited draft sections and public vector files.
> They are not derived from, and do not copy, the v1 package bodies, helper decomposition,
> comments, or internal names. Where a third-party primitive is used (`rfc8785`,
> `cryptography`, `pqcrypto`), it is an external dependency under its own licence, listed
> in the third-party table, and is not AlgoVoi v1 code.

## Module ledger

| module | implemented_from | author | date | notes |
|---|---|---|---|---|
| canon | draft-hopley-x402-canonicalisation-jcs-v1 (Rules 1-4: JCS RFC 8785, integer-ms timestamps, type-validate-before-canon, canon_version pin) + manifest.json canon_version | substrate2 | 2026-06-06 | thin RFC 8785 wrapper + independently-authored discipline layer; not derived from v1 source. Proven: 73/73 JCS vectors byte+hash exact |
| digest | canonicalisation-substrate.mdx (sha256 over JCS bytes; "sha256:" prefix convention) | substrate2 | 2026-06-06 | sha256_jcs over canon bytes; not derived from v1 |
| receipts.compliance | draft-hopley-x402-compliance-receipt-02 §3-5 + compliance_receipt_v1 vectors + schemas/examples/receipt-*.json | substrate2 | 2026-06-06 | 6-field receipt (ALLOW/REFER/DENY), integer-ms discipline, closed-enum + array-order + canon_version load-bearing. v1 signature consulted via AST (kwonly args) only. Proven: 8/8 receipts reproduced byte-identical + content_hash exact |
| httpsig | draft-hopley-x402-rfc9421-binding-00 + RFC 9421 §2.3-2.5 + RFC 9530 + the RFC 8032 §7.1 pinned fixture | substrate2 | 2026-06-06 | signing base line-per-component, @signature-params last, @method case-preserved, @authority lowercased; Ed25519 via cryptography. Proven: signing base + signature_input + content-digest + 64-byte sig all match the pinned fixture |
| pqc | draft-hopley-x402-pqc-credential-binding-00 + atb-reputation-credential.mdx | substrate2 | 2026-06-06 | PQClean Falcon-1024 via pqcrypto; verify-not-reproduce (randomised sig); kid = sha256(pk)[:16]. Not derived from v1 |
| atb_credential | atb-reputation-credential.mdx + atb-hub-conformance.mdx + draft-hopley-x402-atb-reputation-credential-00 + the published verify_from_spec.py envelope contract | substrate2 | 2026-06-06 | {payload,sig,alg,kid} envelope, JCS-signed. Proven: v2-built envelope accepted by the external stdlib-only verifier (no substrate2 imports); shipped envelope verified by v2 |
| action | draft-hopley-x402-canonicalisation-jcs-v1 (action_ref) + action_ref_namespace_v0 / action_ref_transactional_v0 vectors | substrate2 | 2026-06-06 | action_ref = sha256_jcs({agent_id,action_type,scope,timestamp_ms}); scope non-empty string, no enum. Proven byte+hash exact vs vectors |
| receipts.settlement | draft-hopley-x402-settlement-attestation-02 + settlement_attestation_v1 vectors | substrate2 | 2026-06-06 | SETTLED/PENDING_FINALITY/REVERSED; amount_minor as integer-minor string. Proven byte+hash exact. v1 signature via AST only |
| receipts.refund | draft-hopley-x402-refund-receipt-02 + refund_receipt_v1 vectors | substrate2 | 2026-06-06 | FULL/PARTIAL/REJECTED. Proven byte+hash exact. v1 signature via AST only |
| receipts.cancellation | draft-hopley-x402-cancellation-receipt-02 + cancellation_receipt_v1 vectors | substrate2 | 2026-06-06 | USER_REQUESTED/MERCHANT_REQUESTED/COMPLIANCE_TERMINATED/EXPIRED. Proven byte+hash exact. v1 signature via AST only |
| receipts.ctq | draft-hopley-x402-composite-trust-query-02 + composite_trust_query_v1 vectors | substrate2 | 2026-06-06 | TRUSTED/PROVISIONAL/INSUFFICIENT_EVIDENCE/UNTRUSTED. Proven byte+hash exact. v1 signature via AST only |
| pef | draft-hopley-x402-payment-evidence-frame-00 + pef_v1 vectors | substrate2 | 2026-06-06 | URN-form canon_version, derived receipt_format + receipt_hash, frame_id = sha256:+sha256_jcs(preimage). Proven: preimage bytes + frame_id + receipt_hash exact across 8 vectors |
| jws | draft-hopley-x402-compliance-receipt-02 (JWS section) | substrate2 | 2026-06-06 | compact EdDSA; header/payload sorted-key COMPACT JSON (never JCS); kid=sha256(pk)[:32]; did:key base58btc 0xED01 prefix; receipt verifier vs JWKS. Proven: round-trip + tamper + unknown-kid. Not derived from v1 |
| zkp | draft-hopley-x402-federation-zkp-00 + draft-hopley-x402-pqc-credential-binding-00 + zkp_receipt_v1 vectors | substrate2 | 2026-06-06 | Falcon-1024 envelope binding opaque 32B commitment + 200-900B proof; structural + expiry + type checks. Proven: 8 zkp_receipt_v1 canon vectors byte+hash exact; envelope round-trip + bad-commitment rejection. v1 signature via AST only |
| federation | draft-hopley-x402-federation-zkp-00 | substrate2 | 2026-06-06 | compose_commitments = sha256(c0..cn||nonce); HMAC token with label "AlgoVoi-FederationToken-v1"; per-credential independent Falcon verify, no shared trust root. Proven: compose determinism+order-sensitivity, 2-credential compose -> token verify, wrong-secret rejection. v1 signature via AST only |
| audit | draft-hopley-x402-compliance-receipt-02 §5 + compliance_receipt_v1 chain vectors + v1 audit_chain test contract | substrate2 | 2026-06-06 | runtime chain row {chain_position, prev_hash, content_hash, payload}; head pos 0 / prev None; verify raises on break. Proven: v1 audit_chain suite passes via shim + wire-form vectors in own gate |
| transactional | draft-hopley-x402-canonicalisation-jcs-v1 + action_ref_transactional_v0 vectors + v1 transactional test contract | substrate2 | 2026-06-06 | transition_hash = sha256_jcs(preimage); build chain returns dict {action_ref, transitions[]}; action_ref 64-hex validation. Proven: 7 transition vectors byte+hash exact + v1 transactional suite passes via shim |
| compat.v1_shim | Phase 5 cutover (v1 import surface) | substrate2 | 2026-06-06 | registers old v1 module names in sys.modules backed by substrate2; install()/uninstall(), idempotent, env-gated. Maps algovoi_substrate(+submodules), rfc9421_signer, rfc9421_verifier, settlement/refund/cancellation/ctq/pef, receipt_verifier, zkp, federation, atb_credential_verifier |
| atb_credential_verifier | atb-reputation-credential.mdx + atb-hub-conformance.mdx + v1 verifier contract | substrate2 | 2026-06-06 | consumer ATBCredentialVerifier.verify (Falcon envelope, never raises), grants_discount/has_zkp, LRU result cache, fetch_hub_keys. Proven: v1 atb-credential-verifier suite 15/15 via shim |
| rfc9421_verifier | draft-hopley-x402-rfc9421-binding-00 + RFC 9421/9530 + verifier fixtures | substrate2 | 2026-06-06 | parse_signature_input/value, build_signing_base (rfc9421 + algovoi-v0 modes), verify_signature, verify_request. Proven: v1 rfc9421-verifier suite 23/23 via shim (FIXTURE_SIGNING_BASE_V0/RFC9421 byte-exact) |
| composite_trust_query | draft-hopley-x402-composite-trust-query + v1 test contract | substrate2 | 2026-06-07 | composite_trust_query_hash(rows) = sha256_jcs of rows sorted by source_id with `sig` stripped (order- and signature-invariant; subset/payload-distinct). Distinct from receipts.ctq.build_ctq_response. Proven: v1 test_composite_trust_query 9/9 via shim. Closed cutover GAP 1 |

## Phase 5 reused-suite results (the interop arbiter)

Running the **v1 packages' own test suites** against substrate2 via the shim (the byte-exact
cross-check that self-round-trips cannot provide):

- **192 passed, 0 failed** across 13 v1 packages/suites: algovoi_substrate (canonicalize 14,
  action_ref 11, audit_chain 10, compliance_receipt 10, transactional 20),
  algovoi-rfc9421-signer (21), algovoi-rfc9421-verifier (23), algovoi-settlement-attestation
  (10), algovoi-refund-receipt (14), algovoi-cancellation-receipt (11),
  algovoi-composite-trust-query (9), algovoi_pef (24), algovoi-atb-credential-verifier (15).
- This proves substrate2 is a drop-in, byte/behaviour-identical replacement for the core
  substrate, both RFC 9421 halves, all four receipt sibling packages, the Payment Evidence
  Frame, and the consumer ATB credential verifier — the full surface the gateway and plugins
  import.
- (Note: atb-credential-verifier and rfc9421-verifier both ship a test_verifier.py, so they
  must be collected in separate pytest sessions — a basename clash in pytest's import model,
  not a substrate2 issue. Each is green standalone.)

Remaining reused suites (deliberately deferred):
- algovoi-zkp-receipt and algovoi-federation-validator: their tests import v1 PRIVATE symbols
  (_b64url_decode, _COMMITMENT_BYTES, _FED_TOKEN_LABEL) and submodule paths. Those assert v1's
  internal decomposition, which a clean-room reimplementation deliberately does not replicate.
  substrate2's PUBLIC zkp/federation API is proven in the own gate (section 6 round-trips).
  Matching v1's private layout would contradict the "unique code" mandate.
- algovoi-receipt-verifier: jws.verify_compliance_receipt framing (lower priority).
- Production cutover: wiring the shim into the gateway behind SUBSTRATE2_ENABLED=1 (a
  supervised step; run the full platform suite flag-ON vs flag-OFF before flipping).

## Cutover gap-check (2026-06-07)

Enumerated every production import of v1 substrate packages across gateway/, control_plane/,
shared/ and diffed against what the shim provides. 11/13 import bindings were covered; two gaps
found and CLOSED:
- **GAP 1** — `algovoi_substrate.composite_trust_query.composite_trust_query_hash` (compliance_gate.py:913,
  the /compliance/trust-query path) was a NotImplemented stub. Implemented the module; shim now maps
  it; v1 test_composite_trust_query 9/9 via shim. Full algovoi_substrate suite now 74/74 via shim →
  **total reused = 201, 0 fail.**
- **GAP 2** — `from algovoi_rfc9421_verifier.parse import parse_signature_input` (compliance_gate.py:574)
  failed: the `.parse` submodule path was not registered. Shim now registers `algovoi_rfc9421_verifier`
  as a package with `.parse` / `.signing_base` / `.content_digest` / `.verify` submodules.
- Not a gap: the gateway signs receipts via `shared.utils.substrate_signer` (not an algovoi_* package),
  so JWS signing is OUTSIDE the cutover surface and unchanged by the flag. The shim bootstrap must run
  in BOTH the gateway and control_plane processes (control_plane imports the cancellation/refund builders).

The production cutover surface is now fully covered by the shim. Next: wire the bootstrap behind
SUBSTRATE2_ENABLED, run the full platform suite flag-ON vs flag-OFF, confirm byte-identical, flip.

## Third-party primitives (external deps, not AlgoVoi code)

| package | version | role | licence |
|---|---|---|---|
| rfc8785 | >=0.1.4 | RFC 8785 / JCS number+string canonicalisation primitive | (per upstream) |
| cryptography | >=42 | Ed25519 key handling + signatures | Apache-2.0 / BSD |
| pqcrypto | >=0.4.0 | PQClean Falcon-1024 (FIPS 206) | (per upstream) |

The decision to depend on `rfc8785` rather than re-derive the ECMAScript
shortest-round-trip number serialiser is deliberate: byte-identity with the five-impl
convergence set requires the same primitive, and v1 depends on the same library.
Reusing a published third-party primitive is not copying v1; the clean-room contribution
is the discipline layer (type validation, integer-only timestamps, canon_version pin).
