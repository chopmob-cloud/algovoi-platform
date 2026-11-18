# substrate2 2.0.0 — GA criteria

**INTERNAL.** Defines what "done" means for substrate2, so GA is something the machine can
prove rather than something a person asserts. Every criterion below is executable; the
"how to prove it" column is the actual command.

substrate2 shipped as `2.0.0a6` from June 2026 while being the engine inside a commercially
licensed enterprise product. The alpha tag was never a statement about maturity, it was the
absence of a written finish line. This is that finish line.

---

## Why GA matters commercially

substrate2 is never sold on its own (`GTM-PRICING.md` section 6: bundled into the enterprise
/ on-premise tier, no separate SKU). It is what makes those products defensible. The primary
buyer segment is regulated fintechs and PSPs whose stated conversion trigger is that they
*"can't take Apache-2.0 as-is, no warranty, through procurement"*.

Those buyers read version strings. An `a6` alpha inside a licensed product is a procurement
objection that costs nothing to remove and cannot be argued away with test counts.

---

## The criteria

| # | Criterion | How to prove it | Status |
|---|---|---|---|
| 1 | Conformance gate fully green | `python -m substrate2.conformance.run_all` exits 0, all 10 sections GREEN | MET (see install-path note) |
| 2 | Test suite green, **on a clean box** | `python -m pytest tests/ -q` with no sibling packages installed | MET |
| 3 | **Byte-identity with the open substrate** | `python -m substrate2.conformance.byte_parity` reports IDENTICAL | MET |
| 4 | Cross-platform reproducibility | byte_parity `REPORT_DIGEST` equal on Windows source tree and Linux installed wheel | MET |
| 5 | No unfinished surfaces | no `NotImplementedError` in shipped code paths | MET |
| 6 | No `^...$` anchors in reference validators | `tests/test_anchor_discipline.py` static sweep, 0 offenders | MET |
| 7 | Self-contained conformance bundle | gate runs from the installed wheel with `ALGOVOI_ASSET_ROOT` pointing at nothing | MET |
| 8 | Deterministic under a hostile interpreter | report digest stable across repeat runs and varied `PYTHONHASHSEED` | MET |
| 9 | **The shipped artifact is itself verifiable** | `tests/test_release_manifest.py` green, and the release envelope verifies offline against the pinned release key with `artifact_dir` supplied | BLOCKED on release-key custody (see below) |

---

## Criterion 1 — the install-path constraint

The `zkp` extra depends on `algovoi-bpverify`, which is **not on any public index** (it is
commercial and ships as a wheel inside the on-premise bundle). Consequence, verified on a
clean VM2 container 2026-07-21:

- `pip install substrate2[zkp]` from a public index **fails**, and section 6 (ZKP +
  federation) then goes RED with `ModuleNotFoundError: algovoi_bpverify`.
- Supplying the bundled `algovoi_bpverify-0.1.0-cp310-abi3-manylinux_2_17_x86_64.whl`
  alongside the substrate2 wheel gives **ALL GREEN** on the same clean container.

So the gate is fully green on the **actual delivery path** (the on-prem bundle, which
carries both wheels) and cannot be on a public-index-only install. That is correct for a
commercial component, but it must never be described as "pip installable" and any install
doc must ship the bpverify wheel alongside. Do not attempt to fix this by publishing
bpverify.

## Criterion 3 in detail — the guarantee that carries commercial weight

A customer swapping the open Apache-2.0 package for substrate2 must find that **every digest
they have already anchored still recomputes**. If one byte differs, every historical record
they hold becomes unverifiable under the engine they have just paid for. That is not a
regression, it is a total loss of their evidence base.

So byte-identity is the thing to warrant, and warranty is moat item 2 in `GTM-PRICING.md`.

**This became a permanent, provable property on 2026-07-21**, when the open estate was frozen
(`decision-commercial-only-free-frozen-2026-07-21`). While the open substrate kept moving,
byte-identity was a maintenance burden chasing a target. Frozen, the target stops moving, so
the claim can be stated as a guarantee against a named version rather than a best effort.

**Proven against `algovoi-substrate` 0.5.1** (the frozen published release):

- 166 vector inputs, every input object in every bundled set, through both canonicalisers
- 7 canonicalisation edge shapes: empty object/array, integral float, U+2028/U+2029, non-BMP
  key ordering, large integers, nesting
- 6 shared-signature primitives: `action_ref`, `sha256_jcs`, `transition_hash`,
  `composite_trust_query_hash`, `settlement_action_binding`, CAIP verdicts

**The check bites.** Injecting the classic Go `json.Marshal` divergence (HTML-escaping `&`)
into substrate2's canonicaliser is caught — by exactly one vector,
`jcs_edge_v1/jcs-edge-009-solidus-and-html-literal`. One in 166. That is the whole argument
for keeping the edge sets bundled: the other 165 vectors never touch the character, so
without `jcs_edge_v1` this defect ships silently and every affected receipt stops verifying.

---

## What GA does NOT claim

- **Not published, not open.** substrate2 remains internal and commercially licensed. GA is
  about the engine being finished, not about distribution.
- **Not feature-complete against every roadmap idea.** Crypto-agility and verifier-as-product
  remain held behind a named buyer, by design. Capability is already ahead of demand, and
  building further without a buyer is motion, not progress.
- **Not a promise of future byte-identity to a moving target.** The guarantee is against
  `algovoi-substrate` 0.5.1 specifically. It holds because that release is frozen. If the
  open estate is ever unfrozen, this criterion must be re-proven against the new version.

---

## Re-proving GA

Run all of it:

```
python -m pytest tests/ -q
python -m substrate2.conformance.run_all            # must print ALL GREEN
python -m substrate2.conformance.byte_parity        # must print IDENTICAL
```

The byte-parity harness hashes its own source as part of section A, so the `REPORT_DIGEST`
covers the harness too: changing the harness changes the digest by design, and a pinned
digest therefore pins the evidence and the thing being evidenced together.

## Reference digest at GA

Pinned 2026-07-21 for substrate2 **2.0.0**, proven identical on a Windows 11 / Python 3.12
source tree and a Linux glibc 2.41 / Python 3.11 installed wheel in a clean container:

```
REPORT_DIGEST 83743e29d3c173153c0ee20d1839722198f0612f88717290dfae3f86455b96f8

  A_source         3ae83be803a6c3ec7e7fee1c886c8ccb2811ca83f054dc590d42ab561e7f85aa
  B_vectors        d7c26a7dd00452f5aafbfa77d11c8b32c7513d3a0d703a04f0e4efb8307c14c4
  C_primitives     ca740b1ef587ee922130d3e3b98d4cd50a769fdaf6cbaeb2140cbbd21c09669b
  D_receipts       55b75ebc21a62648a1910d17627dbd235af90460b7d145175d5e5b7e3654c67f
  EF_verdicts      b830a11c3067aa2775e0d49657edab13edd33d2760e21e71e6f994028a028c90
  G_byte_identity  1487fc6ef878be0f49409c5c339a73080bb8a24cf0ded2ac9e7c0a44c59e1eb5
```

A changed digest is not automatically a defect — it means something covered by the report
moved, and the per-section digests say which. `A_source` alone changing is a code edit;
`B_vectors`, `D_receipts` or `G_byte_identity` changing without an intended reason is a
regression in the evidence base and must be explained before shipping.

Worked example, same day: adding the optional CAIP fields to `zkp.PaymentReceipt` moved
`A_source` from `69100c79…` to `2f7a0c8f…` and left all five other sections byte-identical.
Adding the RFC 3161 timestamp module then moved it again to `51aa61ed…`, with the same five
sections still untouched. That is the signature of a correct additive change — the code
moved, the evidence did not.

### Post-GA movement, 2026-07-25 — `substrate2.release`

Adding the signed-release subpackage moved `A_source` from `3ae83be8…` to `f8f9a0f9…`,
again with all five other sections byte-identical and byte-identity vs `algovoi-substrate`
0.5.1 still IDENTICAL:

```
REPORT_DIGEST 92f90daa55735f08aeaacd832ad2ddf54d2dd92a0d9dd91bab19babfd7f4f0e2

  A_source         f8f9a0f91a3648aa0f19c5448a30459a2c84ab10dbd4e15cad44f9368cf1a1a8
```

Criterion 4 re-proven for this digest: identical on the Windows 11 / Python 3.12 source
tree and on a Linux `python:3.11-slim` container on VM2 with the wheel installed from
the index plus `algovoi-substrate==0.5.1`. Note the open package must be present in the
container or section G reports UNPROVEN and the report digest legitimately differs — that
is the harness being honest, not a regression.

Two defects this round of proving caught, both in the new code:

- Criterion 6 earned its keep: the first draft of `release/sbom.py` parsed requirement
  strings with `^\s*(...)` and the static sweep failed the build. Fixed to `\A`.
- The clean container caught the more interesting one. `_closure` treated every
  unresolved requirement as fatal, so a dependency gated behind an environment marker
  (`typing-extensions; python_version < "3.11"`) aborted SBOM generation on any modern
  interpreter. Markers are still not evaluated — that would mean taking on a build-tooling
  dependency this module deliberately refuses — but absence is now read as the marker's
  answer. A requirement with **no** marker that is missing is still refused, because a
  disclosure document that understates what ships is worse than no document.

## Criterion 9 — why it is BLOCKED rather than unmet

The mechanism is built and adversarially tested (21 tests: tamper, algorithm confusion,
rollback, expiry, substituted artifact, swapped SBOM, unknown role, malformed input).
What is missing is not code. Issuing a real release envelope needs an AlgoVoi **release
signing key**, and `decision.deployment_security_standard` (G1–G10) puts key custody in an
HSM/KMS. Generating one on a development box and committing it would defeat the control
this criterion exists to add, so the key is a founder decision, not a build step.

Until that key exists, the subpackage ships and is testable, but no signed release manifest
is issued and `dist/` remains unattested.

A second worked example, where a section OTHER than `A_source` moved and it was still
correct. Aligning `AuditChainRow` key insertion order with the open package moved
`C_primitives`, because the harness records `str(row)` for audit rows and that captures key
order. Checked before accepting it: every `content_hash` and `prev_hash` was unchanged and
identical to the open package, `dict` equality held, and `B_vectors` / `D_receipts` /
`G_byte_identity` were untouched. So the move was presentational, intended, and toward the
open package. The lesson is the process, not the outcome: a moved section is a question to
answer with evidence, never a number to update.

Criterion 2 says *on a clean box* for a reason found on 2026-07-21:
`tests/test_execution_evidence_ccc.py` imported the sibling package
`algovoi_command_center` unguarded, and because pytest **interrupts** on a collection error,
that one missing sibling made all 68 tests uncollectable anywhere it was absent — including
the tests that prove GA. It now uses `importorskip`. A clean container runs 65 passed,
2 skipped (that module, plus the opt-in live-TSA test).
