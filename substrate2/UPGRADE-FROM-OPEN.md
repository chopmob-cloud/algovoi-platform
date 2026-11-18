# Upgrading from the open substrate to Substrate 2

**INTERNAL — sales enablement.** This is the documented bridge between the free Apache-2.0
`algovoi-substrate` and the commercial engine. Publishing any part of it publicly is a
separate decision; nothing here is public copy yet.

It exists because the 2026-07-11 substrate roadmap named the gap plainly: *"open-L1 and
commercial-substrate2 are two separate things with no documented bridge"*, and called closing
it the money ramp. This is item 2.

---

## The only question that matters first

> If I swap the free package for yours, do the records I have already anchored still verify?

**Yes, and it is proven rather than promised.**

If a single byte differed, every historical record the customer holds would become
unverifiable under the engine they just paid for. That is not a regression, it is the loss of
their evidence base — so it is the objection to answer before any feature is mentioned.

Two independent proofs ship in the package:

| Proof | What it covers | Where |
|---|---|---|
| Canonicaliser agreement | **166 vector inputs**, 7 canonicalisation edge shapes, 6 shared primitives, all byte-identical to `algovoi-substrate` 0.5.1 | `conformance/byte_parity.py` section G |
| Drop-in agreement | Customer code importing **only** free-package names, run unchanged on both engines, identical output including `repr` | `tests/test_upgrade_dropin.py` |

Both run on the customer's own hardware. `python -m substrate2.conformance.byte_parity`
prints `IDENTICAL` or it does not.

**This is a guarantee rather than a best effort because the open estate is frozen**
(`decision-commercial-only-free-frozen-2026-07-21`). The compatibility target no longer moves,
so the claim is pinned to a named version: `algovoi-substrate` **0.5.1**. If that ever
unfreezes, the guarantee must be re-proven against the new version.

---

## What changes in the customer's code

Nothing at the call sites. `substrate2.compat.v1_shim` registers the `algovoi_substrate.*`
namespace, backed by substrate2:

```python
from substrate2.compat import v1_shim
v1_shim.install()          # before the application's imports resolve
```

Existing `from algovoi_substrate import ...` statements then resolve to substrate2 with no
edit. The gateway does this behind `SUBSTRATE2_ENABLED=1`, and
`substrate2.compat.v1_shim.installed()` reports at runtime which engine is actually serving,
so "running on Substrate 2" is observable rather than asserted.

`install()` is idempotent and reversible via `uninstall()`, so the switch is a genuine toggle
and a customer can back it out without redeploying.

---

## What they gain

Ordered by what actually closes a deal, not by engineering interest.

**1. Licence and risk transfer.** Warranty, indemnity, SLA, and embedding rights without the
Apache attribution chain flowing through their product. The stated conversion trigger for the
primary buyer segment — regulated fintechs and PSPs — is that they *cannot take Apache-2.0
"as-is, no warranty" through procurement*. This is the one that signs.

**2. Independent time (RFC 3161).** Every timestamp in the open package is self-asserted: the
issuer writes `issued_at_ms` into the preimage it then signs. substrate2 adds trusted
timestamps over the retention-chain head, so an independent authority attests the record
existed by a given time. See `TIMESTAMPING.md` — note the scope boundary there, it is JAdES
B-T equivalent and must not be described as long-term validation.

**3. Capabilities the open tier does not have**: zero-knowledge receipts, cross-issuer
federation, ATB credential verification, penta-format export (native / JWS / PEF / TAP).

**4. One supported package** instead of assembling ~15 open ones at compatible versions.

**Do not pitch PQC as commercial-only** — `algovoi-substrate-pqc` is Apache-2.0 and a savvy
buyer will catch it. Lead with terms, ZKP/federation, and independent time.

---

## What they must be told

Honesty here is cheaper than a failed technical review.

- **Not pip-installable.** The `zkp` extra needs `algovoi-bpverify`, which is commercial and
  on no public index. Ship the bundled wheel alongside; see `GA-CRITERIA.md` criterion 1.
- **Not open.** substrate2 source is not provided under an open licence. The Apache-2.0
  reference and the public conformance vectors remain available for independent verification —
  that is the point of the byte-identity guarantee.
- **Timestamp strength is the TSA's**, not ours. Public TSAs sign with RSA or ECDSA today.
- **The free packages keep working.** Frozen is not withdrawn; nothing they run today stops.

---

## The conversation, in order

1. *Will my anchored records still verify?* — run `byte_parity`, show `IDENTICAL`, 166 inputs.
2. *How much code changes?* — one `v1_shim.install()` line, reversible.
3. *What do I get?* — terms and indemnity first, then independent time, then ZKP/federation.
4. *What is the catch?* — bundled install path, closed source, TSA algorithm.

The trigger is never "better bytes" — the bytes are identical by design, and that is the
feature. It is a procurement requirement, a need for capability the open tier withholds, or
wanting to embed without the attribution chain.

---

## Verify it yourself

```
python -m substrate2.conformance.byte_parity     # IDENTICAL vs algovoi-substrate 0.5.1
python -m substrate2.conformance.run_all         # ALL GREEN
python -m pytest tests/test_upgrade_dropin.py    # unchanged customer code, both engines
```
