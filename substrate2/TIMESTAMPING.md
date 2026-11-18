# RFC 3161 trusted timestamps in substrate2

**INTERNAL.** How substrate2 gets independent time into the evidence chain, what that
proves, and — more important for anyone writing sales or docs copy — what it does **not**.

---

## The problem it solves

Every other time value in substrate2 is **self-asserted**. `keystone_secure.with_validity`
writes `issued_at_ms` and `expires_at_ms` into a preimage, and the issuer then signs it. That
proves the issuer's intent. It does not prove the moment, because the party making the claim
also supplied the clock.

An RFC 3161 timestamp replaces:

> our system says this happened then

with:

> an independent authority attests this digest existed by then

That is the distinction an auditor cares about, and it is why this is a ratified external
standard (RFC 3161, Standards Track, August 2001) rather than another AlgoVoi convention.

---

## What gets stamped: the chain head

`retention_chain.retention_chain_ref` already hash-links every receipt into a chain. So
**one token over the chain head gives every receipt beneath it an existence proof**, at one
TSA round trip per batch instead of one per receipt.

An individual receipt is therefore proven by **chain inclusion plus the head's token**, which
is how transparency logs work. Consequences worth stating plainly to a customer:

- No per-receipt network call, so the signing path stays fast and stays usable where outbound
  network is restricted.
- The guarantee is "existed by the time of the next chain-head stamp", not "existed at this
  exact instant". Stamp cadence is the resolution. Choose it deliberately.

---

## Privacy

The TSA is sent **only a hash** (RFC 3161 `messageImprint`) and by design never sees the
data. Timestamping leaks nothing, which suits a no-PII evidence product exactly.

---

## The sidecar rule, and why the chain never changes

The timestamp is recorded as a **sidecar**, never folded into the chain:

```
chain_timestamp_ref = "sha256:" + SHA-256(JCS({
    chain_ref, chain_seq, issuer_id,
    tsa_policy_oid, tst_serial, gen_time_ms, message_imprint_hex,
}))
```

The retention-chain preimage is fixed at four fields, and every `chain_ref` already anchored
must keep recomputing. So the sidecar references the chain by its existing ref. **Nothing in
`retention_chain.py` changes and no historical digest moves.** `tests/test_timestamp.py`
asserts this directly rather than trusting it.

The raw token travels alongside as base64, outside the preimage. The preimage carries the
token's identifying fields (policy OID, serial, genTime, imprint), so substituting a
different token changes the ref.

---

## Scope: what this is and is not

| | |
|---|---|
| **Is** | The equivalent of **JAdES B-T** (ETSI TS 119 182-1 v1.2.1) — an independent signature timestamp |
| **Is not** | **B-LT** — no `xVals` / `rVals` certificate and revocation validation-data capture |
| **Is not** | **B-LTA** — no archive-timestamp renewal |
| **Is not** | eIDAS **qualified**. That requires a qualified trust-service provider, which is a procurement decision, not a code change |

**Do not** describe output from this module as JAdES conformant, eIDAS qualified, or
"long-term validation". Those are follow-on phases, and claiming them early is the kind of
thing a regulated buyer's technical reviewer catches.

### The PQC caveat

The cryptographic strength of a token is **the TSA's, not ours**. Public TSAs sign with RSA
or ECDSA today (the freetsa.org fixture in our tests is `sha512_ecdsa`). ML-DSA-capable TSAs
exist commercially but are not widespread.

`TimestampToken.signature_alg` records which algorithm was used, so a caller can decide
rather than assume. Note the genuine argument in the other direction: a timestamp applied
*before* an algorithm's retirement date is itself the standard mitigation for that algorithm
ageing — it evidences that the data existed and was signed while the algorithm was still
trusted.

---

## Usage

```python
from substrate2 import timestamp as ts
from substrate2.retention_chain import retention_chain_ref

head = retention_chain_ref(prev_receipt_hash=prev, receipt_hash=cur,
                           chain_seq=seq, issuer_id=issuer)

req, nonce = ts.timestamp_request(head)              # a chain_ref goes in unmodified
resp = ts.fetch_timestamp("https://freetsa.org/tsr", req)
result = ts.verify_timestamp_token(resp, expected_digest=head, nonce=nonce)

record = ts.build_chain_timestamp(chain_ref=head, chain_seq=seq,
                                  issuer_id=issuer, token=result.token)
```

Requires `substrate2[timestamp]` (adds `asn1crypto`, pure-Python, no compiled deps). The
import is lazy, so a base install runs everything else unaffected.

`fetch_timestamp` is the **only** function that touches the network; everything else is pure
protocol and verifies offline.

### Parsed is not verified

`verify_timestamp_token` runs the RFC 3161 section 2.4.2 recipient checks: status carries no
error, `messageImprint` equals the digest asked about, hash algorithm matches, nonce matches
when one was sent.

It does **not** check the TSA's signature or certificate chain unless `trust_anchors` is
supplied. `TimestampResult.signature_verified` reports which happened, so a caller can never
read *the token says this* as *the TSA vouched for this*.

---

## Testing

`tests/test_timestamp.py` runs offline against a **real** recorded freetsa.org token
(`tests/fixtures/`). A real token rather than a synthetic one is the point: a hand-built
fixture would only prove the parser agrees with itself.

The load-bearing test is the negative control — a token obtained for chain head A must fail
against chain head B. A token is evidence only about the digest it covers; one that verified
against any digest would be worthless.

Live round-trip: `SUBSTRATE2_TSA_LIVE=1 python -m pytest tests/test_timestamp.py`.
