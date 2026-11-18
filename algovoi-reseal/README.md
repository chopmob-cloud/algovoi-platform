# AlgoVoi Reseal — quantum-seal the signed documents you already have

**An [AlgoVoi](https://algovoi.co.uk) product.** Every post-quantum product on
the market protects tomorrow's data. This one rescues yesterday's.

A document signed with RSA or ECDSA stays provable only while those algorithms
stay unforgeable. Records on decade-long retention clocks (contracts, clinical
records, deeds, qualified e-signatures) outlive that window: the day a quantum
adversary can forge the classical signature, the original can no longer be told
apart from a tamper, and nothing recovers it after the fact. The rescue is only
possible NOW, while the classical signature still verifies.

`av-reseal` verifies the classical signature today and binds that verification,
with the full certificate chain as bytes, into a post-quantum attestation:

- JCS-canonical (RFC 8785) payload, `sha256:` content-addressed
- Falcon-1024 + ML-DSA-65 dual signatures (estate envelope convention)
- RFC 3161 timestamp from an independent TSA over the attestation hash
  (the TSA sees only a hash, never content; `--no-tsa` for air-gap)
- verifies offline, forever, with no AlgoVoi service in the trust path

## Quick start

```
av-reseal inspect contract.pdf          # what's signed, does it verify, how exposed
av-reseal keygen                        # your own PQ identity (~/.algovoi-reseal)
av-reseal seal contract.pdf             # -> contract.pdf.reseal.json (stamped)
av-reseal verify contract.pdf.reseal.json --file contract.pdf
```

`inspect`/`seal` pair `X.p7s` with its sibling `X` automatically. Batch seals
are hash-linked and the chain head carries the one TSA stamp, transparency-log
style.

## Carriers understood

- PDF embedded signatures (PAdES / PKCS#7): every `/ByteRange` + `/Contents` CMS
- Detached CMS (`.p7s`) over any file
- Anything else: sealed for existence + integrity (stated as such, no signature claim)

## Trust model

An artifact carries its signing public key, so verification alone proves it is
internally consistent and unaltered, NOT who sealed it. Pin the sealer's
published Falcon kid out-of-band and pass `--expect-kid` to anchor
authenticity (the kid is a full 256-bit SHA-256 of the key, not truncated).
Exit codes mirror the estate free-verifier: `0` verified and anchored, `1`
failed, `2` malformed/usage, `3` cryptographically intact but the key is
self-asserted.

**Dual signature is enforced, not decorative.** The set of signing algorithms
and their kids is bound *inside* the signed payload (`sealed_with`), so an
attacker cannot strip the ML-DSA-65 signature to fall back to Falcon-only: every
declared algorithm must have a present, valid signature under its matching kid,
or verification fails. A verifier build that cannot check a declared signature
fails closed.

**RFC-3161 time is only trusted when anchored.** A token's genTime is
attacker-settable with a self-signed TSA cert, so an unanchored token is
reported as `UNANCHORED TIME - not independently verified`. Pass `--tsa-roots`
to pin trusted TSA roots; a token that does not chain to one is rejected.

PDF signatures are additionally checked for whole-file coverage: a signature
over an earlier revision (incremental-update / shadow-attack surface) is
reported as PARTIAL COVERAGE, and SHA-1 digests are flagged weak. Both flags
travel inside the sealed attestation.

## Trust path and revocation (opt-in, offline)

Supply trusted roots and, optionally, a CRL and both move out of `not_checked`
and into the sealed record:

```
av-reseal inspect contract.pdf --trust-roots ./roots/ --crl issuer.crl
av-reseal seal    contract.pdf --trust-roots ./roots/ --crl issuer.crl
```

Both are fully offline (no network, no OCSP fetch), so air-gap holds and a
hostile document cannot turn verification into an SSRF or an oracle. Scope is
stated honestly in the output: basic RFC 5280 path building (issuer/subject
linkage, per-link signature, validity windows, CA basic-constraints, anchor
pinned by SHA-256), with `name_constraints`, `policy_oids`, `extended_key_usage`
and `path_length` left in `not_checked`. Issuer resolution requires a verified
signature, not just a matching name, so an attacker-supplied name-colliding
cert cannot steer it. A CRL past its `nextUpdate` is flagged stale.

## Honesty contract

The attestation records exactly which checks ran (`checks`) and which did not
(`not_checked`). It preserves evidence; it does not launder a broken PKI into
"valid". Certificates are captured as DER bytes so a stricter policy can re-run
against them in any future decade.

## Licensing

`algovoi-reseal` is original AlgoVoi work, licensed under the **AlgoVoi Reseal
Proprietary Software License** (see [LICENSE](LICENSE)). Producing sealed
attestations (`seal`) requires an active AlgoVoi license key.

It depends on third-party open-source packages, all under **permissive**
licenses (Apache-2.0, BSD-3-Clause, MIT, MIT-0) — none copyleft, none imposing
source-disclosure. Their required attributions are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and summarised in
[NOTICE](NOTICE): rfc8785 (Trail of Bits), pqcrypto (Backbone Technologies),
cryptography (PyCA), asn1crypto (Will Bond), and the transitive cffi/pycparser.
These are used as installed dependencies, not vendored into this package.

Public standards (RFC 8785/3161/5652/5280, FIPS 204/206) are implemented from
their specifications and impose no license terms.

## Two signing profiles (pick per identity)

Both are first-class and fully supported; the verifier accepts either, dispatching
on the algorithm declared in the signed `sealed_with` (so neither can be
downgraded). Choose at keygen:

| Profile | `--mldsa-level` | Signatures | Level | Trade-off |
|---|---|---|---|---|
| **Compact** (default) | `65` | Falcon-1024 + ML-DSA-65 | L5 + L3 | smaller seals, parity with the AlgoVoi estate |
| **Matched** | `87` | Falcon-1024 + ML-DSA-87 | L5 + L5 | both signatures at NIST L5; ~+640 B pubkey, ~+1.3 KB per signature, negligible time |

```
av-reseal keygen --mldsa-level 65   # Compact (default)
av-reseal keygen --mldsa-level 87   # Matched, L5 both
```

Falcon-1024 is draft FN-DSA/FIPS 206; ML-DSA-65/87 are finalized FIPS 204.

## Known limitations (stated honestly)
- **Cross-library interop is verified against liboqs (Open Quantum Safe).**
  Both Falcon-1024 and ML-DSA-65 round-trip both ways (pqcrypto sign / liboqs
  verify and vice versa), and a real sealed artifact's PQ signatures verify
  under liboqs against the exact JCS canonical bytes. The interop tests skip
  automatically where liboqs is not installed.
- **Windows key-file mode.** `keygen` writes the key file with 0600, which POSIX
  enforces; on Windows the mode bits are advisory. Run seal on the Linux estate
  or protect the key directory with OS ACLs.
- **Full RFC 5280 path validation is not claimed.** `name_constraints`,
  `policy_oids`, `extended_key_usage` and `path_length` remain in `not_checked`.

## Validated

`pytest` 75/75, run in two independent environments (the dev container and a
clean-room build from the packaged wheel with only declared deps). Coverage:
functional; adversarial artifact handling (forged artifacts, key-swap,
malformed/fuzz inputs, shadow-PDF coverage, weak-digest, cert-binding);
trust-path/revocation (untrusted root, revoked serial, name-colliding rogue
root, wrong-issuer CRL, stale CRL, cyclic chain, keyCertSign); and cryptographic
validation (exact FIPS-204 ML-DSA-65 and Falcon-1024 parameter sizes, bit-flip
and truncation negatives, dual-signature anti-strip binding, ML-DSA-less
verifier fails closed, full-width kid, JCS canonicalization robustness).

An independent adversarial red-team pass was run against the crypto design; its
four serious findings (ML-DSA strip, ML-DSA-less silent pass, forgeable
unanchored RFC-3161 time, 64-bit kid) are all fixed and each has a regression
test. Plus a live installed-wheel end-to-end: real RSA-2048 CMS under a
two-level PKI verified with `--trust-roots`, sealed, stamped at DigiCert's
public TSA, offline anchored (exit 0), unanchored-and-labelled (exit 0 with the
UNANCHORED TIME warning), wrong TSA root rejected fail-closed (exit 1), wrong
kid (exit 1), one-byte tamper (exit 1).
