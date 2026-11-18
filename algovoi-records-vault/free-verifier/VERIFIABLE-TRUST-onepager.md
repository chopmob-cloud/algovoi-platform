# AlgoVoi — Verifiable Trust

**AlgoVoi is the proof layer for agent and machine money: when value moves, AlgoVoi makes it provable
— and anyone can verify the proof, offline, without trusting AlgoVoi.**

Compliance and evidence products ask you to trust the vendor. AlgoVoi inverts that. Every receipt,
key, and evidence pack we produce is something your own security team can authenticate independently,
with public libraries and zero AlgoVoi code in the trust base.

## Why this wins where others ask for faith

| Buyer's real question | AlgoVoi's answer |
|---|---|
| "Can I trust the records if the vendor disappears?" | Yes. Verify them offline from the published public key alone, forever. |
| "Will this survive quantum?" | Signed with Falcon-1024 (FN-DSA-1024), a NIST PQC standard. |
| "Am I locked in?" | No. The verifier is a few hundred lines of readable Python — free to use and redistribute, no AlgoVoi code in your trust base, never calls home. |
| "How is the key bound to AlgoVoi?" | The registry is Falcon-signed and its `kid` fingerprints its own key; you anchor that key to AlgoVoi via the TLS domain (`api.algovoi.co.uk`) or a pinned fingerprint, then the signature proves everything from that anchor forward — plus per-product `did:web` identities. |
| "Will it hold up to an auditor or a court?" | A single altered byte fails verification at exactly that entry. Tamper-evidence is mechanical, not a promise. |

## The proof is live, not a slide

- **Signed key registry** — `https://api.algovoi.co.uk/.well-known/algovoi-product-keys.json`
  (Falcon-1024 signed; 3 operated keys, 15 products, key-rotation lineage). Each product also carries
  a resolvable `did:web` identity.
- **Free evidence verifier** — `algovoi_verify.py`: verifies receipts, chains, packs, the registry,
  and key lineage **offline**. Its entire trust base is two public libraries (`pqcrypto` + `rfc8785`);
  no AlgoVoi code, never calls home. Free to use and redistribute.
- **RFC 9421 signing-base verifier** — `algovoi-rfc9421-verifier` on PyPI, Apache-2.0.
- **Conformance corpus** — public, Apache-2.0, 17 sets / 131 vectors, cross-validated across 8
  independent language implementations (Python, Node, Go, Rust, Java, PHP, .NET, Ruby).
- **Standards-grounded** — RFC 9421 §2.5 conformant signing base, RFC 8785 (JCS) canonicalisation.
  Outside builders already pin their work to our corpus by digest.

## The whole pitch, in one command

```bash
bash verify_it_yourself.sh
```

The script installs its two-library trust base (`pqcrypto` + `rfc8785`) into a throwaway venv, fetches
our live signed registry, verifies it on your own machine, then changes one character and watch the
post-quantum signature catch it. Five minutes. No account. No AlgoVoi code in your trust base.

> **Don't trust AlgoVoi. Run the 5-minute verification yourself —** then let's talk about a pilot
> against your own evidence.

**pilot@algovoi.co.uk · https://docs.algovoi.co.uk/verifiable-archive**
