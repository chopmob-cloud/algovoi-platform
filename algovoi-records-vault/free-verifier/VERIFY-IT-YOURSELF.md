# Verify It Yourself — 5 minutes, your terminal, our reputation on the line

> **Don't trust AlgoVoi. Verify us.** In five minutes you will cryptographically prove, on your own
> machine, that AlgoVoi's evidence is genuine, post-quantum signed, and tamper-evident — with **no
> AlgoVoi code in your trust base** and **nothing phoning home** except one HTTPS GET of our public,
> signed registry.

Your entire trust base is two public, audited-primitive libraries:

```bash
pqcrypto + rfc8785
```

## The one command

```bash
bash verify_it_yourself.sh
```

That's it. The script installs the two libraries into an isolated `.venv` (so it never touches your
system packages), fetches our live signed key registry, verifies every Falcon-1024 signature
**offline**, then changes one character of a signed key and shows you the signature catch it.

> Prefer to do it by hand? The whole trust base is two libraries in a throwaway venv:
> ```bash
> python3 -m venv .venv && . .venv/bin/activate    # Debian/Ubuntu: sudo apt install python3-venv first
> pip install pqcrypto rfc8785
> ```

## What you will see

```
3/4  Verify it — offline, from the published public key alone
PASS registry kid binds to its public key cf36870dd671f95a
PASS Falcon-1024 signature over registry payload
INFO valid_until 2026-07-13T18:57:55Z | operated keys 3 | products 15
RESULT: PRODUCT REGISTRY VERIFIED            <- exit 0

4/4  Now break it — change ONE character of a signed key, re-verify
FAIL Falcon-1024 signature over registry payload
RESULT: REGISTRY VERIFICATION FAILED         <- exit 1
```

The first run passes. The tampered run fails — at exactly the altered entry.

## What you just proved (without trusting us)

- **Authenticity** — the registry was signed by the holder of the key published at
  `api.algovoi.co.uk`, and its `kid` is a SHA-256 fingerprint of that key. You anchor that key to
  AlgoVoi the way you anchor any signer: by the TLS domain you fetched it from, or by pinning the
  fingerprint `cf36870dd671f95a` out-of-band. The signature then proves everything *from that anchor
  forward* — true of every signature system, X.509 included.
- **Integrity** — the evidence is genuine, unaltered, and offline-verifiable, into the post-quantum
  era (Falcon-1024 / FN-DSA-1024, re-derived by you).
- **Tamper-evidence** — a single altered byte is caught, at exactly that entry.
- **Continuity** — key-rotation lineage is cross-signed (old key endorses new), so a decades-old
  anchor's succession is provable, not asserted.
- **No lock-in** — the verifier is a few hundred lines of readable Python you can audit in full, free
  to use and redistribute. It never calls home, never needs a secret key, and never needs an AlgoVoi
  service running.

This is the difference between a vendor *claiming* its records are trustworthy and you *proving* it —
to an auditor, a court, or your own security team, years after the receipt was signed.

## Do it with your own evidence next

The same verifier checks a receipt, an evidence chain, a full pack, or a key-rotation lineage:

```bash
python algovoi_verify.py receipt   receipt.txt public_key.b64
python algovoi_verify.py chain      access_chain.json public_key.b64
python algovoi_verify.py pack       ./evidence-pack/     <expected_kid>
python algovoi_verify.py keys       rotation_proofs.json <genesis_kid>
```

A receipt or chain is anchored by construction, because you hand it the public key. A pack or a key
lineage carries its key *inside the artifact*, so pass the `kid` you pinned out-of-band — the same
anchor described above. Without it the verifier still re-derives every signature, but it reports
`INTACT, KEY NOT ANCHORED` and exits `3` rather than `0`, because an unanchored artifact proves
integrity and not authorship.

Spin up a pilot and point this script at receipts *you* generated. When it exits `0`, that evidence
is yours to defend — no AlgoVoi in the loop.

**Talk to us:** pilot@algovoi.co.uk · https://docs.algovoi.co.uk/verifiable-archive
