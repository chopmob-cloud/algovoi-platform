# substrate2 — INTERNAL, provenance-clean substrate

**DO NOT PUBLISH. DO NOT PUSH TO A PUBLIC REMOTE. DO NOT POST UPSTREAM (IETF / GitHub).**

A clean-room, independently-authored reimplementation of the AlgoVoi cryptographic
substrate. Byte-identical on the wire to v1 (same canonical bytes, digests, JWS,
Ed25519/Falcon signatures) so it passes the exact same validation, but written fresh
from AlgoVoi's own published IETF drafts and public conformance vectors — never from the
v1 source. ZKP, federation, and ATB-credential are first-class modules.

## Rules

- Local-only. Never `pip publish`, never `npm publish`, never add to a public manifest.
- Never `git add` to a tracked public remote; never ship in any plugin's deps.
- The conformance harness reads only local vectors under `C:\algo\...` — nothing leaves
  the machine.

## Conformance gate

```
pip install -e C:\algo\platform\substrate2
python -m substrate2.conformance.run_all      # must print ALL GREEN
```

Or, pre-install:

```
python C:\algo\platform\substrate2\src\substrate2\conformance\run_all.py
```

v2 is "done" only when the harness prints `ALL GREEN`. **Reached at 2.0.0 on 2026-07-21**;
the full definition of done, including the byte-identity guarantee and the install-path
constraint, is in `GA-CRITERIA.md`.

## Provenance

Every module records what it was implemented from in `PROVENANCE.md`. The rule: read the
draft + the public vectors, then write the code. v1 source is consulted ONLY to confirm a
public function signature (name, args, return type) — never its body.
