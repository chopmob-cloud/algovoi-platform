# algovoi-license

The shared offline licence gate for AlgoVoi commercial add-ons (the Tier B protection default).

A licence-gated add-on becomes a two-line gate instead of a copied module with an embedded key to keep
in sync:

```python
from algovoi_license import require_license

require_license("algovoi-command-center-totp")   # call at load time; fail-closed
```

Verification is fully offline: the buyer's Falcon-1024-signed licence is checked against the embedded
issuer public key. It accepts the suite `bundle_license` (runs every component in the on-prem bundle) or
a per-package `oem_license` matching the name you pass. No network, no phone-home.

`rfc8785` and `pqcrypto` are soft imports: they ship with the licensed suite, so a gated add-on works
wherever it legitimately runs, and a lifted standalone install that lacks them fails closed.

Provide the licence via env `ALGOVOI_LICENSE_KEY` (the key string) or `ALGOVOI_LICENSE_FILE` (a path).

## Delegated Mesh-federation issuers

Alongside the two direct licence types, `verify_license_offline` accepts a **delegated** per-package
licence: an `oem_license` envelope that carries an `issuer_cert`. This lets an AV-RAILS operator run a
Mesh federation and allocate licences to its OWN members with no per-agent purchase, while the AlgoVoi
root signature plus a name constraint stop it minting for anyone outside its namespace.

- `verify_fed_issuer_cert(cert, root_pub, package)` → `(ok, fed_pub, constraints, reason)`. Verifies a
  root-signed `fed_issuer_v1` cert: it is signed by the AlgoVoi root over its JCS-canonical `payload`,
  names the federation Falcon-1024 public key (`fed_pub`, 1793 bytes), is scoped to one `package`,
  time-limited (`expires_at`), and carries a non-empty list of DID-prefix `name_constraint` entries.
  Every check fails closed.
- `within_name_constraint(did, constraints)` → `bool`. True only when `did` falls within one of the
  DID-prefix constraints at a syntax boundary (`:`, `/`, `#`, `?`), so `did:web:acme.example` matches
  `did:web:acme.example:agent-7` but not `did:web:acme.example.evil.com`. Empty / `*` / non-DID
  constraints are ignored, so a delegated issuer must be genuinely constrained.

When an `oem_license` envelope carries an `issuer_cert`, the licence signature is verified against the
federation key the root vouched for (not the root itself), and every `agent_dids` entry must fall inside
the cert's name constraint. Only per-package licences may be delegated; a delegated envelope with no
holder or a holder outside the namespace is rejected. Both `within_name_constraint` and
`verify_fed_issuer_cert` are exported in `__all__`.

BUSL-1.1. Free to use in production with a free licence key. Embeds only a public verification key;
no secret is distributed. See LICENSING.md at the repository root.
