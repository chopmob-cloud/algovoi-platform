# Licensing

**The AlgoVoi estate is free to use in production.** Two licences cover it, and the split is
deliberate rather than historical.

## 1. Application software — BUSL-1.1, free production use granted

Every AlgoVoi application package (the payment rails, the compliance suite, the substrate they run
on, and the standalone tools) is licensed under the **Business Source Licence 1.1** with an
Additional Use Grant. In practice:

| You may | You may not |
|---|---|
| Run it in production, at no charge, including inside a commercial product | Offer it, or a derivative, to third parties as a hosted or managed service that substitutes for it |
| Modify it and run your modification | Publish a licence key to a public registry or repository |
| Redistribute it with the licence and NOTICE intact | Remove proprietary, licence or attribution notices |
| Get the source and audit it | Exceed the deployment limit of two installs per key |

A **free licence key** is required for each deployment. Register at
<https://api.algovoi.co.uk/suite-store>; the key is issued immediately and verifies offline — no
phone-home, no callback, air-gap capable.

**Change Date: 2030-04-07.** On that date, or four years after a version's first public
distribution (whichever is earlier), that version converts to the **Apache License 2.0**.

## 2. Libraries and reference implementations — Apache-2.0

The substrate primitives and reference verifiers are **Apache-2.0**, no key, no registration:
`algovoi-substrate`, `algovoi-substrate-pqc`, `algovoi-jcs-conformance-vectors`,
`algovoi-rfc9421-*`, `algovoi-pef`, `algovoi-settlement-attestation`, the agent framework plugins,
`algovoi-keystone-*`, `avm-*`, and `av-reseal-verify`.

Why the split: an application you deploy carries operational risk and deserves a licence that says
who is responsible for what. A canonicalisation library that others import by digest should be
unencumbered, or it will not be imported.

## 3. Internal infrastructure — not published, not licensed

The store, licence fulfilment service and private package index are operational infrastructure, not
products. They are not distributed and no licence is granted to them.

## 4. Trademarks

The AlgoVoi name and logo are trademarks of Christopher Hopley. The software licences grant no
trademark rights. Fork it, rename it, ship it — do not present a fork as AlgoVoi.

## 5. Third-party components

Dependencies are permissively licensed (MIT, BSD-2/3-Clause, Apache-2.0). Each package's
`pyproject.toml` declares its own dependency set; the release SBOM (CycloneDX and SPDX) is the
authoritative list for a given version.

## 6. Support

None is included. The software is provided as is, with no warranty, maintenance, updates or service
level. Community discussion is best-efforts and voluntary. See `SUPPORT.md`.

## 7. Contact

Licensing questions: legal@ilovechicken.co.uk
Everything else: support@algovoi.co.uk
