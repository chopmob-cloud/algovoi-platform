# AlgoVoi Platform

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

The AlgoVoi application estate: payment rails, verifiable compliance, and the post-quantum
substrate they share. **Free to use in production** under BUSL-1.1 with an Additional Use Grant; a
free licence key is required per deployment and verifies offline.

- **Get a licence key:** https://api.algovoi.co.uk/suite-store
- **Documentation:** https://docs.algovoi.co.uk
- **Licensing:** see `LICENSING.md`
- **Security:** see `SECURITY.md`

## What is here

| Layer | Packages |
|---|---|
| Substrate | `substrate2`, `algovoi-substrate2-controlplane`, `algovoi-license` |
| Payment rails | `algovoi-gateway-core`, the seven chain providers, `algovoi-gateway-suite` |
| Agent identity and control | `algovoi-agent-passport`, `algovoi-payment-mandate`, `algovoi-mandate-auditor`, `algovoi-edge-sentinel`, `algovoi-substrate-guard-pro` |
| Compliance estate | `algovoi-command-center`, `algovoi-records-vault*`, `algovoi-recovery-vault`, `algovoi-doc-archive*`, `algovoi-retention-*`, `algovoi-sanctions-monitor`, `algovoi-travel-rule`, `algovoi-audit-log`, `algovoi-compliance-gate`, `algovoi-archive-auditor` |
| Evidence tools | `algovoi-evidence-audit`, `algovoi-reseal`, `algovoi-proofs`, `algovoi-federation-validator`, `algovoi-zkp-receipt` |

Each package is self-contained: `pip install -e .` from its directory, or build a wheel with
`python -m build`.

## Support

None is included. The software is provided as is; community discussion is best-efforts. See
`SUPPORT.md`. For regulated use, your counsel certifies your compliance — the software supplies
verifiable evidence, not a certification.

## Licence

BUSL-1.1 with an Additional Use Grant permitting free production use. Converts to Apache-2.0 on
2030-04-07. See `LICENSE` and `LICENSING.md`. The AlgoVoi name and logo are trademarks; no trademark
licence is granted.
