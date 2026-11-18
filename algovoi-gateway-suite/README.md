# algovoi-gateway-suite

All-chains meta-package for the AlgoVoi payment gateway. One commercial licence
installs `algovoi-gateway-core` plus every chain provider: Algorand, Base,
Stellar, VOI, Hedera, Solana, and Tempo.

Each provider registers under the `algovoi_gateway.providers` entry point, so
`algovoi-gateway-core` discovers all seven chains automatically.

Commercial licence: `LicenseRef-AlgoVoi-Commercial-1.0`.
