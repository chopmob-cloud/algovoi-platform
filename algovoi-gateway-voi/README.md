# algovoi-gateway-voi

Voi chain add-on for the AlgoVoi payment gateway. Voi is an AVM chain (Algorand fork), so settlement is detected via the indexer REST API. Watches native VOI payments (`tx-type=pay`) to the merchant address with instant finality. Registers as the `voi` provider.

Config: `GATEWAY_VOI_INDEXER` (e.g. Nodely), `GATEWAY_VOI_ASSET` (default native VOI), `GATEWAY_VOI_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout is a later phase.
