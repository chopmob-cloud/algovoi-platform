# algovoi-gateway-algorand

Algorand chain add-on for the AlgoVoi payment gateway (our native chain). Detects USDC (ASA) settlement to the merchant address via the Algorand indexer, with Algorand instant (single-block) finality. Registers as the `algorand` provider.

Config: `GATEWAY_ALGORAND_INDEXER` (e.g. AlgoNode), `GATEWAY_ALGORAND_USDC_ASA` (mainnet 31566704), `GATEWAY_ALGORAND_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout (`sign_and_pay`) is a later phase.
