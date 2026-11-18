# algovoi-gateway-base

Base (EVM) chain add-on for the AlgoVoi payment gateway. Detects USDC settlement to the merchant address via JSON-RPC `Transfer` logs with a confirmations finality rule, and emits signed settlement receipts through `algovoi-gateway-core`. Registers as the `base` provider.

Config: `GATEWAY_BASE_RPC_URL`, `GATEWAY_BASE_USDC`, `GATEWAY_BASE_CONFIRMATIONS`, `GATEWAY_BASE_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout (`sign_and_pay`) is a later phase.
