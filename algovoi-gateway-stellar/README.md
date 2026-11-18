# algovoi-gateway-stellar

Stellar chain add-on for the AlgoVoi payment gateway. Detects USDC settlement to the merchant account via the Stellar Horizon REST API, with ledger-close finality. Stellar amounts (7 fixed decimals, as strings) are converted to integer minor units with Decimal. Registers as the `stellar` provider.

Config: `GATEWAY_STELLAR_HORIZON`, `GATEWAY_STELLAR_USDC_ISSUER` (default Circle mainnet issuer), `GATEWAY_STELLAR_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout is a later phase.
