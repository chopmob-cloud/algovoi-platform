# algovoi-gateway-hedera

Hedera chain add-on for the AlgoVoi payment gateway. Detects USDC (HTS) settlement to the merchant account via the Hedera Mirror Node REST API, with instant (consensus) finality. Accounts are `0.0.x` ids. Registers as the `hedera` provider.

Config: `GATEWAY_HEDERA_MIRROR` (e.g. mainnet-public.mirrornode.hedera.com), `GATEWAY_HEDERA_USDC` (mainnet 0.0.456858), `GATEWAY_HEDERA_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout is a later phase.
