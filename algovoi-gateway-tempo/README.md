# algovoi-gateway-tempo

Tempo chain add-on for the AlgoVoi payment gateway. Tempo is an EVM L1 (TIP-20 is an ERC-20 superset), so USDCe settlement is detected exactly as on Base; this add-on reuses the proven Base/EVM provider configured for Tempo. Registers as the `tempo` provider.

Config: `GATEWAY_TEMPO_RPC_URL` (mainnet chain-id 4217 / testnet 42431), `GATEWAY_TEMPO_USDCE`, `GATEWAY_TEMPO_CONFIRMATIONS`, `GATEWAY_TEMPO_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout is a later phase.
