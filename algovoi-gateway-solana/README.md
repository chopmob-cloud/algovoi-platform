# algovoi-gateway-solana

Solana chain add-on for the AlgoVoi payment gateway. Detects USDC (SPL token) settlement to the merchant USDC token account via JSON-RPC (`getSignaturesForAddress` + `getTransaction`, token-balance delta) with a finality rule on the transaction commitment. Registers as the `solana` provider.

Config: `GATEWAY_SOLANA_RPC_URL` (use a keyed provider for production, e.g. Helius/QuickNode; free public RPCs heavily rate-limit), `GATEWAY_SOLANA_USDC_MINT`, `GATEWAY_SOLANA_LOOKBACK`.

Receive-and-verify in Phase 1; custody/payout (`sign_and_pay`) is a later phase.

## ATA-sponsorship anti-griefing bounds

`ensure_recipient_ata(owner, mint=None)` is a payout preflight that makes sure a recipient's associated
token account exists (idempotent `CreateAssociatedTokenAccountIdempotent`), funding the account rent
(~0.002 SOL) from the operator key. Because it spends operator SOL, sponsorship is currently bounded so a
flood of first-time-recipient requests cannot drain the operator (the x402 #1020 ATA-sponsorship griefing
vector). It fails closed on each bound; the calling endpoint remains the first line of defence and MUST
still only invoke it for a validated recipient.

- `GATEWAY_SOLANA_ALLOWED_MINTS` — comma-separated mints that may be sponsored. Default: the configured
  USDC mint (`GATEWAY_SOLANA_USDC_MINT`). A request for any other mint is refused.
- `GATEWAY_SOLANA_MIN_OPERATOR_SOL_LAMPORTS` — floor the operator balance must stay above (after paying
  rent) or sponsorship is refused. Default: `50000000` (0.05 SOL).
- `GATEWAY_SOLANA_MAX_ATA_RENT_LAMPORTS` — cap on the rent a single create may cost, blocking Token-2022
  extension-account rent abuse. Default: `3000000` (0.003 SOL).
