"""
Stellar transaction verifier using the Horizon REST API.

Verifies:
  1. Native XLM payment (asset_type="native")
  2. USDC / credit_alphanum4 / credit_alphanum12 token payments (trust-lined asset)
  3. Path payments delivering the expected asset to the merchant
     (path_payment_strict_send / path_payment_strict_receive) — e.g. a customer
     swapping XLM -> USDC via Stellar DEX and delivering USDC to the merchant.
  4. Fee-bump transactions — if Horizon returns `inner_transaction`, the memo
     and operations live on the INNER tx, not the outer fee-bump wrapper.

XLM stroops: 1 XLM = 10_000_000 stroops. Horizon returns amounts as decimal
strings (e.g. "123.4567890") — convert with Decimal to avoid float drift.

TX hash format: 64 lowercase hex chars. Stellar transaction hashes are the
SHA-256 of the transaction envelope XDR.

Horizon response shapes used:
  GET /transactions/{tx_hash}
    -> top-level tx, memo_type, memo, successful, inner_transaction
  GET /transactions/{tx_hash}/operations?limit=100
    -> payment operations list; `limit=100` matches Stellar's per-tx op cap
       (default is 10, which would miss any payment buried past index 10 in a
       batched transaction).

Memo binding:
  Horizon exposes `memo_type` ("none"/"text"/"id"/"hash"/"return") and `memo`
  on the transaction object. For MEMO_TEXT the `memo` field contains the
  decoded UTF-8 text directly. Algo/VOI/Hedera use "algovoi:{token}" but
  Stellar's MEMO_TEXT is limited to 28 bytes, so Stellar links use the
  shorter "av:{token[:20]}" memo (stored in payment_links.memo_note_prefix).

Fee-bump transactions:
  Stellar CAP-15 fee-bumps wrap an inner transaction. Horizon returns:
    {
      "hash": "<outer>",
      "memo_type": "none",     # outer never has memo
      "fee_account": "G...",
      "inner_transaction": {
        "hash": "<inner>",
        "max_fee": "...",
      }
    }
  The real memo + operations live on the INNER tx. A customer paying via a
  fee-bump wrapper (common with sponsored fees) would be rejected by a naive
  verifier that reads memo off the outer transaction. This verifier detects
  fee-bumps and re-fetches the inner tx automatically.

Compound asset_id format:
  For non-native Stellar assets (USDC), expected_asset_id is a STRING in
  "CODE:ISSUER" format — e.g. "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".
"""

import logging
from decimal import Decimal

import httpx

from algovoi_settlement_verify.schemas import ExpectedFeeLeg, NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

_STROOPS_PER_XLM = 10_000_000

# Operation types that deliver value to a destination account.
# `payment` is the classic transfer. `path_payment_strict_send` and
# `path_payment_strict_receive` are DEX swaps where the destination asset
# fields (`asset_type`, `asset_code`, `asset_issuer`, `to`, `amount`) describe
# what the merchant actually received. We ignore `account_merge` and
# `create_account` for now — those are edge cases that most merchant flows
# won't encounter and carry different amount semantics (a followup can add
# them if operational experience shows demand).
_PAYMENT_OP_TYPES = frozenset(
    {
        "payment",
        "path_payment_strict_send",
        "path_payment_strict_receive",
    }
)

# Horizon ops pagination: default is 10, Stellar per-tx max is 100.
_OPS_PAGE_LIMIT = 100


def _verify_stellar_fee_leg(
    *,
    ops: list[dict],
    expected_fee: ExpectedFeeLeg,
    expected_code: str | None,
    expected_issuer: str | None,
    merchant_receiver: str,
) -> str | None:
    """
    Scan a list of Stellar transaction operations for a platform fee leg
    crediting `expected_fee.wallet` in the same asset as the main payment
    for at least `expected_fee.amount_microunits` stroops (or token units).

    V1 restriction (SEV1-C audit fix): ONLY plain `payment` ops are
    accepted for the fee leg — path_payment_strict_send and
    path_payment_strict_receive are rejected because their `amount` field
    has different semantics per op type (source vs destination amount),
    creating a slippage attack vector where the operator receives less
    than what the fee-check believed was committed.

    The main merchant leg still accepts path_payment ops because the
    merchant receives the destination amount regardless of slippage. The
    operator cannot absorb slippage risk — exact-amount delivery is
    required for the fee leg.

    - Native XLM (expected_code is None): op.asset_type must be "native"
    - Credit asset: op.asset_type must be credit_alphanum{4,12} AND
      asset_code + asset_issuer must match expected

    Returns None on success, short error string on failure.
    """
    required = expected_fee.amount_microunits
    if required <= 0:
        return None

    for op in ops:
        op_type = op.get("type")
        # V1: Only plain payment ops accepted for fee legs — path_payments
        # carry slippage risk where amount != what the operator receives.
        if op_type != "payment":
            continue
        if op.get("to") != expected_fee.wallet:
            continue
        # Defensive: merchant and operator wallets should be distinct.
        # If they happen to match, refuse to credit a merchant-leg as the
        # fee leg.
        if merchant_receiver == expected_fee.wallet:
            continue

        if expected_code is None:
            if op.get("asset_type") != "native":
                continue
        else:
            if op.get("asset_type") not in ("credit_alphanum4", "credit_alphanum12"):
                continue
            if op.get("asset_code") != expected_code:
                continue
            if op.get("asset_issuer") != expected_issuer:
                continue

        try:
            amount_stroops = int(Decimal(str(op.get("amount", "0"))) * _STROOPS_PER_XLM)
        except Exception:
            continue

        if amount_stroops < required:
            continue

        return None  # valid fee leg found

    return "Fee leg missing or amount insufficient"


class StellarVerifier(BaseVerifier):
    def __init__(self, horizon_url: str):
        self.base_url = horizon_url.rstrip("/")

    async def verify(self, payload: PaymentPayload) -> VerifyResult:
        try:
            # ── Fetch the transaction by its user-submitted hash ─────────────
            async with httpx.AsyncClient(timeout=10.0) as client:
                tx_resp = await client.get(f"{self.base_url}/transactions/{payload.tx_id}")

            if tx_resp.status_code == 404:
                return self._fail(payload, "Transaction not found")
            if tx_resp.status_code != 200:
                return self._fail(payload, "Transaction lookup failed")

            tx = tx_resp.json()

            if not tx.get("successful"):
                return self._fail(payload, "Transaction failed on-chain")

            # ── Fee-bump unwrap (M3) ─────────────────────────────────────────
            # If Horizon returns `inner_transaction`, the memo + ops live on
            # the inner tx, not the outer fee-bump wrapper. Re-fetch the
            # inner transaction and use its hash for the operations lookup.
            inner = tx.get("inner_transaction") or {}
            inner_hash = inner.get("hash") if isinstance(inner, dict) else None
            if inner_hash:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    inner_resp = await client.get(
                        f"{self.base_url}/transactions/{inner_hash}"
                    )
                if inner_resp.status_code != 200:
                    return self._fail(payload, "Inner transaction lookup failed")
                tx = inner_resp.json()
                if not tx.get("successful"):
                    return self._fail(payload, "Inner transaction failed on-chain")
                ops_tx_hash = inner_hash
            else:
                ops_tx_hash = payload.tx_id

            # ── Memo binding check ───────────────────────────────────────────
            if payload.expected_note_prefix is not None:
                memo_type = tx.get("memo_type", "none")
                memo = tx.get("memo", "") or ""
                if memo_type != "text" or memo != payload.expected_note_prefix:
                    return self._fail(payload, "Memo binding mismatch")

            # ── Fetch payment operations (M2: explicit limit=100) ────────────
            async with httpx.AsyncClient(timeout=10.0) as client:
                ops_resp = await client.get(
                    f"{self.base_url}/transactions/{ops_tx_hash}/operations"
                    f"?limit={_OPS_PAGE_LIMIT}"
                )

            if ops_resp.status_code != 200:
                return self._fail(payload, "Operations lookup failed")

            ops = ops_resp.json().get("_embedded", {}).get("records", [])

            receiver = payload.expected_receiver
            expected_amount_stroops = payload.expected_amount_microalgos

            # Determine expected asset (native XLM vs credit asset)
            expected_code: str | None = None
            expected_issuer: str | None = None
            if payload.expected_asset_id is not None and payload.expected_asset_id != 0:
                raw = str(payload.expected_asset_id)
                if ":" not in raw:
                    return self._fail(
                        payload,
                        "Invalid Stellar asset_id (expected CODE:ISSUER)",
                    )
                expected_code, expected_issuer = raw.split(":", 1)

            # ── Scan operations for a matching delivery (M1: path_payments) ──
            confirmed_amount: int | None = None
            for op in ops:
                op_type = op.get("type")
                if op_type not in _PAYMENT_OP_TYPES:
                    continue
                # `to` is the G-address receiver for both payment and
                # path_payment ops. If merchant stored only the G form, this
                # matches even when a muxed source was used (Horizon exposes
                # the muxed form in `to_muxed`, the G form in `to`).
                if op.get("to") != receiver:
                    continue

                # Destination asset fields describe what the merchant actually
                # received, for both payment and path_payment_* ops.
                if expected_code is None:
                    if op.get("asset_type") != "native":
                        continue
                else:
                    if op.get("asset_type") not in ("credit_alphanum4", "credit_alphanum12"):
                        continue
                    if op.get("asset_code") != expected_code:
                        continue
                    if op.get("asset_issuer") != expected_issuer:
                        continue

                # `amount` is the delivered amount for all three op types.
                amount_str = op.get("amount", "0")
                try:
                    amount_stroops = int(Decimal(str(amount_str)) * _STROOPS_PER_XLM)
                except Exception:
                    continue

                if amount_stroops < expected_amount_stroops:
                    continue

                confirmed_amount = amount_stroops
                break

            if confirmed_amount is None:
                return self._fail(payload, "No matching payment operation")

            # ── Billing V1 Phase B5: platform fee leg check ─────────────────
            # Stellar multi-operation transactions carry multiple payment
            # ops in the same tx. Scan the already-fetched ops list for a
            # sibling operation crediting the operator wallet in the same
            # asset as the main leg.
            if payload.expected_fee is not None:
                fee_error = _verify_stellar_fee_leg(
                    ops=ops,
                    expected_fee=payload.expected_fee,
                    expected_code=expected_code,
                    expected_issuer=expected_issuer,
                    merchant_receiver=receiver,
                )
                if fee_error is not None:
                    logger.warning(
                        "verifier.fee_leg.rejected",
                        extra={
                            "tx_id": payload.tx_id,
                            "network": payload.network,
                            "reason": fee_error,
                        },
                    )
                    return self._fail(payload, fee_error)

            return VerifyResult(
                verified=True,
                tx_id=payload.tx_id,
                network=payload.network,
                confirmed_amount=confirmed_amount,
            )

        except Exception:
            logger.exception("stellar.verifier.error", extra={"tx_id": payload.tx_id})
            return self._fail(payload, "Verification failed")

    @staticmethod
    def _fail(payload: PaymentPayload, error: str) -> VerifyResult:
        return VerifyResult(
            verified=False,
            tx_id=payload.tx_id,
            network=payload.network,
            error=error,
        )

    async def verify_authority_tx(self, tx_id: str, network: NetworkEnum) -> VerifyResult:
        """Confirm a Stellar tx is on-chain without checking amount/receiver."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{self.base_url}/transactions/{tx_id}")
        except httpx.HTTPError as exc:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error=f"Network error: {exc}")
        if resp.status_code == 404:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not found")
        if resp.status_code != 200:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction lookup failed")
        if not resp.json().get("successful"):
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction failed on-chain")
        return VerifyResult(verified=True, tx_id=tx_id, network=network, confirmed_amount=0)

    async def health(self) -> bool:
        """Health check via Horizon root (returns version info, lightweight)."""
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.base_url}/")
            return resp.status_code == 200
        except Exception:
            return False
