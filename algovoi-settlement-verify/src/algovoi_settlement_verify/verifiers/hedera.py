"""
Hedera transaction verifier using the Mirror Node REST API.

Uses the Hedera Mirror Node (read-only REST, no gRPC / hedera-sdk needed).
No API key is required for the public mirror node endpoint.

Two transaction types are verified:
  1. Native HBAR payment (CRYPTOTRANSFER with tinybar transfers)
  2. HTS (Hedera Token Service) token transfer

HBAR microunits: 1 HBAR = 100_000_000 tinybars.
HTS token amounts: stored as-is in the token_transfers array (already in smallest unit).

TX ID normalisation:
  Payer wallets submit: 0.0.ACCT@SECONDS.NANOSECONDS  (@ and . separators)
  Mirror Node URL expects: 0.0.ACCT-SECONDS-NANOSECONDS  (all hyphens)
  This verifier normalises automatically.

Mirror Node transaction response shape:
  GET /api/v1/transactions/{tx_id}
  {
    "transactions": [{
      "consensus_timestamp": "...",
      "name": "CRYPTOTRANSFER",
      "memo_base64": "<base64>",
      "transfers": [
        {"account": "0.0.SENDER", "amount": -100, "is_approval": false},
        {"account": "0.0.RECEIVER", "amount": 100, "is_approval": false}
      ],
      "token_transfers": [
        {"token_id": "0.0.456858", "account": "0.0.RECEIVER", "amount": 100}
      ]
    }]
  }

Note binding:
  memo_base64 is standard base64; decoded UTF-8 must start with expected_note_prefix
  (e.g. "algovoi:{token}").
"""

import base64
import re
import logging

import httpx

from algovoi_settlement_verify.schemas import ExpectedFeeLeg, NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

# Mirror Node TX ID format uses hyphens: 0.0.ACCT-SECONDS-NANOSECONDS
_TX_NORMALIZE_RE = re.compile(r"^(0\.\d+\.\d+)[@](\d+)[.](\d+)$")


def _normalize_tx_id(tx_id: str) -> str:
    """
    Convert 0.0.ACCT@SECONDS.NANOSECONDS → 0.0.ACCT-SECONDS-NANOSECONDS.
    If already in hyphen format, return as-is.
    """
    m = _TX_NORMALIZE_RE.match(tx_id)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    # Already hyphen-separated (or unknown format — pass through, let Mirror Node reject)
    return tx_id


def _verify_hedera_fee_leg(
    *,
    tx: dict,
    expected_fee: ExpectedFeeLeg,
    expected_asset_id: int | str | None,
) -> str | None:
    """
    Verify that a Hedera CryptoTransfer transaction contains a fee leg
    crediting the operator wallet in the same asset as the main payment.

    - Native HBAR payment → scan `transfers` for entry
        account == expected_fee.wallet AND amount >= expected_fee.amount_microunits
    - HTS token payment → scan `token_transfers` for entry
        token_id == 0.0.<expected_asset_id> AND account == expected_fee.wallet
        AND amount >= expected_fee.amount_microunits

    Operator wallet is the full Hedera account ID (e.g. "0.0.1317927").

    Returns None on success, short error string on failure.
    """
    if expected_asset_id is not None:
        # HTS fee leg
        token_id = f"0.0.{expected_asset_id}"
        received = 0
        for transfer in tx.get("token_transfers", []) or []:
            if (
                transfer.get("token_id") == token_id
                and transfer.get("account") == expected_fee.wallet
                and transfer.get("amount", 0) > 0
            ):
                received += int(transfer.get("amount", 0))
        if received == 0:
            return "Fee leg missing (no HTS token transfer to operator wallet)"
        if received < expected_fee.amount_microunits:
            return "Fee leg amount insufficient (HTS token)"
        return None

    # Native HBAR fee leg
    received = 0
    for transfer in tx.get("transfers", []) or []:
        if (
            transfer.get("account") == expected_fee.wallet
            and transfer.get("amount", 0) > 0
            and not transfer.get("is_approval", False)
        ):
            received += int(transfer.get("amount", 0))
    if received == 0:
        return "Fee leg missing (no HBAR transfer to operator wallet)"
    if received < expected_fee.amount_microunits:
        return "Fee leg amount insufficient (HBAR)"
    return None


class HederaVerifier(BaseVerifier):
    def __init__(self, mirror_node_url: str):
        self.base_url = mirror_node_url.rstrip("/")

    async def verify(self, payload: PaymentPayload) -> VerifyResult:
        try:
            mirror_tx_id = _normalize_tx_id(payload.tx_id)
            url = f"{self.base_url}/api/v1/transactions/{mirror_tx_id}"

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url)

            if resp.status_code == 404:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Transaction not found",
                )
            if resp.status_code != 200:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Transaction lookup failed",
                )

            data = resp.json()
            transactions = data.get("transactions", [])
            if not transactions:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Transaction not found in Mirror Node response",
                )

            tx = transactions[0]

            # Verify transaction reached consensus (has a consensus_timestamp)
            if not tx.get("consensus_timestamp"):
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Transaction not yet confirmed",
                )

            # Check transaction result — only UNKNOWN or SUCCESS is valid
            tx_result = tx.get("result", "")
            if tx_result not in ("SUCCESS", ""):
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error=f"Transaction failed on-chain: {tx_result}",
                )

            receiver = payload.expected_receiver  # e.g. "0.0.12345"

            if payload.expected_asset_id:
                # ── HTS token transfer ───────────────────────────────────────
                # HTS token IDs are stored as the account serial number (int).
                # Reconstruct the full HTS token ID as "0.0.{asset_id}".
                token_id = f"0.0.{payload.expected_asset_id}"
                token_transfers = tx.get("token_transfers", [])

                received_amount = 0
                for transfer in token_transfers:
                    if (
                        transfer.get("token_id") == token_id
                        and transfer.get("account") == receiver
                        and transfer.get("amount", 0) > 0
                    ):
                        received_amount += transfer.get("amount", 0)

                if received_amount == 0:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error=f"No HTS token transfer found to {receiver} for token {token_id}",
                    )

                if received_amount < payload.expected_amount_microalgos:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Insufficient HTS token amount",
                    )

                confirmed_amount = received_amount

            else:
                # ── Native HBAR transfer ─────────────────────────────────────
                # transfers array contains all accounts; find positive entry for receiver
                transfers = tx.get("transfers", [])
                received_tinybars = 0
                for transfer in transfers:
                    if (
                        transfer.get("account") == receiver
                        and transfer.get("amount", 0) > 0
                        and not transfer.get("is_approval", False)
                    ):
                        received_tinybars += transfer.get("amount", 0)

                if received_tinybars == 0:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error=f"No HBAR transfer found to {receiver}",
                    )

                if received_tinybars < payload.expected_amount_microalgos:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Insufficient HBAR amount",
                    )

                confirmed_amount = received_tinybars

            # ── Note / memo binding check ────────────────────────────────────
            if payload.expected_note_prefix is not None:
                memo_b64 = tx.get("memo_base64", "") or ""
                try:
                    decoded_memo = base64.b64decode(memo_b64).decode("utf-8", errors="replace").strip()
                except Exception:
                    decoded_memo = ""

                if decoded_memo != payload.expected_note_prefix:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Memo binding mismatch",
                    )

            # ── Billing V1 Phase B4: platform fee leg check ─────────────────
            # Hedera CryptoTransfer natively supports multi-party transfers
            # in a single transaction — the `transfers` (HBAR) and
            # `token_transfers` (HTS) arrays contain every party. There's
            # no atomic-group fetch to do; we just scan the same tx for
            # an entry crediting the operator wallet in the same asset.
            if payload.expected_fee is not None:
                fee_error = _verify_hedera_fee_leg(
                    tx=tx,
                    expected_fee=payload.expected_fee,
                    expected_asset_id=payload.expected_asset_id,
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
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error=fee_error,
                    )

            return VerifyResult(
                verified=True,
                tx_id=payload.tx_id,
                network=payload.network,
                confirmed_amount=confirmed_amount,
            )

        except Exception:
            logger.exception("hedera.verifier.error", extra={"tx_id": payload.tx_id})
            return VerifyResult(
                verified=False,
                tx_id=payload.tx_id,
                network=payload.network,
                error="Verification failed",
            )

    async def verify_authority_tx(self, tx_id: str, network: NetworkEnum) -> VerifyResult:
        """Confirm a Hedera tx is on-chain without checking amount/receiver."""
        mirror_tx_id = _normalize_tx_id(tx_id)
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{self.base_url}/api/v1/transactions/{mirror_tx_id}")
        except httpx.HTTPError as exc:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error=f"Network error: {exc}")
        if resp.status_code == 404:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not found")
        if resp.status_code != 200:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction lookup failed")
        txs = resp.json().get("transactions", [])
        if not txs:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not found")
        if txs[0].get("result") != "SUCCESS":
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction failed on-chain")
        return VerifyResult(verified=True, tx_id=tx_id, network=network, confirmed_amount=0)

    async def health(self) -> bool:
        """Health check via Mirror Node network fees endpoint (lightweight, no tx needed)."""
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(f"{self.base_url}/api/v1/network/fees")
            return resp.status_code == 200
        except Exception:
            return False
