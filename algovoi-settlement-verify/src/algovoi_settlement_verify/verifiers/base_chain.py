"""
Base chain (EVM L2) transaction verifier using Alchemy / JSON-RPC.

Verifies ERC-20 USDC transfers on Base mainnet and Base Sepolia.

Settlement asset:
  Mainnet:  USDC  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913  (6 decimals)
  Sepolia:  USDC  0x036CbD53842c5426634e7929541eC2318f3dCF7e  (6 decimals)

Verification flow:
  1. eth_getTransactionReceipt — confirms tx included in a block and succeeded
     (status == "0x1"). Also returns the event logs.
  2. Scan logs for an ERC-20 Transfer event where:
       log.address  == USDC contract (case-insensitive)
       topics[0]    == Transfer event signature
       topics[2]    == expected_receiver (0-padded to 32 bytes)
       data         >= expected_amount_microalgos (USDC 6-decimal microunits)
  3. Note binding: EVM transactions have no native memo field. If
     expected_note_prefix is set, we check the tx input data (calldata)
     starts with the UTF-8 hex encoding of the prefix. Callers may leave
     expected_note_prefix=None to skip this check — appropriate for
     payment links that use amount-uniqueness for reference binding.

TX hash format:   0x + 64 lowercase hex chars (66 chars total)
Address format:   0x + 40 hex chars, any case (checksummed or lowercase)
Microunits:       1 USDC = 1_000_000 microunits (same denomination as Algorand USDC)

JSON-RPC call:
  POST {rpc_url}
  {"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["0x..."],"id":1}

  result.status         "0x1" = success, "0x0" = reverted
  result.logs[]
    .address            contract that emitted the event
    .topics[0]          event signature hash
    .topics[1]          from address (32-byte padded)
    .topics[2]          to address (32-byte padded)
    .data               transfer amount (32-byte big-endian hex, no 0x prefix stripped)
"""

import logging
from decimal import Decimal

import httpx

from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

# ERC-20 Transfer(address indexed from, address indexed to, uint256 value)
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

_USDC_MAINNET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
_USDC_SEPOLIA  = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

_USDC_DECIMALS = 6  # 1 USDC = 1_000_000 microunits


def _addr_topic(address: str) -> str:
    """Normalise a 0x address into the 32-byte zero-padded topic string Ethereum uses."""
    return "0x" + address[2:].lower().zfill(64)


def _parse_uint256(hex_str: str) -> int:
    """Parse a 32-byte big-endian hex value (with or without 0x prefix)."""
    return int(hex_str, 16)


class BaseChainVerifier(BaseVerifier):
    """Verifies USDC ERC-20 transfers on Base mainnet / Base Sepolia."""

    def __init__(self, rpc_url: str, network: NetworkEnum, min_confirmations: int = 0):
        self._rpc_url = rpc_url.rstrip("/")
        self._usdc = _USDC_MAINNET if network == NetworkEnum.base_mainnet else _USDC_SEPOLIA
        # SECURITY (2026-08-19): finality depth. A mined receipt exists at ~1 block and can be REORGED out,
        # so accepting it as final is a reorg risk. Set ``min_confirmations`` > 0 to require the tx to be
        # buried that many blocks behind the chain head before it verifies. Default 0 preserves the prior
        # behaviour (the reorg-safe depth is chain/policy-specific, so it is an explicit operator choice).
        self._min_confirmations = max(0, int(min_confirmations))

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fail(self, payload: PaymentPayload, reason: str) -> VerifyResult:
        logger.warning(
            "base_chain_verify_failed",
            extra={"tx_id": payload.tx_id, "reason": reason},
        )
        return VerifyResult(
            verified=False,
            tx_id=payload.tx_id,
            network=payload.network,
            confirmed_amount=None,
            error=reason,
        )

    async def _rpc(self, client: httpx.AsyncClient, method: str, params: list) -> dict:
        resp = await client.post(
            self._rpc_url,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
            headers={"Content-Type": "application/json"},
            timeout=15.0,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Verify ────────────────────────────────────────────────────────────────

    async def verify(self, payload: PaymentPayload) -> VerifyResult:
        tx_hash = payload.tx_id.lower()
        receiver = payload.expected_receiver.lower()
        expected_microunits = payload.expected_amount_microalgos  # same denomination: 6dp

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                receipt_resp = await self._rpc(client, "eth_getTransactionReceipt", [tx_hash])
        except httpx.RequestError as exc:
            logger.error("base_chain_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC request failed")
        except Exception as exc:
            logger.error("base_chain_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC error")

        receipt = receipt_resp.get("result")

        if receipt is None:
            return self._fail(payload, "Transaction not found")

        # Check transaction succeeded on-chain
        if receipt.get("status") != "0x1":
            return self._fail(payload, "Transaction reverted or failed")

        # ── Finality: require the tx to be buried min_confirmations blocks ───
        if self._min_confirmations > 0:
            try:
                tx_block = int(receipt.get("blockNumber", "0x0"), 16)
                async with httpx.AsyncClient(timeout=15.0) as client:
                    head_resp = await self._rpc(client, "eth_blockNumber", [])
                head = int(head_resp.get("result", "0x0"), 16)
            except Exception as exc:  # noqa: BLE001
                logger.error("base_chain_finality_error", extra={"error": str(exc)})
                return self._fail(payload, "Could not determine finality")
            confirmations = head - tx_block + 1
            if confirmations < self._min_confirmations:
                return self._fail(
                    payload,
                    f"Insufficient confirmations: {confirmations} < {self._min_confirmations}")

        # ── Note binding via calldata (optional) ─────────────────────────────
        if payload.expected_note_prefix is not None:
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    tx_resp = await self._rpc(client, "eth_getTransactionByHash", [tx_hash])
                tx_data = tx_resp.get("result", {}).get("input", "0x")
                # expected_note_prefix is UTF-8 text; encode to hex for comparison
                expected_hex = "0x" + payload.expected_note_prefix.encode().hex()
                if not tx_data.lower().startswith(expected_hex.lower()):
                    return self._fail(payload, "Calldata memo binding mismatch")
            except Exception as exc:
                logger.error("base_chain_note_check_error", extra={"error": str(exc)})
                return self._fail(payload, "Could not verify calldata memo")

        # ── Scan logs for matching USDC Transfer ──────────────────────────────
        logs = receipt.get("logs", [])
        receiver_topic = _addr_topic(receiver)
        usdc_lower = self._usdc.lower()

        confirmed_amount: int | None = None
        for log in logs:
            if log.get("address", "").lower() != usdc_lower:
                continue
            topics = log.get("topics", [])
            if len(topics) < 3:
                continue
            if topics[0].lower() != _TRANSFER_TOPIC:
                continue
            if topics[2].lower() != receiver_topic:
                continue

            try:
                amount = _parse_uint256(log.get("data", "0x0"))
            except (ValueError, TypeError):
                continue

            if amount >= expected_microunits:
                confirmed_amount = amount
                break

        if confirmed_amount is None:
            return self._fail(
                payload,
                f"No USDC Transfer to {payload.expected_receiver} "
                f"for ≥ {expected_microunits} microunits found in logs",
            )

        logger.info(
            "base_chain_verified",
            extra={
                "tx_id": tx_hash,
                "network": payload.network,
                "confirmed_microunits": confirmed_amount,
            },
        )
        return VerifyResult(
            verified=True,
            tx_id=payload.tx_id,
            network=payload.network,
            confirmed_amount=confirmed_amount,
        )

    async def verify_authority_tx(self, tx_id: str, network: NetworkEnum) -> VerifyResult:
        """Confirm an EVM tx is mined without checking amount/receiver."""
        tx_hash = tx_id if tx_id.startswith("0x") else f"0x{tx_id}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                data = await self._rpc(client, "eth_getTransactionReceipt", [tx_hash])
            except Exception as exc:
                return VerifyResult(verified=False, tx_id=tx_id, network=network, error=f"RPC error: {exc}")
        receipt = data.get("result")
        if not receipt:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not found")
        if receipt.get("status") != "0x1":
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction reverted")
        return VerifyResult(verified=True, tx_id=tx_id, network=network, confirmed_amount=0)

    # ── Health ────────────────────────────────────────────────────────────────

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await self._rpc(client, "eth_blockNumber", [])
            return "result" in resp
        except Exception:
            return False
