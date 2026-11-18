"""
Tempo chain (EVM L1) transaction verifier using Alchemy / JSON-RPC.

Verifies TIP-20 USDCe transfers on Tempo mainnet and Tempo testnet (Moderato).

Settlement asset:
  Mainnet:  USDCe  0x20c000000000000000000000b9537d11c60e8b50  (6 decimals)
  Testnet:  USDCe  0x20c000000000000000000000b9537d11c60e8b50  (same contract — update if Moderato differs)

Chain IDs:
  Mainnet:  4217   (CAIP-2: eip155:4217)
  Testnet:  42431  (CAIP-2: eip155:42431)

Tempo uses the TIP-20 token standard — a superset of ERC-20.  The Transfer
event signature and log layout are identical to ERC-20, so the verification
logic mirrors BaseChainVerifier exactly.

Verification flow:
  1. eth_getTransactionReceipt — confirms tx included in a block and succeeded
     (status == "0x1"). Also returns the event logs.
  2. Scan logs for a TIP-20/ERC-20 Transfer event where:
       log.address  == USDCe contract (case-insensitive)
       topics[0]    == Transfer event signature
       topics[2]    == expected_receiver (0-padded to 32 bytes)
       data         >= expected_amount_microalgos (USDC 6-decimal microunits)
  3. Note binding: if expected_note_prefix is set, we check the tx input data
     (calldata) starts with the UTF-8 hex encoding of the prefix.

TX hash format:   0x + 64 lowercase hex chars (66 chars total)
Address format:   0x + 40 hex chars, any case (checksummed or lowercase)
Microunits:       1 USDC = 1_000_000 microunits (same denomination as Algorand USDC)
"""

import logging

import httpx

from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

# ERC-20 / TIP-20 Transfer(address indexed from, address indexed to, uint256 value)
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

_USDC_MAINNET = "0x20c000000000000000000000b9537d11c60e8b50"
_USDC_TESTNET  = "0x20c000000000000000000000b9537d11c60e8b50"  # Moderato — update if address differs

_USDC_DECIMALS = 6  # 1 USDCe = 1_000_000 microunits


def _addr_topic(address: str) -> str:
    """Normalise a 0x address into the 32-byte zero-padded topic string Ethereum uses."""
    return "0x" + address[2:].lower().zfill(64)


def _parse_uint256(hex_str: str) -> int:
    """Parse a 32-byte big-endian hex value (with or without 0x prefix)."""
    return int(hex_str, 16)


class TempoChainVerifier(BaseVerifier):
    """Verifies USDCe TIP-20 transfers on Tempo mainnet / Tempo testnet (Moderato)."""

    def __init__(self, rpc_url: str, network: NetworkEnum, min_confirmations: int = 0):
        self._rpc_url = rpc_url.rstrip("/")
        self._usdc = _USDC_MAINNET if network == NetworkEnum.tempo_mainnet else _USDC_TESTNET
        # SECURITY (2026-08-19): finality depth — see BaseChainVerifier. Set >0 for reorg protection.
        self._min_confirmations = max(0, int(min_confirmations))

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fail(self, payload: PaymentPayload, reason: str) -> VerifyResult:
        logger.warning(
            "tempo_chain_verify_failed",
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
            logger.error("tempo_chain_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC request failed")
        except Exception as exc:
            logger.error("tempo_chain_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC error")

        receipt = receipt_resp.get("result")

        if receipt is None:
            return self._fail(payload, "Transaction not found")

        if receipt.get("status") != "0x1":
            return self._fail(payload, "Transaction reverted or failed")

        # ── Finality: require the tx to be buried min_confirmations blocks ───
        if self._min_confirmations > 0:
            try:
                tx_block = int(receipt.get("blockNumber", "0x0"), 16)
                async with httpx.AsyncClient(timeout=15.0) as client:
                    head_resp = await self._rpc(client, "eth_blockNumber", [])
                head = int(head_resp.get("result", "0x0"), 16)
            except Exception:  # noqa: BLE001
                return self._fail(payload, "Could not determine finality")
            if head - tx_block + 1 < self._min_confirmations:
                return self._fail(
                    payload, f"Insufficient confirmations: {head - tx_block + 1} < {self._min_confirmations}")

        # ── Note binding via calldata (optional) ─────────────────────────────
        if payload.expected_note_prefix is not None:
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    tx_resp = await self._rpc(client, "eth_getTransactionByHash", [tx_hash])
                tx_data = tx_resp.get("result", {}).get("input", "0x")
                expected_hex = "0x" + payload.expected_note_prefix.encode().hex()
                if not tx_data.lower().startswith(expected_hex.lower()):
                    return self._fail(payload, "Calldata memo binding mismatch")
            except Exception as exc:
                logger.error("tempo_chain_note_check_error", extra={"error": str(exc)})
                return self._fail(payload, "Could not verify calldata memo")

        # ── Scan logs for matching USDCe Transfer ─────────────────────────────
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
                f"No USDCe Transfer to {payload.expected_receiver} "
                f"for ≥ {expected_microunits} microunits found in logs",
            )

        logger.info(
            "tempo_chain_verified",
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
        """Confirm a Tempo (EVM) tx is mined without checking amount/receiver."""
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
