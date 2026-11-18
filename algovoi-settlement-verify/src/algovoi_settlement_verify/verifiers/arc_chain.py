"""
ARC chain (EVM L1 — Arc Network) transaction verifier using JSON-RPC.

ARC is a purpose-built L1 for programmable money with USDC as the native
gas token. Settlement asset is USDC at the precompile/wrapper address
0x3600000000000000000000000000000000000000.

Chain:
  Testnet Chain ID:  5042002
  RPC:               https://rpc.testnet.arc.io  (legacy rpc.testnet.arc.network still resolves)
  Explorer:          testnet.arcscan.app
  Status:            testnet only as of 2026-08 (mainnet not yet live)

IMPORTANT: ARC USDC has 18 decimal places, not the standard 6.
All amounts stored internally as 6dp microunits must be scaled by 10^12
before comparing against on-chain Transfer event data values.

Verification flow:
  1. eth_getTransactionReceipt — confirms tx included in a block and
     succeeded (status == "0x1"). Also returns the event logs.
  2. Scan logs for an ERC-20 Transfer event where:
       log.address  == ARC USDC contract (0x3600...)
       topics[0]    == Transfer event signature
       topics[2]    == expected_receiver (0-padded to 32 bytes)
       data (18dp)  >= expected_amount_microalgos * 10^12
  3. Confirmed amount is returned scaled back to 6dp microunits so the
     payment ledger stays in the platform-standard denomination.

References:
  https://docs.arc.io/arc/references/contract-addresses
  https://docs.arc.io/build/agentic-economy (ERC-8004, ERC-8183)
"""

import logging

import httpx

from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

# ERC-20 Transfer(address indexed from, address indexed to, uint256 value)
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# ARC USDC — the native gas token exposed as an ERC-20 wrapper.
# Same address on both testnet and (future) mainnet per Arc docs.
_USDC_TESTNET = "0x3600000000000000000000000000000000000000"

# ARC USDC uses 18 decimal places. Platform microunits are 6dp.
# Multiply 6dp microunits by this factor to get on-chain 18dp base units.
_MICROUNIT_SCALE = 10 ** 12  # 10^(18 - 6)


def _addr_topic(address: str) -> str:
    """Normalise a 0x address into the 32-byte zero-padded topic string Ethereum uses."""
    return "0x" + address[2:].lower().zfill(64)


def _parse_uint256(hex_str: str) -> int:
    """Parse a 32-byte big-endian hex value (with or without 0x prefix)."""
    return int(hex_str, 16)


class ArcChainVerifier(BaseVerifier):
    """Verifies USDC ERC-20 transfers on ARC testnet (and future mainnet)."""

    def __init__(self, rpc_url: str, network: NetworkEnum, min_confirmations: int = 0):
        self._rpc_url = rpc_url.rstrip("/")
        # Single USDC address across testnet (mainnet address TBD — update here when live)
        self._usdc = _USDC_TESTNET
        # SECURITY (2026-08-19): finality depth — see BaseChainVerifier. Set >0 to require the tx to be
        # buried that many blocks behind the head before it verifies (reorg protection). Default preserved.
        self._min_confirmations = max(0, int(min_confirmations))

    def _fail(self, payload: PaymentPayload, reason: str) -> VerifyResult:
        logger.warning(
            "arc_chain_verify_failed",
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

    async def verify(self, payload: PaymentPayload) -> VerifyResult:
        tx_hash = payload.tx_id.lower()
        receiver = payload.expected_receiver.lower()

        # Scale from platform 6dp microunits to ARC's 18dp base units.
        # Example: 1_000_000 microunits (1 USDC) → 1_000_000_000_000_000_000 (10^18)
        expected_arc_units = payload.expected_amount_microalgos * _MICROUNIT_SCALE

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                receipt_resp = await self._rpc(client, "eth_getTransactionReceipt", [tx_hash])
        except httpx.RequestError as exc:
            logger.error("arc_chain_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC request failed")
        except Exception as exc:
            logger.error("arc_chain_rpc_error", extra={"error": str(exc)})
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

        # Optional note/calldata binding
        if payload.expected_note_prefix is not None:
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    tx_resp = await self._rpc(client, "eth_getTransactionByHash", [tx_hash])
                tx_data = tx_resp.get("result", {}).get("input", "0x")
                expected_hex = "0x" + payload.expected_note_prefix.encode().hex()
                if not tx_data.lower().startswith(expected_hex.lower()):
                    return self._fail(payload, "Calldata memo binding mismatch")
            except Exception as exc:
                logger.error("arc_chain_note_check_error", extra={"error": str(exc)})
                return self._fail(payload, "Could not verify calldata memo")

        # Scan logs for matching USDC Transfer event
        logs = receipt.get("logs", [])
        receiver_topic = _addr_topic(receiver)
        usdc_lower = self._usdc.lower()

        confirmed_arc_units: int | None = None
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

            if amount >= expected_arc_units:
                confirmed_arc_units = amount
                break

        if confirmed_arc_units is None:
            return self._fail(
                payload,
                f"No USDC Transfer to {payload.expected_receiver} "
                f"for >= {expected_arc_units} arc-units ({payload.expected_amount_microalgos} microunits) "
                f"found in logs",
            )

        # Convert confirmed amount back to 6dp microunits for the ledger
        confirmed_microunits = confirmed_arc_units // _MICROUNIT_SCALE

        logger.info(
            "arc_chain_verified",
            extra={
                "tx_id": tx_hash,
                "network": payload.network,
                "confirmed_arc_units": confirmed_arc_units,
                "confirmed_microunits": confirmed_microunits,
            },
        )
        return VerifyResult(
            verified=True,
            tx_id=payload.tx_id,
            network=payload.network,
            confirmed_amount=confirmed_microunits,
        )

    async def verify_authority_tx(self, tx_id: str, network: NetworkEnum) -> VerifyResult:
        """Confirm an ARC (EVM) tx is mined without checking amount/receiver."""
        tx_hash = tx_id if tx_id.startswith("0x") else f"0x{tx_id}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                data = await self._rpc(client, "eth_getTransactionReceipt", [tx_hash])
            except Exception as exc:
                return VerifyResult(
                    verified=False, tx_id=tx_id, network=network,
                    error=f"RPC error: {exc}",
                )
        receipt = data.get("result")
        if not receipt:
            return VerifyResult(
                verified=False, tx_id=tx_id, network=network,
                error="Transaction not found",
            )
        if receipt.get("status") != "0x1":
            return VerifyResult(
                verified=False, tx_id=tx_id, network=network,
                error="Transaction reverted",
            )
        return VerifyResult(verified=True, tx_id=tx_id, network=network, confirmed_amount=0)

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await self._rpc(client, "eth_blockNumber", [])
            return "result" in resp
        except Exception:
            return False
