"""
Solana transaction verifier — USDC SPL token transfers.

Uses Solana JSON-RPC getTransaction with jsonParsed encoding. Verification
is based on postTokenBalances / preTokenBalances delta so it handles all
transfer instruction variants (transfer, transferChecked, CPI inner calls).

Settlement assets:
  Mainnet:  USDC  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v  (6 decimals)
  Devnet:   USDC  4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU  (6 decimals)

Verification flow:
  1. getTransaction(signature, {encoding:"jsonParsed", commitment:"finalized"})
  2. null result → not yet finalized (call again later) or not found
  3. meta.err != null → transaction failed on-chain
  4. Scan postTokenBalances for entry where owner==expected_receiver,
     mint==USDC. Compute delta vs preTokenBalances for that accountIndex.
     delta >= expected_amount_microalgos → verified.
  5. Optional memo binding: scan meta.logMessages for Memo program output.
     Expected format: 'Program log: Memo (len N): "prefix..."'

TX signature format:  base58, 87–88 chars  [1-9A-HJ-NP-Z]
Address format:       base58, 32–44 chars  [1-9A-HJ-NP-Z]
Microunits:           1 USDC = 1_000_000 (6 decimal places)
"""

import logging
import re

import httpx

from algovoi_settlement_verify.schemas import NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

_USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
_USDC_DEVNET  = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
_USDC_DECIMALS = 6

_MEMO_LOG_RE = re.compile(r'Memo \(len \d+\): "(.+)"')


class SolanaVerifier(BaseVerifier):
    """Verifies USDC SPL token transfers on Solana mainnet / devnet."""

    def __init__(self, rpc_url: str, network: NetworkEnum):
        self._rpc_url = rpc_url.rstrip("/")
        self._usdc = _USDC_MAINNET if network == NetworkEnum.solana_mainnet else _USDC_DEVNET

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fail(self, payload: PaymentPayload, reason: str) -> VerifyResult:
        logger.warning(
            "solana_verify_failed",
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
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await self._rpc(
                    client,
                    "getTransaction",
                    [
                        payload.tx_id,
                        {
                            "encoding": "jsonParsed",
                            "commitment": "finalized",
                            "maxSupportedTransactionVersion": 0,
                        },
                    ],
                )
        except httpx.RequestError as exc:
            logger.error("solana_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC request failed")
        except Exception as exc:
            logger.error("solana_rpc_error", extra={"error": str(exc)})
            return self._fail(payload, "RPC error")

        result = resp.get("result")
        if result is None:
            return self._fail(payload, "Transaction not found or not yet finalized")

        meta = result.get("meta") or {}
        if meta.get("err") is not None:
            return self._fail(payload, "Transaction failed on-chain")

        # ── Solana Pay `reference` binding (strongest binding on Solana) ──────
        # When expected_reference_pubkey is set, the tx must include that
        # pubkey in its account keys. This cryptographically binds the
        # settling tx to a specific checkout without needing memo parsing.
        # accountKeys can appear under transaction.message.accountKeys (jsonParsed
        # returns each as {"pubkey": "...", "signer": bool, "writable": bool}).
        if getattr(payload, "expected_reference_pubkey", None):
            tx_msg = ((result.get("transaction") or {}).get("message") or {})
            raw_keys = tx_msg.get("accountKeys") or []
            account_pubkeys: set[str] = set()
            for entry in raw_keys:
                if isinstance(entry, dict):
                    pk = entry.get("pubkey")
                    if pk:
                        account_pubkeys.add(pk)
                elif isinstance(entry, str):
                    account_pubkeys.add(entry)
            # Loaded addresses (address lookup tables) — ALT-resolved accounts
            # appear under meta.loadedAddresses.{writable,readonly}. Reference
            # accounts are read-only so are likely under `readonly` if looked up.
            loaded = meta.get("loadedAddresses") or {}
            for pk in (loaded.get("writable") or []) + (loaded.get("readonly") or []):
                account_pubkeys.add(pk)

            if payload.expected_reference_pubkey not in account_pubkeys:
                return self._fail(
                    payload,
                    "Reference pubkey not present in transaction accounts",
                )

        # ── Optional memo binding (legacy / integrator-opt-in) ────────────────
        if payload.expected_note_prefix is not None:
            memo_found = False
            for log_line in meta.get("logMessages") or []:
                m = _MEMO_LOG_RE.search(log_line)
                if m and m.group(1).startswith(payload.expected_note_prefix):
                    memo_found = True
                    break
            if not memo_found:
                return self._fail(payload, "Memo binding not found in transaction logs")

        # ── USDC balance delta check ──────────────────────────────────────────
        # Build a pre-balance map for the USDC mint: accountIndex → amount
        pre_map: dict[int, int] = {
            entry["accountIndex"]: int(entry["uiTokenAmount"]["amount"])
            for entry in (meta.get("preTokenBalances") or [])
            if entry.get("mint") == self._usdc
        }

        # Scan post-balances for the expected receiver
        for entry in (meta.get("postTokenBalances") or []):
            if entry.get("mint") != self._usdc:
                continue
            if entry.get("owner") != payload.expected_receiver:
                continue

            post_amount = int(entry["uiTokenAmount"]["amount"])
            pre_amount = pre_map.get(entry["accountIndex"], 0)
            received = post_amount - pre_amount

            if received >= payload.expected_amount_microalgos:
                logger.info(
                    "solana_verified",
                    extra={
                        "tx_id": payload.tx_id,
                        "network": payload.network,
                        "confirmed_microunits": received,
                    },
                )
                return VerifyResult(
                    verified=True,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    confirmed_amount=received,
                )

        return self._fail(
            payload,
            f"No USDC transfer to {payload.expected_receiver} "
            f"for ≥ {payload.expected_amount_microalgos} microunits found",
        )

    async def verify_authority_tx(self, tx_id: str, network: NetworkEnum) -> VerifyResult:
        """Confirm a Solana tx is finalized without checking amount/receiver."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                data = await self._rpc(client, "getTransaction", [tx_id, {"encoding": "json", "commitment": "finalized"}])
            except Exception as exc:
                return VerifyResult(verified=False, tx_id=tx_id, network=network, error=f"RPC error: {exc}")
        result = data.get("result")
        if result is None:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not found or not finalized")
        if result.get("meta", {}).get("err") is not None:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction failed on-chain")
        return VerifyResult(verified=True, tx_id=tx_id, network=network, confirmed_amount=0)

    # ── Health ────────────────────────────────────────────────────────────────

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await self._rpc(client, "getHealth", [])
            return resp.get("result") == "ok"
        except Exception:
            return False
