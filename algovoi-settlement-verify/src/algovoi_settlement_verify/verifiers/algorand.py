"""Algorand / VOI transaction verifier.

Uses two endpoints:
- algod    (node_url)    — health check only
- indexer  (indexer_url) — confirmed transaction lookup with retry
                            (see `_fetch_tx_with_retry` for rationale)

Three transaction types are verified:
  1. Native ALGO/VOI payment (payment-transaction)
  2. Native ASA transfer     (asset-transfer-transaction)
  3. ARC200 app call         (application-transaction) — VOI smart-contract tokens

ARC200 (VOI Network):
  aUSDC (naUSDC): contractId 47140315, 6 decimals, USD-pegged
  WAD:            contractId 47138068, 6 decimals, USD-pegged

  An ARC200 transfer is an application call:
    arc200_transfer(address,uint256)bool

  The indexer returns tx-type="appl" with:
    application-transaction.application-id  — must match contractId
    application-transaction.accounts        — caller-supplied foreign-accounts hint (NOT authoritative)
    application-transaction.application-args — ARC-4 encoded [selector, addr, amount]

  Recipient decoding (SECURITY):
    The recipient is decoded ONLY from application-args[1] (the ARC-4 `address` argument that
    arc200_transfer(address,uint256) actually credits). The `accounts[]` array is caller-supplied and
    does NOT bind the transfer, so it is never trusted for the recipient (trusting accounts[0] let an
    attacker spoof the recipient check while args[1] paid a different address).

  Amount decoding:
    application-args[2] decoded as big-endian unsigned int (supports uint64 and uint256).

Note binding:
  The outer tx note field works identically for all three types.

Indexer response shape (GET /v2/transactions/{txid}):
  {
    "transaction": {
      "confirmed-round": <int>,
      "payment-transaction": { "receiver": "<addr>", "amount": <int> },
      "asset-transfer-transaction": { "asset-id": <int>, "receiver": "<addr>", "amount": <int> },
      "application-transaction": {
        "application-id": <int>,
        "accounts": ["<addr>", ...],
        "application-args": ["<b64_selector>", "<b64_addr>", "<b64_amount>"]
      }
    }
  }
"""
import asyncio
import base64
import hashlib
import logging
import struct

import httpx

from algovoi_settlement_verify.schemas import ExpectedFeeLeg, NetworkEnum, PaymentPayload, VerifyResult
from algovoi_settlement_verify.verifiers.base import BaseVerifier

logger = logging.getLogger(__name__)

# Indexer retry policy for the single-tx lookup endpoint.
#
# Background: VOI (nodely.io) and, to a lesser extent, Algorand indexers
# have a lag between "tx is confirmed on the node" and "tx is queryable
# via /v2/transactions/{id}". The list endpoint /v2/transactions catches
# up faster than the single-tx endpoint. Observed on VOI 2026-04-05:
# txn confirmed at T+0, single-tx lookup returned 404 until ~T+20s,
# while the list endpoint had it almost immediately.
#
# The fix is to retry the single-tx endpoint a few times with short
# backoff. Total wall-clock budget: ~21 seconds (4 retries).
_TX_LOOKUP_MAX_ATTEMPTS = 5
_TX_LOOKUP_BACKOFFS_SECS = (1.0, 2.0, 4.0, 6.0)  # 4 sleeps between 5 attempts = ~13s + network

# ARC200 contract IDs on VOI mainnet.
# These are application calls, not native ASA transfers.
_ARC200_CONTRACT_IDS: frozenset[int] = frozenset({
    47140315,   # aUSDC (naUSDC) — DorkFi bridged USDC
    47138068,   # WAD (Whale Asset Dollar) — DorkFi overcollateralised USD
})


def _pubkey_to_address(pubkey_bytes: bytes) -> str:
    """Convert a 32-byte Algorand/VOI public key to its canonical 58-char base32 address (checksummed).

    The canonical Algorand address is the base32 of ``pubkey || sha512_256(pubkey)[-4:]`` with the ``=``
    padding stripped (58 chars). SECURITY (2026-08-19): the padding MUST be stripped so the address the
    ARC200 recipient decodes to matches ``expected_receiver`` and the indexer's own address format — the
    padded 64-char form never matched, which is why the old code fell back to the spoofable ``accounts[0]``.
    """
    chksum = hashlib.new("sha512_256", pubkey_bytes).digest()[-4:]
    return base64.b32encode(pubkey_bytes + chksum).decode().rstrip("=")


def _decode_arc200_amount(encoded: str) -> int | None:
    """
    Decode ARC-4 uint256 or uint64 from base64-encoded application arg.

    ARC200 transfers use uint256 (32 bytes big-endian) in spec,
    but some implementations emit uint64 (8 bytes).
    Returns None if decoding fails.
    """
    try:
        raw = base64.b64decode(encoded)
        return int.from_bytes(raw, "big")
    except Exception:
        return None


class AlgorandVerifier(BaseVerifier):
    def __init__(
        self,
        node_url: str,
        indexer_url: str,
        api_token: str | None = None,
    ):
        self.node_url = node_url.rstrip("/")
        self.indexer_url = indexer_url.rstrip("/")
        self.headers = {"X-Algo-API-Token": api_token} if api_token else {}

    async def _fetch_tx_with_retry(self, tx_id: str) -> httpx.Response | None:
        """
        Fetch a single transaction by id from the indexer, retrying on 404.

        Returns the final httpx.Response if the indexer eventually returned
        a 2xx, or None if all attempts 404'd (or if a non-404 error occurred
        that isn't worth retrying).

        Rationale: VOI/nodely indexer has observed lag of 10-30s on the
        single-tx endpoint vs the list endpoint. Retry with short backoff
        absorbs this lag without blocking verify calls for txns that
        genuinely don't exist (which 404 all 5 times in ~13s wall-clock
        before returning failure).
        """
        url = f"{self.indexer_url}/v2/transactions/{tx_id}"
        last_resp: httpx.Response | None = None

        async with httpx.AsyncClient(timeout=10.0) as client:
            for attempt in range(_TX_LOOKUP_MAX_ATTEMPTS):
                try:
                    resp = await client.get(url, headers=self.headers)
                except httpx.HTTPError as exc:
                    logger.warning(
                        "verifier.indexer.http_error",
                        extra={"tx_id": tx_id, "attempt": attempt, "error": str(exc)},
                    )
                    # Network errors: retry once, otherwise give up
                    if attempt >= 1:
                        return None
                    await asyncio.sleep(_TX_LOOKUP_BACKOFFS_SECS[0])
                    continue

                last_resp = resp
                if resp.status_code == 200:
                    if attempt > 0:
                        logger.info(
                            "verifier.indexer.lag_recovered",
                            extra={"tx_id": tx_id, "attempts": attempt + 1},
                        )
                    return resp

                # 404 = indexer lag (most common) OR genuinely unknown tx.
                # Any other non-200 (5xx, rate limit) is also worth retrying.
                if attempt < len(_TX_LOOKUP_BACKOFFS_SECS):
                    await asyncio.sleep(_TX_LOOKUP_BACKOFFS_SECS[attempt])

        # All attempts exhausted. last_resp is the most recent response.
        if last_resp is not None and last_resp.status_code != 200:
            logger.warning(
                "verifier.indexer.tx_not_found_after_retry",
                extra={
                    "tx_id": tx_id,
                    "attempts": _TX_LOOKUP_MAX_ATTEMPTS,
                    "final_status": last_resp.status_code,
                },
            )
        return None

    async def _fetch_group_txs(self, group_id_b64: str) -> list[dict]:
        """
        Fetch every transaction in an atomic group by querying the indexer
        list endpoint keyed on group-id. Retries with the same backoff
        policy as _fetch_tx_with_retry because the list endpoint can have
        partial-visibility windows during indexer catch-up — a single-shot
        scan may see only the merchant leg and miss the fee leg, leaking
        revenue (SEV1-D from the Phase B3-B5 audit).

        Returns the list of `transactions` (possibly empty). The caller
        treats an empty list as "group not found on indexer yet".
        """
        url = f"{self.indexer_url}/v2/transactions"
        params = {"group-id": group_id_b64}
        last_txs: list[dict] = []

        async with httpx.AsyncClient(timeout=10.0) as client:
            for attempt in range(_TX_LOOKUP_MAX_ATTEMPTS):
                try:
                    resp = await client.get(url, headers=self.headers, params=params)
                except httpx.HTTPError as exc:
                    logger.warning(
                        "verifier.indexer.group_lookup_error",
                        extra={
                            "group_id": group_id_b64,
                            "attempt": attempt,
                            "error": str(exc),
                        },
                    )
                    if attempt >= 1:
                        return []
                    await asyncio.sleep(_TX_LOOKUP_BACKOFFS_SECS[0])
                    continue

                if resp.status_code == 200:
                    txs = resp.json().get("transactions", []) or []
                    # An atomic fee group has at least 2 legs (merchant + fee).
                    # If we see fewer than 2 we're probably seeing indexer
                    # lag — retry until we see at least 2 or give up.
                    if len(txs) >= 2:
                        if attempt > 0:
                            logger.info(
                                "verifier.indexer.group_lag_recovered",
                                extra={
                                    "group_id": group_id_b64,
                                    "attempts": attempt + 1,
                                    "legs": len(txs),
                                },
                            )
                        return txs
                    last_txs = txs
                else:
                    logger.warning(
                        "verifier.indexer.group_lookup_non_200",
                        extra={
                            "group_id": group_id_b64,
                            "attempt": attempt,
                            "status": resp.status_code,
                        },
                    )

                if attempt < len(_TX_LOOKUP_BACKOFFS_SECS):
                    await asyncio.sleep(_TX_LOOKUP_BACKOFFS_SECS[attempt])

        # All attempts exhausted. Return whatever we got last (may be empty
        # or a partial group) — the caller's fee-leg check will reject it
        # either way.
        if last_txs:
            logger.warning(
                "verifier.indexer.group_partial_after_retry",
                extra={
                    "group_id": group_id_b64,
                    "attempts": _TX_LOOKUP_MAX_ATTEMPTS,
                    "legs": len(last_txs),
                },
            )
        return last_txs

    @staticmethod
    def _extract_tx_receiver_amount_and_asset(tx: dict) -> tuple[str, int, int | None]:
        """
        Pull (receiver, amount, asset_id_or_none) from an indexer transaction
        dict. Supports native ALGO/VOI payments and native ASA transfers.

        Returns ("", 0, None) if the tx is neither (e.g. ARC200 app call,
        key reg, etc.) — ARC200 fee legs are out of scope for V1.
        """
        payment = tx.get("payment-transaction")
        if payment:
            return (
                payment.get("receiver", ""),
                int(payment.get("amount", 0) or 0),
                None,
            )
        axfer = tx.get("asset-transfer-transaction")
        if axfer:
            return (
                axfer.get("receiver", ""),
                int(axfer.get("amount", 0) or 0),
                int(axfer.get("asset-id", 0) or 0),
            )
        return ("", 0, None)

    async def _verify_atomic_fee_leg(
        self,
        main_tx: dict,
        expected_fee: ExpectedFeeLeg,
        main_asset_id: int | None,
        main_tx_id: str,
    ) -> str | None:
        """
        Verify that the atomic group containing `main_tx` also contains a
        sibling transfer to `expected_fee.wallet` of at least
        `expected_fee.amount_microunits` in the same asset as main_asset_id.

        Returns None on success, or a short error string on failure. The
        error strings are opaque to the outside world — the caller wraps
        them into a generic VerifyResult.
        """
        group_id_b64 = main_tx.get("group")
        if not group_id_b64:
            return "Fee leg required but transaction is not an atomic group"

        group_txs = await self._fetch_group_txs(group_id_b64)
        if not group_txs:
            return "Fee leg required but atomic group not found on indexer"

        # Walk the group looking for the fee leg. Must be:
        #   - distinct from main_tx
        #   - same asset type (native vs ASA) as main_tx
        #   - receiver matches expected_fee.wallet
        #   - amount >= expected_fee.amount_microunits
        for sibling in group_txs:
            sibling_tx_id = sibling.get("id") or sibling.get("tx-id")
            if sibling_tx_id == main_tx_id:
                continue

            recv, amt, asset_id = self._extract_tx_receiver_amount_and_asset(sibling)
            if not recv:
                continue  # not a payment-type tx, skip
            if asset_id != main_asset_id:
                continue  # fee leg must match main asset (ALGO or same ASA)
            if recv != expected_fee.wallet:
                continue  # different receiver
            if amt < expected_fee.amount_microunits:
                # A transfer to the operator wallet exists but is short —
                # keep looking in case another sibling has the full amount.
                continue
            return None  # found a valid fee leg

        return "Fee leg missing or amount insufficient in atomic group"

    async def verify(self, payload: PaymentPayload) -> VerifyResult:
        try:
            resp = await self._fetch_tx_with_retry(payload.tx_id)
            if resp is None:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Transaction not found",
                )

            tx = resp.json().get("transaction", {})
            confirmed_round = tx.get("confirmed-round")

            if not isinstance(confirmed_round, int) or confirmed_round <= 0:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Transaction not confirmed",
                )

            # ── Branch: ARC200 app call / ASA transfer / native payment ────
            if payload.expected_asset_id and payload.expected_asset_id in _ARC200_CONTRACT_IDS:
                # ── ARC200 smart-contract token (VOI) ────────────────────────
                appl = tx.get("application-transaction")
                if not appl:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Expected ARC200 application call but transaction type differs",
                    )

                on_chain_app_id = appl.get("application-id", 0)
                if on_chain_app_id != payload.expected_asset_id:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="ARC200 contract ID mismatch",
                    )

                # Recipient — read ONLY from the signed ARC-4 argument.
                # SECURITY (2026-08-19): the ARC200 transfer recipient is the `address` argument of
                # arc200_transfer(address,uint256), i.e. application-args[1] — that is what the contract
                # actually credits. The `accounts[]` foreign-accounts array is a caller-supplied reference
                # list and does NOT bind the transfer, so trusting accounts[0] let an attacker set
                # accounts[0]=merchant (to pass the recipient check) while args[1]=attacker (the true
                # recipient): the merchant received nothing yet the settlement "verified". Never trust
                # accounts[]; decode the recipient from the ARC-4 arg or fail closed (empty receiver).
                args = appl.get("application-args", [])
                receiver = ""
                if len(args) >= 2:
                    try:
                        pubkey = base64.b64decode(args[1])
                        if len(pubkey) == 32:
                            receiver = _pubkey_to_address(pubkey)
                    except Exception:
                        receiver = ""

                # Amount — decode from args[2]
                amount = 0
                if len(args) >= 3:
                    decoded = _decode_arc200_amount(args[2])
                    if decoded is not None:
                        amount = decoded

            elif payload.expected_asset_id:
                # ── Native ASA transfer ──────────────────────────────────────
                axfer = tx.get("asset-transfer-transaction")
                if not axfer:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Expected ASA transfer but transaction type differs",
                    )

                on_chain_asset_id = axfer.get("asset-id", 0)
                if on_chain_asset_id != payload.expected_asset_id:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Asset ID mismatch",
                    )

                receiver = axfer.get("receiver", "")
                # Use only the explicit transfer amount — never count close-amount,
                # which is a remainder sent when closing an ASA position entirely.
                amount = axfer.get("amount", 0)
            else:
                # ── Native ALGO/VOI payment ──────────────────────────────────
                payment = tx.get("payment-transaction")
                if not payment:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Expected native payment but transaction type differs",
                    )

                receiver = payment.get("receiver", "")
                amount = payment.get("amount", 0)

            # ── Common checks ───────────────────────────────────────────────
            if receiver != payload.expected_receiver:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Receiver mismatch",
                )
            if amount < payload.expected_amount_microalgos:
                return VerifyResult(
                    verified=False,
                    tx_id=payload.tx_id,
                    network=payload.network,
                    error="Insufficient amount",
                )

            # Note binding check (optional — only enforced when prefix is set)
            if payload.expected_note_prefix is not None:
                raw_note = tx.get("note") or ""
                try:
                    # Algorand indexer may return standard or URL-safe base64,
                    # with or without padding.  Normalise both variants before
                    # decoding; errors="replace" keeps the check fail-closed for
                    # non-UTF-8 bytes.
                    normalised = raw_note.replace("-", "+").replace("_", "/")
                    normalised += "=" * (-len(normalised) % 4)
                    decoded_note = base64.b64decode(normalised).decode("utf-8", errors="replace")
                except Exception:
                    decoded_note = ""
                # Exact match (not prefix) — prevents crafted memos like "algovoi:tokenA_extra"
                # from matching. Verified safe: all real transactions produce exactly the
                # expected memo after strip(). See scaling_audit_actions.md.
                required_prefix = payload.expected_note_prefix
                if decoded_note.strip() != required_prefix:
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Note binding mismatch",
                    )

            # ── Billing V1 Phase B3: platform fee leg check ─────────────────
            # When expected_fee is set, the on-chain tx must belong to an
            # atomic group containing a sibling transfer to the operator
            # wallet of at least the expected amount in the same asset.
            # Fee legs for ARC200 app-call payments are out of scope — V1
            # only skims fees on native and ASA payments.
            if payload.expected_fee is not None:
                is_arc200 = (
                    payload.expected_asset_id is not None
                    and payload.expected_asset_id in _ARC200_CONTRACT_IDS
                )
                if is_arc200:
                    # V1 limitation: ARC200 app calls are never group-fee
                    # eligible. The gateway should never inject a fee on
                    # ARC200 resources; if it did, fail closed so the
                    # bug surfaces in logs rather than silently waiving.
                    return VerifyResult(
                        verified=False,
                        tx_id=payload.tx_id,
                        network=payload.network,
                        error="Fee leg not supported for ARC200 payments",
                    )
                # ASA transfers carry an asset-id; native payments don't.
                main_asset_id = (
                    int(payload.expected_asset_id)
                    if payload.expected_asset_id
                    else None
                )
                fee_error = await self._verify_atomic_fee_leg(
                    main_tx=tx,
                    expected_fee=payload.expected_fee,
                    main_asset_id=main_asset_id,
                    main_tx_id=payload.tx_id,
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
                confirmed_amount=amount,
                confirmed_round=int(confirmed_round),
            )
        except Exception:
            return VerifyResult(
                verified=False,
                tx_id=payload.tx_id,
                network=payload.network,
                error="Verification failed",
            )

    async def verify_authority_tx(self, tx_id: str, network: "NetworkEnum") -> VerifyResult:
        """Confirm an Algorand/VOI tx is on-chain without checking amount/receiver."""
        resp = await self._fetch_tx_with_retry(tx_id)
        if resp is None:
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not found")
        tx = resp.json().get("transaction", {})
        if not tx.get("confirmed-round"):
            return VerifyResult(verified=False, tx_id=tx_id, network=network, error="Transaction not confirmed")
        return VerifyResult(
            verified=True,
            tx_id=tx_id,
            network=network,
            confirmed_amount=0,
            confirmed_round=int(tx["confirmed-round"]),
        )

    async def health(self) -> bool:
        # Health check via algod (2 s timeout for Docker healthcheck window).
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"{self.node_url}/health", headers=self.headers
                )
            return resp.status_code == 200
        except Exception:
            return False
