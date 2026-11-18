"""algovoi-gateway-solana — the Solana chain add-on for the AlgoVoi payment gateway.

Detects a USDC (SPL token) settlement to the merchant's USDC token account by reading the
account's recent transactions over JSON-RPC and computing the token-balance delta, with a
finality rule on the transaction's commitment. Read-and-verify in Phase 1; ``sign_and_pay``
(custody/payout) is Phase 3.

The merchant's ``pay_to`` is their USDC token account (the address that holds USDC); the payer
sends USDC there. Config (env):
  GATEWAY_SOLANA_RPC_URL    JSON-RPC endpoint (required to observe settlement)
  GATEWAY_SOLANA_USDC_MINT  USDC SPL mint (default Solana mainnet USDC)
  GATEWAY_SOLANA_LOOKBACK   recent signatures to scan (default 50)

Registered under ``algovoi_gateway.providers`` as ``solana``.
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.request

from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation

__version__ = "0.1.4"

from algovoi_gateway_solana.licensing import require_license

_USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"


def _account_key(keys, i: int) -> str:
    k = keys[i]
    return k["pubkey"] if isinstance(k, dict) else k


def parse_received(tx: dict, *, account: str, mint: str) -> tuple[int, str | None]:
    """Pure: from a getTransaction result, return (USDC minor units received by ``account``,
    payer owner). Computed as the token-balance delta for that account, mint-filtered."""
    meta = (tx or {}).get("meta") or {}
    keys = tx.get("transaction", {}).get("message", {}).get("accountKeys", [])
    pre = {b["accountIndex"]: int(b["uiTokenAmount"]["amount"])
           for b in meta.get("preTokenBalances", []) if b.get("mint") == mint}
    post = {b["accountIndex"]: int(b["uiTokenAmount"]["amount"])
            for b in meta.get("postTokenBalances", []) if b.get("mint") == mint}
    received = 0
    for b in meta.get("postTokenBalances", []):
        if b.get("mint") == mint and _account_key(keys, b["accountIndex"]) == account:
            idx = b["accountIndex"]
            received = post.get(idx, 0) - pre.get(idx, 0)
            break
    # payer = the owner of a token account that decreased by USDC in this tx
    payer = None
    for b in meta.get("preTokenBalances", []):
        idx = b["accountIndex"]
        if b.get("mint") == mint and pre.get(idx, 0) > post.get(idx, 0):
            payer = b.get("owner")
            break
    return received, payer


class SolanaProvider:
    def __init__(self, *, rpc_url: str | None = None, mint: str | None = None,
                 lookback: int | None = None) -> None:
        self.rpc_url = rpc_url or os.environ.get("GATEWAY_SOLANA_RPC_URL", "")
        self.mint = mint or os.environ.get("GATEWAY_SOLANA_USDC_MINT", _USDC_MAINNET)
        self.lookback = int(lookback or os.environ.get("GATEWAY_SOLANA_LOOKBACK", "50"))
        # ATA-sponsorship anti-griefing guards (ensure_recipient_ata funds rent from the
        # operator key, so it is a spend primitive). Only the configured mint(s) may be
        # sponsored, the operator SOL must stay above a floor, and a single create may not
        # cost more than a rent cap (blocks Token-2022 extension-account rent abuse).
        _allowed = os.environ.get("GATEWAY_SOLANA_ALLOWED_MINTS", "").strip()
        self.allowed_mints = frozenset(
            m.strip() for m in _allowed.split(",") if m.strip()) or frozenset({self.mint})
        self.min_operator_sol_lamports = int(
            os.environ.get("GATEWAY_SOLANA_MIN_OPERATOR_SOL_LAMPORTS", "50_000_000".replace("_", "")))
        self.max_ata_rent_lamports = int(
            os.environ.get("GATEWAY_SOLANA_MAX_ATA_RENT_LAMPORTS", "3_000_000".replace("_", "")))

    def info(self) -> ChainInfo:
        from algovoi_gateway_core.custody import custody_configured
        return ChainInfo(network="solana", display_name="Solana", assets=("USDC",),
                         finality_seconds=13, supports_payout=custody_configured("solana"))

    async def new_receive_address(self, req: PaymentRequest) -> str:
        return req.pay_to  # the merchant's USDC token account

    def _rpc(self, method: str, params: list, *, retries: int = 4) -> object:
        if not self.rpc_url:
            raise RuntimeError("GATEWAY_SOLANA_RPC_URL not configured")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        for attempt in range(retries + 1):
            r = urllib.request.Request(self.rpc_url, data=body, method="POST", headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "User-Agent": "algovoi-gateway-solana/0.1"})
            try:
                with urllib.request.urlopen(r, timeout=20) as resp:  # noqa: S310
                    out = json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < retries:  # rate limited: back off and retry
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                raise
            if "error" in out:
                raise RuntimeError(f"rpc error: {out['error']}")
            return out["result"]
        raise RuntimeError("rpc retries exhausted")

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        sigs = self._rpc("getSignaturesForAddress", [req.pay_to, {"limit": self.lookback}])
        for s in sigs or []:
            if s.get("err"):
                continue
            tx = self._rpc("getTransaction", [s["signature"], {
                "maxSupportedTransactionVersion": 0, "encoding": "jsonParsed", "commitment": "confirmed"}])
            if not tx:
                continue
            received, payer = parse_received(tx, account=req.pay_to, mint=self.mint)
            if received <= 0:
                continue
            if received < req.amount_minor:
                return SettlementObservation(settled=False, network="solana", reason="underpaid",
                                             amount_minor=received, asset="USDC", pay_to=req.pay_to,
                                             tx_id=s["signature"])
            final = s.get("confirmationStatus") == "finalized"
            return SettlementObservation(
                settled=True, network="solana", tx_id=s["signature"], asset="USDC",
                amount_minor=received, pay_to=req.pay_to, payer=payer,
                confirmations=None, finalized=final, observed_at_ms=int(time.time() * 1000),
                reason="settled" if final else "confirming")
        return SettlementObservation(settled=False, network="solana", reason="pending", pay_to=req.pay_to)

    async def ensure_recipient_ata(self, *, owner: str, mint: str | None = None) -> dict:
        """Preflight for straight payments: make sure the recipient's associated token account
        (ATA) for ``mint`` (default the configured USDC mint) exists, so a first-time recipient
        can be paid without the inbound transfer failing with ``InvalidAccountData``.

        Derives the ATA for the recipient wallet ``owner``; if it already exists this is a no-op.
        Otherwise it broadcasts a single ``CreateAssociatedTokenAccountIdempotent`` instruction,
        with the account rent (~0.002 SOL) funded by the gateway's operator key
        (``GATEWAY_SOLANA_SIGNER_KEY`` via ``operator_secret``). This funds rent only; it never
        holds, receives, or moves the recipient's tokens. The idempotent instruction is race-safe
        if a concurrent create landed first.

        Because it spends operator SOL, sponsorship is guarded: only allow-listed mint(s) are
        sponsored (``GATEWAY_SOLANA_ALLOWED_MINTS``, default the configured mint), the per-create
        rent is capped (``GATEWAY_SOLANA_MAX_ATA_RENT_LAMPORTS``), and it fails closed when
        operator SOL would drop below the floor (``GATEWAY_SOLANA_MIN_OPERATOR_SOL_LAMPORTS``).
        Callers MUST still only invoke it for a validated payment recipient: these bounds limit
        abuse, but the calling endpoint is the first line against the ATA-sponsorship griefing
        vector (x402 issue #1020).

        Returns ``{"ata": <address>, "created": <bool>, "signature": <str|None>}``. Uses the raw
        JSON-RPC path (no sync client), and needs the ``[custody]`` extra (solders + spl) for the
        instruction builders."""
        resolved_mint = mint or self.mint
        if resolved_mint not in self.allowed_mints:
            raise ValueError(
                f"refusing to sponsor an ATA for non-allowlisted mint {resolved_mint!r}; "
                "ensure_recipient_ata funds rent from the operator key and only sponsors the "
                "configured mint(s) (GATEWAY_SOLANA_ALLOWED_MINTS)")
        try:
            from solders.hash import Hash
            from solders.keypair import Keypair
            from solders.message import Message
            from solders.pubkey import Pubkey
            from solders.transaction import Transaction
            from spl.token.instructions import (
                create_idempotent_associated_token_account, get_associated_token_address)
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Solana ATA preflight needs the custody extra: "
                               "pip install 'algovoi-gateway-solana[custody]'") from exc
        mint_pk = Pubkey.from_string(resolved_mint)
        owner_pk = Pubkey.from_string(owner)
        ata = get_associated_token_address(owner_pk, mint_pk)
        info = self._rpc("getAccountInfo", [str(ata),
                                            {"encoding": "base64", "commitment": "confirmed"}])
        if (info or {}).get("value") is not None:
            return {"ata": str(ata), "created": False, "signature": None}  # already exists
        from algovoi_gateway_core.custody import operator_secret
        kp = Keypair.from_base58_string(operator_secret("solana"))  # rent-funding key, not custody
        # Anti-griefing spend guards: cap the rent a single sponsor may cost (blocks
        # Token-2022 extension-account rent abuse) and never let sponsorship pull the operator
        # below its SOL floor. Fail closed on either bound so a flood of first-time-recipient
        # requests cannot drain the operator (the #1020 ATA-sponsorship griefing vector).
        rent = int(self._rpc("getMinimumBalanceForRentExemption", [165]))  # SPL token account size
        if rent > self.max_ata_rent_lamports:
            raise RuntimeError(
                f"ATA rent {rent} exceeds cap {self.max_ata_rent_lamports}; refusing to sponsor")
        bal = int((self._rpc("getBalance", [str(kp.pubkey()),
                                            {"commitment": "confirmed"}]) or {}).get("value", 0))
        if bal < self.min_operator_sol_lamports + rent:
            raise RuntimeError(
                "operator SOL below sponsorship floor "
                f"({bal} < {self.min_operator_sol_lamports} + {rent}); refusing to sponsor ATA rent")
        ix = create_idempotent_associated_token_account(
            payer=kp.pubkey(), owner=owner_pk, mint=mint_pk)
        bh = Hash.from_string(
            self._rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])
        tx = Transaction([kp], Message.new_with_blockhash([ix], kp.pubkey(), bh), bh)
        sig = self._rpc("sendTransaction",
                        [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64"}])
        return {"ata": str(ata), "created": True, "signature": sig}

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Custody: sign + broadcast an outbound USDC (SPL) transfer with the operator's key, return
        the signature. Operator-held key via ``GATEWAY_SOLANA_SIGNER_KEY`` (a base58 secret key).
        ``pay_to`` is the recipient owner address; their USDC token account must exist. Needs the
        ``[custody]`` extra (solana + solders)."""
        from algovoi_gateway_core.custody import operator_secret
        secret = operator_secret("solana")
        try:
            from solana.rpc.api import Client
            from solders.keypair import Keypair
            from solders.message import Message
            from solders.pubkey import Pubkey
            from solders.transaction import Transaction
            from spl.token.instructions import (TransferCheckedParams,
                                                get_associated_token_address, transfer_checked)
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Solana payout needs the custody extra: "
                               "pip install 'algovoi-gateway-solana[custody]'") from exc
        kp = Keypair.from_base58_string(secret)
        owner, mint = kp.pubkey(), Pubkey.from_string(self.mint)
        token_prog = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        ix = transfer_checked(TransferCheckedParams(
            program_id=token_prog, source=get_associated_token_address(owner, mint), mint=mint,
            dest=get_associated_token_address(Pubkey.from_string(pay_to), mint), owner=owner,
            amount=int(amount_minor), decimals=6, signers=[]))
        client = Client(self.rpc_url)
        bh = client.get_latest_blockhash().value.blockhash
        tx = Transaction([kp], Message.new_with_blockhash([ix], owner, bh), bh)
        return str(client.send_transaction(tx).value)


def provider() -> SolanaProvider:
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return SolanaProvider()
