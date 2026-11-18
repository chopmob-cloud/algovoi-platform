"""algovoi-gateway-hedera — the Hedera chain add-on for the AlgoVoi payment gateway.

Detects a USDC (HTS token) settlement to the merchant account by reading the Hedera Mirror
Node REST API for successful cryptotransfers, with Hedera's instant (consensus) finality.
Accounts are ``0.0.x`` ids; amounts are integer minor units. Read-and-verify in Phase 1;
``sign_and_pay`` (custody/payout) is Phase 3.

Config (env):
  GATEWAY_HEDERA_MIRROR   mirror node base URL (default Hedera mainnet public mirror)
  GATEWAY_HEDERA_USDC      USDC HTS token id (default mainnet USDC 0.0.456858)
  GATEWAY_HEDERA_LOOKBACK  recent transactions to scan (default 50)

Registered under ``algovoi_gateway.providers`` as ``hedera``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation

__version__ = "0.1.4"

from algovoi_gateway_hedera.licensing import require_license

_MIRROR_MAINNET = "https://mainnet-public.mirrornode.hedera.com"
_USDC_MAINNET = "0.0.456858"


def parse_settlement(txns: list, *, merchant: str, token_id: str, amount_minor: int) -> SettlementObservation:
    """Pure: find a successful cryptotransfer crediting ``token_id`` to ``merchant`` for at
    least ``amount_minor``. The payer is the account debited for that token."""
    underpaid = None
    for t in txns:
        if t.get("result") != "SUCCESS":
            continue
        tts = t.get("token_transfers", [])
        credit = next((x for x in tts if x.get("token_id") == token_id
                       and x.get("account") == merchant and int(x.get("amount", 0)) > 0), None)
        if not credit:
            continue
        amount = int(credit["amount"])
        if amount < amount_minor:
            underpaid = SettlementObservation(settled=False, network="hedera", reason="underpaid",
                                              amount_minor=amount, asset="USDC", pay_to=merchant,
                                              tx_id=t.get("transaction_id"))
            continue
        payer = next((x["account"] for x in tts if x.get("token_id") == token_id
                      and int(x.get("amount", 0)) < 0), None)
        return SettlementObservation(
            settled=True, network="hedera", tx_id=t.get("transaction_id"), asset="USDC",
            amount_minor=amount, pay_to=merchant, payer=payer, confirmations=None,
            finalized=True, observed_at_ms=int(time.time() * 1000), reason="settled")
    return underpaid or SettlementObservation(settled=False, network="hedera", reason="pending", pay_to=merchant)


class HederaProvider:
    def __init__(self, *, mirror: str | None = None, token_id: str | None = None,
                 lookback: int | None = None) -> None:
        self.mirror = (mirror or os.environ.get("GATEWAY_HEDERA_MIRROR", _MIRROR_MAINNET)).rstrip("/")
        self.token_id = token_id or os.environ.get("GATEWAY_HEDERA_USDC", _USDC_MAINNET)
        self.lookback = int(lookback or os.environ.get("GATEWAY_HEDERA_LOOKBACK", "50"))

    def info(self) -> ChainInfo:
        from algovoi_gateway_core.custody import custody_configured
        return ChainInfo(network="hedera", display_name="Hedera", assets=("USDC",),
                         finality_seconds=5, supports_payout=custody_configured("hedera"))

    async def new_receive_address(self, req: PaymentRequest) -> str:
        return req.pay_to

    def _get(self, path: str, params: dict, *, retries: int = 3) -> object:
        url = f"{self.mirror}{path}?" + urllib.parse.urlencode(params)
        for attempt in range(retries + 1):
            r = urllib.request.Request(url, method="GET", headers={
                "Accept": "application/json", "User-Agent": "algovoi-gateway-hedera/0.1"})
            try:
                with urllib.request.urlopen(r, timeout=20) as resp:  # noqa: S310
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < retries:
                    time.sleep(0.5 * (2 ** attempt)); continue
                raise

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        out = self._get("/api/v1/transactions", {
            "account.id": req.pay_to, "transactiontype": "cryptotransfer",
            "result": "success", "order": "desc", "limit": self.lookback})
        return parse_settlement(out.get("transactions", []) if out else [],
                                merchant=req.pay_to, token_id=self.token_id,
                                amount_minor=req.amount_minor)

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Custody: sign + submit an outbound USDC (HTS) or HBAR transfer with the operator's key,
        return the transaction id. Operator-held key via ``GATEWAY_HEDERA_SIGNER_KEY`` in the form
        ``<accountId>:<privateKey>`` (Hedera needs both). Set ``GATEWAY_HEDERA_NETWORK`` to
        ``mainnet`` or ``testnet``. Needs the ``[custody]`` extra (hiero-sdk-python)."""
        from algovoi_gateway_core.custody import operator_secret
        op_id, _, op_key = operator_secret("hedera").partition(":")
        if not op_key:
            raise RuntimeError("GATEWAY_HEDERA_SIGNER_KEY must be '<accountId>:<privateKey>'")
        try:
            from hiero_sdk_python import (AccountId, Client, Network, PrivateKey, TokenId,
                                          TransferTransaction)
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Hedera payout needs the custody extra: "
                               "pip install 'algovoi-gateway-hedera[custody]'") from exc
        client = Client(Network(network=os.environ.get("GATEWAY_HEDERA_NETWORK", "mainnet")))
        client.set_operator(AccountId.from_string(op_id), PrivateKey.from_string(op_key))
        sender, recipient, amt = AccountId.from_string(op_id), AccountId.from_string(pay_to), int(amount_minor)
        tx = TransferTransaction()
        if asset and asset.upper() == "USDC":
            tok = TokenId.from_string(self.token_id)
            tx.add_token_transfer(tok, sender, -amt).add_token_transfer(tok, recipient, amt)
        else:
            tx.add_hbar_transfer(sender, -amt).add_hbar_transfer(recipient, amt)
        receipt = tx.execute(client)
        return str(getattr(receipt, "transaction_id", receipt))


def provider() -> HederaProvider:
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return HederaProvider()
