"""algovoi-gateway-voi — the Voi chain add-on for the AlgoVoi payment gateway.

Voi is an AVM chain (an Algorand fork), so settlement is detected through the same indexer
REST API. Voi's primary settlement asset is the native VOI token, transferred via a payment
transaction (``tx-type=pay``), so this provider watches native VOI payments to the merchant
address with Voi's instant (single-block) finality. (An ASA mode mirrors the Algorand add-on
if you settle a bridged token instead.)

Config (env):
  GATEWAY_VOI_INDEXER   indexer base URL (default Nodely Voi mainnet indexer)
  GATEWAY_VOI_ASSET     "VOI" (native, default) or an ASA id for a bridged token
  GATEWAY_VOI_LOOKBACK  recent transactions to scan (default 50)

Registered under ``algovoi_gateway.providers`` as ``voi``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation

__version__ = "0.1.3"

from algovoi_gateway_voi.licensing import require_license

_INDEXER_MAINNET = "https://mainnet-idx.voi.nodely.dev"
_ALGOD_MAINNET = "https://mainnet-api.voi.nodely.dev"


def parse_native_payment(txns: list, *, pay_to: str, amount_minor: int) -> SettlementObservation:
    """Pure: find a native VOI payment to ``pay_to`` with amount >= ``amount_minor``.
    Voi finality is instant, so any confirmed transaction is final."""
    underpaid = None
    for t in txns:
        pay = t.get("payment-transaction")
        if not pay or pay.get("receiver") != pay_to:
            continue
        amount = int(pay.get("amount", 0))
        if amount < amount_minor:
            underpaid = SettlementObservation(settled=False, network="voi", reason="underpaid",
                                              amount_minor=amount, asset="VOI", pay_to=pay_to,
                                              tx_id=t.get("id"))
            continue
        return SettlementObservation(
            settled=True, network="voi", tx_id=t.get("id"), asset="VOI",
            amount_minor=amount, pay_to=pay_to, payer=t.get("sender"),
            confirmations=t.get("confirmed-round"), finalized=bool(t.get("confirmed-round")),
            observed_at_ms=int(time.time() * 1000), reason="settled")
    return underpaid or SettlementObservation(settled=False, network="voi", reason="pending", pay_to=pay_to)


class VoiProvider:
    def __init__(self, *, indexer: str | None = None, asset: str | None = None,
                 lookback: int | None = None, algod: str | None = None) -> None:
        self.indexer = (indexer or os.environ.get("GATEWAY_VOI_INDEXER", _INDEXER_MAINNET)).rstrip("/")
        self.asset = asset or os.environ.get("GATEWAY_VOI_ASSET", "VOI")
        self.lookback = int(lookback or os.environ.get("GATEWAY_VOI_LOOKBACK", "50"))
        self.algod = (algod or os.environ.get("GATEWAY_VOI_ALGOD", _ALGOD_MAINNET)).rstrip("/")

    def info(self) -> ChainInfo:
        from algovoi_gateway_core.custody import custody_configured
        return ChainInfo(network="voi", display_name="Voi", assets=(self.asset,),
                         finality_seconds=3, supports_payout=custody_configured("voi"))

    async def new_receive_address(self, req: PaymentRequest) -> str:
        return req.pay_to

    def _get(self, path: str, params: dict, *, retries: int = 3) -> object:
        url = f"{self.indexer}{path}?" + urllib.parse.urlencode(params)
        for attempt in range(retries + 1):
            r = urllib.request.Request(url, method="GET", headers={
                "Accept": "application/json", "User-Agent": "algovoi-gateway-voi/0.1"})
            try:
                with urllib.request.urlopen(r, timeout=20) as resp:  # noqa: S310
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < retries:
                    time.sleep(0.5 * (2 ** attempt)); continue
                raise

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        out = self._get(f"/v2/accounts/{req.pay_to}/transactions",
                        {"tx-type": "pay", "limit": self.lookback})
        return parse_native_payment(out.get("transactions", []) if out else [],
                                    pay_to=req.pay_to, amount_minor=req.amount_minor)

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Custody: sign + broadcast an outbound native VOI payment with the operator's key, return
        txid. Operator-held key via ``GATEWAY_VOI_SIGNER_MNEMONIC``. Needs the ``[custody]`` extra."""
        from algovoi_gateway_core.custody import operator_secret
        secret = operator_secret("voi")
        try:
            from algosdk import account, mnemonic, transaction
            from algosdk.v2client import algod
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Voi payout needs the custody extra: "
                               "pip install 'algovoi-gateway-voi[custody]'") from exc
        sk = mnemonic.to_private_key(secret)
        sender = account.address_from_private_key(sk)
        client = algod.AlgodClient("", self.algod, headers={"User-Agent": "algovoi-gateway-voi"})
        sp = client.suggested_params()
        note = reference.encode("utf-8")[:1000] if reference else None
        txn = transaction.PaymentTxn(sender=sender, sp=sp, receiver=pay_to,
                                     amt=int(amount_minor), note=note)
        txid = client.send_transaction(txn.sign(sk))
        transaction.wait_for_confirmation(client, txid, 4)
        return txid


def provider() -> VoiProvider:
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return VoiProvider()
