"""algovoi-gateway-algorand — the Algorand chain add-on for the AlgoVoi payment gateway.

Detects a USDC (ASA) settlement to the merchant address by querying the Algorand indexer for
asset-transfer transactions to that address, with Algorand's instant (single-block) finality.
Read-and-verify in Phase 1; ``sign_and_pay`` (custody/payout) is Phase 3.

Config (env):
  GATEWAY_ALGORAND_INDEXER  indexer base URL (default AlgoNode mainnet indexer)
  GATEWAY_ALGORAND_USDC_ASA  USDC asset id (default mainnet USDC ASA 31566704)
  GATEWAY_ALGORAND_LOOKBACK  recent transactions to scan (default 50)

Registered under ``algovoi_gateway.providers`` as ``algorand``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation

__version__ = "0.1.3"

from algovoi_gateway_algorand.licensing import require_license

_USDC_MAINNET_ASA = 31566704
_INDEXER_MAINNET = "https://mainnet-idx.algonode.cloud"
_ALGOD_MAINNET = "https://mainnet-api.algonode.cloud"


def parse_settlement(txns: list, *, pay_to: str, asset_id: int, amount_minor: int) -> SettlementObservation:
    """Pure: find an asset-transfer of ``asset_id`` to ``pay_to`` with amount >= ``amount_minor``.
    Algorand finality is instant, so any confirmed transaction is final."""
    best_underpaid = None
    for t in txns:
        axfer = t.get("asset-transfer-transaction")
        if not axfer or axfer.get("asset-id") != asset_id:
            continue
        if axfer.get("receiver") != pay_to:
            continue
        amount = int(axfer.get("amount", 0))
        if amount < amount_minor:
            best_underpaid = SettlementObservation(settled=False, network="algorand", reason="underpaid",
                                                   amount_minor=amount, asset="USDC", pay_to=pay_to,
                                                   tx_id=t.get("id"))
            continue
        return SettlementObservation(
            settled=True, network="algorand", tx_id=t.get("id"), asset="USDC",
            amount_minor=amount, pay_to=pay_to, payer=t.get("sender"),
            confirmations=t.get("confirmed-round"), finalized=bool(t.get("confirmed-round")),
            observed_at_ms=int(time.time() * 1000), reason="settled")
    return best_underpaid or SettlementObservation(settled=False, network="algorand",
                                                   reason="pending", pay_to=pay_to)


class AlgorandProvider:
    def __init__(self, *, indexer: str | None = None, asa: int | None = None,
                 lookback: int | None = None, algod: str | None = None) -> None:
        self.indexer = (indexer or os.environ.get("GATEWAY_ALGORAND_INDEXER", _INDEXER_MAINNET)).rstrip("/")
        self.asa = int(asa or os.environ.get("GATEWAY_ALGORAND_USDC_ASA", _USDC_MAINNET_ASA))
        self.lookback = int(lookback or os.environ.get("GATEWAY_ALGORAND_LOOKBACK", "50"))
        # algod (not the indexer) is needed for custody/payout: suggested params + submit
        self.algod = (algod or os.environ.get("GATEWAY_ALGORAND_ALGOD", _ALGOD_MAINNET)).rstrip("/")

    def info(self) -> ChainInfo:
        from algovoi_gateway_core.custody import custody_configured
        return ChainInfo(network="algorand", display_name="Algorand", assets=("USDC",),
                         finality_seconds=4, supports_payout=custody_configured("algorand"))

    async def new_receive_address(self, req: PaymentRequest) -> str:
        return req.pay_to  # the payer sends USDC ASA to the merchant address

    def _get(self, path: str, params: dict, *, retries: int = 3) -> object:
        url = f"{self.indexer}{path}?" + urllib.parse.urlencode(params)
        for attempt in range(retries + 1):
            r = urllib.request.Request(url, method="GET", headers={
                "Accept": "application/json", "User-Agent": "algovoi-gateway-algorand/0.1"})
            try:
                with urllib.request.urlopen(r, timeout=20) as resp:  # noqa: S310
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < retries:
                    time.sleep(0.5 * (2 ** attempt)); continue
                raise

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        out = self._get(f"/v2/accounts/{req.pay_to}/transactions",
                        {"asset-id": self.asa, "limit": self.lookback})
        txns = (out or {}).get("transactions", [])
        return parse_settlement(txns, pay_to=req.pay_to, asset_id=self.asa,
                                amount_minor=req.amount_minor)

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Custody: sign + broadcast an outbound Algorand payment with the operator's key, return txid.

        Operator-held key via ``GATEWAY_ALGORAND_SIGNER_MNEMONIC`` (a 25-word mnemonic). USDC sends the
        ASA; any other asset sends native ALGO. Needs the ``[custody]`` extra (algosdk)."""
        from algovoi_gateway_core.custody import operator_secret
        secret = operator_secret("algorand")
        try:
            from algosdk import account, mnemonic, transaction
            from algosdk.v2client import algod
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Algorand payout needs the custody extra: "
                               "pip install 'algovoi-gateway-algorand[custody]'") from exc
        sk = mnemonic.to_private_key(secret)
        sender = account.address_from_private_key(sk)
        client = algod.AlgodClient("", self.algod, headers={"User-Agent": "algovoi-gateway-algorand"})
        sp = client.suggested_params()
        note = reference.encode("utf-8")[:1000] if reference else None
        if asset and asset.upper() == "USDC":
            txn = transaction.AssetTransferTxn(sender=sender, sp=sp, receiver=pay_to,
                                               amt=int(amount_minor), index=self.asa, note=note)
        else:
            txn = transaction.PaymentTxn(sender=sender, sp=sp, receiver=pay_to,
                                         amt=int(amount_minor), note=note)
        txid = client.send_transaction(txn.sign(sk))
        transaction.wait_for_confirmation(client, txid, 4)
        return txid


def provider() -> AlgorandProvider:
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return AlgorandProvider()
