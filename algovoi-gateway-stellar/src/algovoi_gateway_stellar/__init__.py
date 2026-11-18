"""algovoi-gateway-stellar — the Stellar chain add-on for the AlgoVoi payment gateway.

Detects a USDC settlement to the merchant account by reading the Stellar Horizon REST API for
payment operations, with Stellar's fast ledger-close finality. Stellar amounts are decimal
strings with 7 fixed decimals; they are converted to integer minor units (x 10^7) with Decimal
(no float). Read-and-verify in Phase 1; ``sign_and_pay`` (custody/payout) is Phase 3.

Config (env):
  GATEWAY_STELLAR_HORIZON  Horizon base URL (default Stellar mainnet Horizon)
  GATEWAY_STELLAR_USDC_ISSUER  USDC issuer (default Circle/Centre mainnet issuer)
  GATEWAY_STELLAR_LOOKBACK     recent payments to scan (default 50)

Registered under ``algovoi_gateway.providers`` as ``stellar``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from decimal import Decimal

from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation

__version__ = "0.1.4"

from algovoi_gateway_stellar.licensing import require_license

_HORIZON_MAINNET = "https://horizon.stellar.org"
_USDC_ISSUER_MAINNET = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"  # Circle USDC
_STROOP = 10 ** 7  # Stellar amounts have 7 fixed decimals

_PAYMENT_TYPES = {"payment", "path_payment_strict_send", "path_payment_strict_receive"}


def to_minor(amount_str: str) -> int:
    """Stellar decimal amount string -> integer minor units (x 10^7), no float."""
    return int(Decimal(amount_str) * _STROOP)


def parse_payments(records: list, *, merchant: str, asset_code: str, asset_issuer: str,
                   amount_minor: int) -> SettlementObservation:
    """Pure: find a USDC payment crediting ``merchant`` for at least ``amount_minor``."""
    underpaid = None
    for r in records:
        if r.get("type") not in _PAYMENT_TYPES or r.get("to") != merchant:
            continue
        if r.get("asset_code") != asset_code or r.get("asset_issuer") != asset_issuer:
            continue
        minor = to_minor(r.get("amount", "0"))
        if minor < amount_minor:
            underpaid = SettlementObservation(settled=False, network="stellar", reason="underpaid",
                                              amount_minor=minor, asset="USDC", pay_to=merchant,
                                              tx_id=r.get("transaction_hash"))
            continue
        return SettlementObservation(
            settled=True, network="stellar", tx_id=r.get("transaction_hash"), asset="USDC",
            amount_minor=minor, pay_to=merchant, payer=r.get("from"), confirmations=None,
            finalized=True, observed_at_ms=int(time.time() * 1000), reason="settled")
    return underpaid or SettlementObservation(settled=False, network="stellar", reason="pending", pay_to=merchant)


class StellarProvider:
    def __init__(self, *, horizon: str | None = None, issuer: str | None = None,
                 lookback: int | None = None) -> None:
        self.horizon = (horizon or os.environ.get("GATEWAY_STELLAR_HORIZON", _HORIZON_MAINNET)).rstrip("/")
        self.issuer = issuer or os.environ.get("GATEWAY_STELLAR_USDC_ISSUER", _USDC_ISSUER_MAINNET)
        self.lookback = int(lookback or os.environ.get("GATEWAY_STELLAR_LOOKBACK", "50"))

    def info(self) -> ChainInfo:
        from algovoi_gateway_core.custody import custody_configured
        return ChainInfo(network="stellar", display_name="Stellar", assets=("USDC",),
                         finality_seconds=6, supports_payout=custody_configured("stellar"))

    async def new_receive_address(self, req: PaymentRequest) -> str:
        return req.pay_to

    def _get(self, path: str, params: dict, *, retries: int = 3) -> object:
        url = f"{self.horizon}{path}?" + urllib.parse.urlencode(params)
        for attempt in range(retries + 1):
            r = urllib.request.Request(url, method="GET", headers={
                "Accept": "application/json", "User-Agent": "algovoi-gateway-stellar/0.1"})
            try:
                with urllib.request.urlopen(r, timeout=20) as resp:  # noqa: S310
                    return json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 503) and attempt < retries:
                    time.sleep(0.5 * (2 ** attempt)); continue
                raise

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        out = self._get(f"/accounts/{req.pay_to}/payments",
                        {"order": "desc", "limit": self.lookback, "include_failed": "false"})
        records = ((out or {}).get("_embedded") or {}).get("records", [])
        return parse_payments(records, merchant=req.pay_to, asset_code="USDC",
                              asset_issuer=self.issuer, amount_minor=req.amount_minor)

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Custody: sign + submit an outbound USDC (or native XLM) payment with the operator's key,
        return the tx hash. Operator-held key via ``GATEWAY_STELLAR_SIGNER_KEY`` (an S... secret seed).
        Amounts are 7-decimal minor units. Needs the ``[custody]`` extra (stellar-sdk)."""
        from decimal import Decimal

        from algovoi_gateway_core.custody import operator_secret
        secret = operator_secret("stellar")
        try:
            from stellar_sdk import Asset, Keypair, Network, Server, TransactionBuilder
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Stellar payout needs the custody extra: "
                               "pip install 'algovoi-gateway-stellar[custody]'") from exc
        kp = Keypair.from_secret(secret)
        server = Server(self.horizon)
        passphrase = os.environ.get("GATEWAY_STELLAR_PASSPHRASE", Network.PUBLIC_NETWORK_PASSPHRASE)
        amount = str(Decimal(int(amount_minor)) / Decimal(10 ** 7))   # 7-decimal stroops -> units
        token = Asset("USDC", self.issuer) if asset and asset.upper() == "USDC" else Asset.native()
        tx = (TransactionBuilder(source_account=server.load_account(kp.public_key),
                                 network_passphrase=passphrase, base_fee=100)
              .append_payment_op(destination=pay_to, asset=token, amount=amount)
              .add_text_memo((reference or "")[:28]).set_timeout(60).build())
        tx.sign(kp)
        return server.submit_transaction(tx)["hash"]


def provider() -> StellarProvider:
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return StellarProvider()
