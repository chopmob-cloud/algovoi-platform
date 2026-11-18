"""algovoi-gateway-base — the Base (EVM) chain add-on for the AlgoVoi payment gateway.

Implements one :class:`ChainProvider` for Base: it detects a USDC settlement to the merchant
address by reading ERC-20 ``Transfer`` logs over JSON-RPC and applies a finality (confirmations)
rule. Read-and-verify only in Phase 1; ``sign_and_pay`` (custody/payout) is Phase 3.

Config (env):
  GATEWAY_BASE_RPC_URL        JSON-RPC endpoint (required to observe settlement)
  GATEWAY_BASE_USDC           USDC contract address (default Base mainnet USDC)
  GATEWAY_BASE_CONFIRMATIONS  blocks for finality (default 5)
  GATEWAY_BASE_LOOKBACK       blocks to scan back for the payment (default 5000)

Registered under the ``algovoi_gateway.providers`` entry point as ``base``.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

from algovoi_gateway_core.provider import ChainInfo, PaymentRequest, SettlementObservation

__version__ = "0.1.4"

from algovoi_gateway_base.licensing import require_license

# keccak256("Transfer(address,address,uint256)")
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_USDC_MAINNET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"   # Base mainnet USDC


def _addr_topic(addr: str) -> str:
    """32-byte left-padded address topic (lowercased)."""
    return "0x" + addr.lower().replace("0x", "").rjust(64, "0")


class BaseProvider:
    """EVM settlement provider. Used directly for Base, and reused for any EVM chain (e.g. Tempo)
    by subclassing with a different ``network``, RPC, and token contract."""

    network = "base"
    display_name = "Base"
    asset_symbol = "USDC"
    default_chain_id = 8453   # Base mainnet; EVM subclasses (e.g. Tempo) override

    def __init__(self, *, rpc_url: str | None = None, usdc: str | None = None,
                 confirmations: int | None = None, lookback: int | None = None) -> None:
        self.rpc_url = rpc_url or os.environ.get("GATEWAY_BASE_RPC_URL", "")
        self.usdc = (usdc or os.environ.get("GATEWAY_BASE_USDC", _USDC_MAINNET)).lower()
        self.confirmations = int(confirmations or os.environ.get("GATEWAY_BASE_CONFIRMATIONS", "5"))
        self.lookback = int(lookback or os.environ.get("GATEWAY_BASE_LOOKBACK", "5000"))
        self.chain_id = int(os.environ.get(f"GATEWAY_{self.network.upper()}_CHAIN_ID", self.default_chain_id))

    def info(self) -> ChainInfo:
        from algovoi_gateway_core.custody import custody_configured
        return ChainInfo(network=self.network, display_name=self.display_name,
                         assets=(self.asset_symbol,), finality_seconds=self.confirmations * 2,
                         supports_payout=custody_configured(self.network))

    async def new_receive_address(self, req: PaymentRequest) -> str:
        # account model: the payer settles USDC directly to the merchant address
        return req.pay_to

    def _rpc(self, method: str, params: list) -> object:
        if not self.rpc_url:
            raise RuntimeError("GATEWAY_BASE_RPC_URL not configured")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        r = urllib.request.Request(self.rpc_url, data=body, method="POST", headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "User-Agent": "algovoi-gateway-base/0.1"})
        with urllib.request.urlopen(r, timeout=15) as resp:  # noqa: S310
            out = json.loads(resp.read())
        if "error" in out:
            raise RuntimeError(f"rpc error: {out['error']}")
        return out["result"]

    def parse_logs(self, logs: list, *, pay_to: str, amount_minor: int, head_block: int) -> SettlementObservation:
        """Pure log-matching + finality (testable without a live node)."""
        want = _addr_topic(pay_to)
        for lg in logs:
            topics = lg.get("topics", [])
            if len(topics) < 3 or topics[0].lower() != _TRANSFER_TOPIC or topics[2].lower() != want:
                continue
            value = int(lg.get("data", "0x0"), 16)
            if value < amount_minor:
                return SettlementObservation(settled=False, network=self.network, reason="underpaid",
                                             amount_minor=value, asset=self.asset_symbol, pay_to=pay_to)
            blk = int(lg.get("blockNumber", "0x0"), 16)
            confs = max(0, head_block - blk + 1)
            payer = "0x" + topics[1][-40:]
            return SettlementObservation(
                settled=True, network=self.network, tx_id=lg.get("transactionHash"), asset=self.asset_symbol,
                amount_minor=value, pay_to=pay_to, payer=payer, confirmations=confs,
                finalized=confs >= self.confirmations, observed_at_ms=int(time.time() * 1000),
                reason="settled" if confs >= self.confirmations else "confirming")
        return SettlementObservation(settled=False, network=self.network, reason="pending", pay_to=pay_to)

    async def observe_settlement(self, req: PaymentRequest) -> SettlementObservation:
        head = int(self._rpc("eth_blockNumber", []), 16)
        # scan recent windows newest-first, chunked to respect per-RPC max block range
        max_range = int(os.environ.get("GATEWAY_BASE_MAX_RANGE", "2000"))
        topics = [_TRANSFER_TOPIC, None, _addr_topic(req.pay_to)]
        floor = max(0, head - self.lookback)
        last = SettlementObservation(settled=False, network=self.network, reason="pending", pay_to=req.pay_to)
        hi = head
        while hi >= floor:
            lo = max(floor, hi - max_range + 1)
            logs = self._rpc("eth_getLogs", [{"address": self.usdc, "fromBlock": hex(lo),
                                              "toBlock": hex(hi), "topics": topics}])
            obs = self.parse_logs(logs, pay_to=req.pay_to, amount_minor=req.amount_minor, head_block=head)
            if obs.settled:
                return obs
            if obs.reason == "underpaid":
                last = obs
            hi = lo - 1
        return last

    async def sign_and_pay(self, *, network: str, asset: str, amount_minor: int,
                           pay_to: str, reference: str) -> str:
        """Custody: sign + broadcast an outbound EVM payout with the operator's key, return the tx hash.

        Operator-held key via ``GATEWAY_<NET>_SIGNER_KEY`` (a 0x secp256k1 private key). USDC (or
        USDCe) sends an ERC-20 ``transfer``; any other asset sends native value. EIP-1559 typed tx.
        Needs the ``[custody]`` extra (eth-account)."""
        from algovoi_gateway_core.custody import operator_secret
        key = operator_secret(self.network)
        try:
            from eth_account import Account
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(f"{self.display_name} payout needs the custody extra: "
                               f"pip install 'algovoi-gateway-{self.network}[custody]'") from exc
        acct = Account.from_key(key if key.startswith("0x") else "0x" + key)
        sender = acct.address
        nonce = int(self._rpc("eth_getTransactionCount", [sender, "pending"]), 16)
        if asset and asset.upper() in ("USDC", "USDCE"):
            to = self.usdc
            data = ("0xa9059cbb" + pay_to.lower().replace("0x", "").rjust(64, "0")
                    + format(int(amount_minor), "064x"))   # transfer(address,uint256)
            value, gas = 0, 120000
        else:
            to, data, value, gas = pay_to, "0x", int(amount_minor), 21000
        max_fee = int(self._rpc("eth_gasPrice", []), 16)
        tx = {"to": to, "value": value, "gas": gas, "nonce": nonce, "chainId": self.chain_id,
              "maxFeePerGas": max_fee * 2, "maxPriorityFeePerGas": min(max_fee, 2_000_000_000),
              "data": data}
        signed = acct.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
        return self._rpc("eth_sendRawTransaction", ["0x" + raw.hex()])


def provider() -> BaseProvider:
    """Entry-point factory."""
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return BaseProvider()
