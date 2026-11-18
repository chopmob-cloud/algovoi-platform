"""algovoi-gateway-tempo — the Tempo chain add-on for the AlgoVoi payment gateway.

Tempo is an EVM L1 whose TIP-20 token standard is an ERC-20 superset, so a USDCe settlement is
detected exactly as on Base: scan the token's ``Transfer`` logs to the merchant address over
JSON-RPC, with a confirmations finality rule. This add-on therefore reuses the proven Base/EVM
provider, configured for Tempo (network, RPC, USDCe contract). ``sign_and_pay`` (custody) is
Phase 3.

Config (env):
  GATEWAY_TEMPO_RPC_URL        JSON-RPC endpoint (Tempo mainnet chain-id 4217 / testnet 42431)
  GATEWAY_TEMPO_USDCE          USDCe contract (default Tempo USDCe, 6 decimals)
  GATEWAY_TEMPO_CONFIRMATIONS  blocks for finality (default 3)
  GATEWAY_TEMPO_LOOKBACK       blocks to scan back (default 5000)

Registered under ``algovoi_gateway.providers`` as ``tempo``.
"""
from __future__ import annotations

import os

from algovoi_gateway_base import BaseProvider

__version__ = "0.1.4"

from algovoi_gateway_tempo.licensing import require_license

_USDCE = "0x20c000000000000000000000b9537d11c60e8b50"   # Tempo USDCe (TIP-20, 6 decimals)


class TempoProvider(BaseProvider):
    network = "tempo"
    display_name = "Tempo"
    asset_symbol = "USDCe"
    default_chain_id = 4217   # Tempo mainnet L1

    def __init__(self) -> None:
        super().__init__(
            rpc_url=os.environ.get("GATEWAY_TEMPO_RPC_URL", ""),
            usdc=os.environ.get("GATEWAY_TEMPO_USDCE", _USDCE),
            confirmations=int(os.environ.get("GATEWAY_TEMPO_CONFIRMATIONS", "3")),
            lookback=int(os.environ.get("GATEWAY_TEMPO_LOOKBACK", "5000")))

    # sign_and_pay (custody) is inherited from BaseProvider (EVM); Tempo is an ERC-20 superset.


def provider() -> TempoProvider:
    require_license()  # fail-closed: this chain add-on needs its own OEM licence
    return TempoProvider()
