"""
algovoi-settlement-verify — Multi-chain stablecoin settlement verification.

Confirm that a payment transaction settled (and finalised) on-chain across 8
networks — Algorand, VOI, Base/EVM, Solana, Hedera, Stellar, Tempo, Arc — with
correct per-chain finality, asset-id, decimal and trustline handling.

Standalone: depends only on `httpx` + `pydantic`. RPC endpoints are injected via
`RpcConfig` (no AlgoVoi infrastructure required — point it at your own nodes).

Basic usage::

    import asyncio
    from algovoi_settlement_verify import verify, PaymentPayload, NetworkEnum, RpcConfig

    payload = PaymentPayload(
        network=NetworkEnum.base_mainnet,
        tx_id="0x...",
        expected_amount_microalgos=1_000_000,      # 1.0 in 6-dp microunits
        expected_receiver="0xRecipient...",
        expected_asset_id="0xA0b8...USDC",          # token contract / asset id
    )
    result = asyncio.run(verify(payload, rpc=RpcConfig(base_rpc_url="https://your-node")))
    print(result.verified, result.confirmed_amount)

Commercial product — AlgoVoi Commercial Licence v1.0. Not for redistribution.
"""

from __future__ import annotations

from dataclasses import dataclass

from algovoi_settlement_verify.schemas import (
    ExpectedFeeLeg,
    NetworkEnum,
    PaymentPayload,
    VerifyResult,
)
from algovoi_settlement_verify.verifiers.algorand import AlgorandVerifier
from algovoi_settlement_verify.verifiers.arc_chain import ArcChainVerifier
from algovoi_settlement_verify.verifiers.base import BaseVerifier
from algovoi_settlement_verify.verifiers.base_chain import BaseChainVerifier
from algovoi_settlement_verify.verifiers.hedera import HederaVerifier
from algovoi_settlement_verify.verifiers.solana import SolanaVerifier
from algovoi_settlement_verify.verifiers.stellar import StellarVerifier
from algovoi_settlement_verify.verifiers.tempo_chain import TempoChainVerifier
from algovoi_settlement_verify.verifiers.voi import VoiVerifier

__version__ = "0.1.1"

__all__ = [
    "verify",
    "verify_authority",
    "get_verifier",
    "RpcConfig",
    "PaymentPayload",
    "VerifyResult",
    "ExpectedFeeLeg",
    "NetworkEnum",
    "SUPPORTED_NETWORKS",
    "UnsupportedNetworkError",
]


class UnsupportedNetworkError(ValueError):
    """Raised when no verifier is registered for the requested network."""


@dataclass
class RpcConfig:
    """Caller-injected RPC/REST endpoints, one per network family.

    Defaults are public best-effort endpoints for convenience only — supply your
    own (rate-limited, production-grade) nodes for real workloads. Testnet fields
    fall back to their mainnet counterpart when left None.
    """

    # Algorand (algod node + indexer)
    algorand_node_url: str = "https://mainnet-api.algonode.cloud"
    algorand_indexer_url: str = "https://mainnet-idx.algonode.cloud"
    algorand_testnet_node_url: str | None = "https://testnet-api.algonode.cloud"
    algorand_testnet_indexer_url: str | None = "https://testnet-idx.algonode.cloud"
    # VOI (algod-compatible)
    voi_node_url: str = "https://mainnet-api.voi.nodely.dev"
    voi_indexer_url: str = "https://mainnet-idx.voi.nodely.dev"
    voi_testnet_node_url: str | None = None
    voi_testnet_indexer_url: str | None = None
    # Hedera (mirror node REST)
    hedera_mirror_node_url: str = "https://mainnet-public.mirrornode.hedera.com"
    hedera_testnet_mirror_node_url: str | None = "https://testnet.mirrornode.hedera.com"
    # Stellar (Horizon)
    stellar_horizon_url: str = "https://horizon.stellar.org"
    stellar_testnet_horizon_url: str | None = "https://horizon-testnet.stellar.org"
    # Base (EVM L2 JSON-RPC)
    base_rpc_url: str = "https://mainnet.base.org"
    base_sepolia_rpc_url: str | None = "https://sepolia.base.org"
    # Solana (JSON-RPC)
    solana_rpc_url: str = "https://api.mainnet-beta.solana.com"
    solana_devnet_rpc_url: str | None = "https://api.devnet.solana.com"
    # Tempo (EVM JSON-RPC)
    tempo_rpc_url: str = "https://rpc.tempochain.io"
    tempo_testnet_rpc_url: str | None = None
    # Arc (EVM L1 JSON-RPC). Mainnet launches 2026-09-16 (chain id 5042);
    # confirm the public RPC host at launch (override via env if it differs).
    arc_rpc_url: str = "https://rpc.arc.network"
    arc_testnet_rpc_url: str = "https://rpc.testnet.arc.network"


# Networks this SDK can verify.
SUPPORTED_NETWORKS: frozenset[NetworkEnum] = frozenset(
    {
        NetworkEnum.algorand_mainnet,
        NetworkEnum.algorand_testnet,
        NetworkEnum.voi_mainnet,
        NetworkEnum.voi_testnet,
        NetworkEnum.hedera_mainnet,
        NetworkEnum.hedera_testnet,
        NetworkEnum.stellar_mainnet,
        NetworkEnum.stellar_testnet,
        NetworkEnum.base_mainnet,
        NetworkEnum.base_sepolia,
        NetworkEnum.solana_mainnet,
        NetworkEnum.solana_devnet,
        NetworkEnum.tempo_mainnet,
        NetworkEnum.tempo_testnet,
        NetworkEnum.arc_mainnet,
        NetworkEnum.arc_testnet,
    }
)


def get_verifier(network: "NetworkEnum | str", rpc: RpcConfig | None = None) -> BaseVerifier:
    """Return the per-chain verifier for ``network``, wired to ``rpc`` endpoints.

    Endpoints are injected (no global config). Testnet variants fall back to the
    mainnet endpoint when the testnet field is None.
    """
    if not getattr(get_verifier, "_licensed", False):
        from algovoi_settlement_verify import licensing
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        get_verifier._licensed = True
    rpc = rpc or RpcConfig()
    n = network if isinstance(network, NetworkEnum) else NetworkEnum(network)

    if n == NetworkEnum.algorand_mainnet:
        return AlgorandVerifier(rpc.algorand_node_url, rpc.algorand_indexer_url)
    if n == NetworkEnum.algorand_testnet:
        return AlgorandVerifier(
            rpc.algorand_testnet_node_url or rpc.algorand_node_url,
            rpc.algorand_testnet_indexer_url or rpc.algorand_indexer_url,
        )
    if n == NetworkEnum.voi_mainnet:
        return VoiVerifier(rpc.voi_node_url, rpc.voi_indexer_url)
    if n == NetworkEnum.voi_testnet:
        return VoiVerifier(
            rpc.voi_testnet_node_url or rpc.voi_node_url,
            rpc.voi_testnet_indexer_url or rpc.voi_indexer_url,
        )
    if n == NetworkEnum.hedera_mainnet:
        return HederaVerifier(rpc.hedera_mirror_node_url)
    if n == NetworkEnum.hedera_testnet:
        return HederaVerifier(rpc.hedera_testnet_mirror_node_url or rpc.hedera_mirror_node_url)
    if n == NetworkEnum.stellar_mainnet:
        return StellarVerifier(rpc.stellar_horizon_url)
    if n == NetworkEnum.stellar_testnet:
        return StellarVerifier(rpc.stellar_testnet_horizon_url or rpc.stellar_horizon_url)
    if n == NetworkEnum.base_mainnet:
        return BaseChainVerifier(rpc.base_rpc_url, NetworkEnum.base_mainnet)
    if n == NetworkEnum.base_sepolia:
        return BaseChainVerifier(rpc.base_sepolia_rpc_url or rpc.base_rpc_url, NetworkEnum.base_sepolia)
    if n == NetworkEnum.solana_mainnet:
        return SolanaVerifier(rpc.solana_rpc_url, NetworkEnum.solana_mainnet)
    if n == NetworkEnum.solana_devnet:
        return SolanaVerifier(rpc.solana_devnet_rpc_url or rpc.solana_rpc_url, NetworkEnum.solana_devnet)
    if n == NetworkEnum.tempo_mainnet:
        return TempoChainVerifier(rpc.tempo_rpc_url, NetworkEnum.tempo_mainnet)
    if n == NetworkEnum.tempo_testnet:
        return TempoChainVerifier(rpc.tempo_testnet_rpc_url or rpc.tempo_rpc_url, NetworkEnum.tempo_testnet)
    if n == NetworkEnum.arc_mainnet:
        return ArcChainVerifier(rpc.arc_rpc_url, NetworkEnum.arc_mainnet)
    if n == NetworkEnum.arc_testnet:
        return ArcChainVerifier(rpc.arc_testnet_rpc_url, NetworkEnum.arc_testnet)

    raise UnsupportedNetworkError(f"No verifier registered for network: {n}")


async def verify(payload: PaymentPayload, *, rpc: RpcConfig | None = None) -> VerifyResult:
    """Verify a settlement: confirm ``payload.tx_id`` paid the expected amount to
    the expected receiver (and asset/fee/note bindings, if set) on ``payload.network``.
    """
    verifier = get_verifier(payload.network, rpc)
    return await verifier.verify(payload)


async def verify_authority(
    tx_id: str, network: "NetworkEnum | str", *, rpc: RpcConfig | None = None
) -> VerifyResult:
    """Confirm a tx is mined/finalised on-chain without amount/receiver checks
    (e.g. ERC-20 approve, SPL Approve, Soroban approve standing authorities).
    """
    n = network if isinstance(network, NetworkEnum) else NetworkEnum(network)
    verifier = get_verifier(n, rpc)
    return await verifier.verify_authority_tx(tx_id, n)
