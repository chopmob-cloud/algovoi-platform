"""Dispatch/registry tests — no network calls, pure wiring checks."""

import pytest

from algovoi_settlement_verify import (
    NetworkEnum,
    PaymentPayload,
    RpcConfig,
    SUPPORTED_NETWORKS,
    UnsupportedNetworkError,
    get_verifier,
    verify,
)
from algovoi_settlement_verify.verifiers.algorand import AlgorandVerifier
from algovoi_settlement_verify.verifiers.base_chain import BaseChainVerifier
from algovoi_settlement_verify.verifiers.solana import SolanaVerifier
from algovoi_settlement_verify.verifiers.stellar import StellarVerifier
from algovoi_settlement_verify.verifiers.hedera import HederaVerifier
from algovoi_settlement_verify.verifiers.tempo_chain import TempoChainVerifier
from algovoi_settlement_verify.verifiers.arc_chain import ArcChainVerifier
from algovoi_settlement_verify.verifiers.voi import VoiVerifier


def test_every_supported_network_dispatches():
    for net in SUPPORTED_NETWORKS:
        v = get_verifier(net)
        assert v is not None, f"no verifier for {net}"


@pytest.mark.parametrize("net,cls", [
    (NetworkEnum.algorand_mainnet, AlgorandVerifier),
    (NetworkEnum.voi_mainnet, VoiVerifier),
    (NetworkEnum.base_mainnet, BaseChainVerifier),
    (NetworkEnum.solana_mainnet, SolanaVerifier),
    (NetworkEnum.stellar_mainnet, StellarVerifier),
    (NetworkEnum.hedera_mainnet, HederaVerifier),
    (NetworkEnum.tempo_mainnet, TempoChainVerifier),
    (NetworkEnum.arc_mainnet, ArcChainVerifier),
    (NetworkEnum.arc_testnet, ArcChainVerifier),
])
def test_dispatch_returns_correct_type(net, cls):
    assert isinstance(get_verifier(net), cls)


def test_string_network_accepted():
    assert isinstance(get_verifier("base-mainnet" if "base-mainnet" in [e.value for e in NetworkEnum]
                                   else NetworkEnum.base_mainnet.value), BaseChainVerifier)


def test_rpc_config_injection_overrides_endpoint():
    rpc = RpcConfig(base_rpc_url="https://custom.example/rpc")
    v = get_verifier(NetworkEnum.base_mainnet, rpc)
    # BaseChainVerifier stores rpc_url (rstrip'd) — confirm injection took.
    assert getattr(v, "_rpc_url", "").startswith("https://custom.example")


def test_testnet_falls_back_to_mainnet_when_unset():
    rpc = RpcConfig(voi_testnet_node_url=None, voi_node_url="https://voi-main.example")
    v = get_verifier(NetworkEnum.voi_testnet, rpc)
    assert v is not None


def test_unsupported_network_raises():
    with pytest.raises((UnsupportedNetworkError, ValueError)):
        get_verifier("not-a-real-network")


def test_payload_correlation_ids_optional():
    # tenant_id / resource_id are optional in the standalone SDK.
    p = PaymentPayload(network=NetworkEnum.base_mainnet, tx_id="0x" + "a" * 64,
                       expected_amount_microalgos=1, expected_receiver="0x" + "b" * 40)
    assert p.tenant_id == "" and p.resource_id == ""
