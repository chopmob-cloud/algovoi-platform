"""Live end-to-end verification against real chains.

Gated behind ALGOVOI_E2E=1 so it never runs in offline/unit CI.

The operator supplies known-good settlement vectors (real on-chain txs) in a JSON
fixtures file — default ``tests/fixtures/e2e_vectors.json`` (copy from
``e2e_vectors.example.json`` and fill in real txs), or point
``ALGOVOI_SETTLEMENT_FIXTURES`` at another path. Each vector is run through
``verify()`` against the live RPC in the fixtures' ``rpc`` block; the harness
asserts the verdict (and confirmed amount) matches what the operator recorded.

Chains with no vector are simply not exercised. This is the gate before ANY
publish or external delivery (feedback_e2e_before_publish): unit tests prove the
wiring; only these prove the chain logic against real settlements.

Run:  ALGOVOI_E2E=1 PYTHONPATH=src python -m pytest tests/test_e2e_live.py -v
"""

import json
import os
import pathlib

import pytest

from algovoi_settlement_verify import NetworkEnum, PaymentPayload, RpcConfig, verify

pytestmark = pytest.mark.skipif(
    not os.environ.get("ALGOVOI_E2E"),
    reason="set ALGOVOI_E2E=1 to run live e2e tests",
)


def _fixtures_path() -> pathlib.Path:
    override = os.environ.get("ALGOVOI_SETTLEMENT_FIXTURES")
    if override:
        return pathlib.Path(override)
    return pathlib.Path(__file__).parent / "fixtures" / "e2e_vectors.json"


def _load_fixtures() -> dict:
    if not os.environ.get("ALGOVOI_E2E"):
        return {}
    p = _fixtures_path()
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _build_rpc(data: dict) -> RpcConfig:
    rpc_kwargs = {k: v for k, v in (data.get("rpc") or {}).items() if not k.startswith("_")}
    return RpcConfig(**rpc_kwargs) if rpc_kwargs else RpcConfig()


_DATA = _load_fixtures()
_VECTORS = [v for v in _DATA.get("vectors", []) if not v.get("_skip")]
_IDS = [v.get("label", v.get("network", "vector")) for v in _VECTORS]


def test_fixtures_present():
    """Fail loudly (not silently pass) if e2e is on but no real vectors are loaded."""
    if not _fixtures_path().exists():
        pytest.skip(
            f"no fixtures at {_fixtures_path()} — copy tests/fixtures/e2e_vectors.example.json "
            "to e2e_vectors.json and fill in real settled txs"
        )
    assert _VECTORS, "fixtures file present but contains no runnable vectors (all _skip?)"


@pytest.mark.parametrize("vec", _VECTORS, ids=_IDS)
async def test_settlement_verifies_live(vec):
    rpc = _build_rpc(_DATA)
    payload = PaymentPayload(
        network=NetworkEnum(vec["network"]),
        tx_id=vec["tx_id"],
        expected_amount_microalgos=vec.get("expected_amount_microalgos", 0),
        expected_receiver=vec.get("expected_receiver", ""),
        expected_asset_id=vec.get("expected_asset_id"),
        verify_authority=vec.get("verify_authority", False),
    )
    result = await verify(payload, rpc=rpc)

    expect = vec.get("expect_verified", True)
    assert result.verified == expect, (
        f"{vec.get('label')}: expected verified={expect}, got {result.verified} "
        f"(error={result.error})"
    )
    if expect and "expected_amount_microalgos" in vec and not payload.verify_authority:
        assert result.confirmed_amount == vec["expected_amount_microalgos"], (
            f"{vec.get('label')}: amount mismatch — got {result.confirmed_amount}, "
            f"expected {vec['expected_amount_microalgos']}"
        )
