"""Guard: the SDK must be fully standalone — zero AlgoVoi-platform coupling.

If any of these fail, an extraction leak has crept back in.
"""

import sys
import pathlib

import algovoi_settlement_verify as sv


def test_no_platform_modules_loaded():
    """Importing the SDK must not pull in any gateway/shared/facilitator module."""
    banned = [m for m in sys.modules if m.split(".")[0] in {"gateway", "shared", "facilitator"}]
    assert banned == [], f"platform modules leaked into the SDK: {banned}"


def test_no_platform_imports_in_source():
    """Static scan: no source file references the platform packages."""
    root = pathlib.Path(sv.__file__).parent
    offenders = []
    for py in root.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for needle in ("import facilitator", "from facilitator", "import shared",
                       "from shared", "import gateway", "from gateway"):
            if needle in text:
                offenders.append(f"{py.name}: {needle}")
    assert offenders == [], f"platform references in source: {offenders}"


def test_only_lightweight_runtime_deps():
    """The verifier layer should need only httpx + pydantic at runtime (no chain SDKs)."""
    heavy = [m for m in sys.modules
             if m.split(".")[0] in {"algosdk", "solders", "solana", "stellar_sdk", "hiero_sdk_python", "web3"}]
    assert heavy == [], f"unexpected heavy chain-SDK import: {heavy}"
