"""Operator-held key custody for gateway payouts (Phase 3).

The operator-held model: the chain signing key lives on the operator's own box and is provided by
environment, never by AlgoVoi. ``sign_and_pay`` loads it through here. Fail-closed: if no key is
configured for the network, a payout is refused (it never silently no-ops). The secret is read on
demand, never logged, and never leaves the process. HSM / cloud-KMS custody is a future adapter
behind this same ``operator_secret`` interface.

Per network, the operator sets one of (checked in order):
  GATEWAY_<NET>_SIGNER_MNEMONIC   a mnemonic / seed phrase (e.g. Algorand 25-word)
  GATEWAY_<NET>_SIGNER_KEY        a raw private key (hex or base64, chain-specific)
  GATEWAY_<NET>_SIGNER_FILE       a path to a file containing either of the above
"""
from __future__ import annotations

import os


class CustodyNotConfigured(RuntimeError):
    """Raised when a payout is attempted with no operator signing key configured (fail-closed)."""


def operator_secret(network: str) -> str:
    """Return the operator signing secret for ``network`` or raise :class:`CustodyNotConfigured`.

    The secret is whatever the chain provider's signer expects (a mnemonic, a hex/base64 key, ...);
    this function only resolves and returns it, it does not interpret it.
    """
    net = network.upper()
    for suffix in ("SIGNER_MNEMONIC", "SIGNER_KEY"):
        v = os.environ.get(f"GATEWAY_{net}_{suffix}", "").strip()
        if v:
            return v
    path = os.environ.get(f"GATEWAY_{net}_SIGNER_FILE", "").strip()
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            v = fh.read().strip()
        if v:
            return v
    raise CustodyNotConfigured(
        f"no operator signing key for {network!r}: set GATEWAY_{net}_SIGNER_MNEMONIC "
        f"(or GATEWAY_{net}_SIGNER_KEY / GATEWAY_{net}_SIGNER_FILE). Payout is fail-closed.")


def custody_configured(network: str) -> bool:
    """True if an operator signing key is configured for the network (no secret is returned)."""
    try:
        operator_secret(network)
        return True
    except CustodyNotConfigured:
        return False


__all__ = ["CustodyNotConfigured", "operator_secret", "custody_configured"]
