"""
Deterministic input-bounds gate, applied BEFORE any signature work (DoS protection).

A signed decision is comparatively expensive (Falcon, optionally ML-DSA). Before doing any of it, the gate
rejects oversized or malformed input cheaply and deterministically, with named codes — the same fail-closed
philosophy as the substrate-guard profile. Limits are content-addressed via :func:`profile_ref` so a
deployment can pin the exact bounds in force.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import rfc8785


@dataclass(frozen=True)
class Bounds:
    """The input limits enforced ahead of a decision. Adopters pin these via :func:`profile_ref`."""
    max_credential_bytes: int = 16_384   # an Agent Passport credential (b64url envelope)
    max_mandate_bytes: int = 16_384      # a Payment Mandate
    max_charge_id_bytes: int = 256
    max_payee_bytes: int = 1_024
    max_asset_bytes: int = 64
    # ceiling = the largest JSON-safe integer (2**53 - 1): minor units above this cannot be canonicalised
    # losslessly under JCS, so the gate refuses them rather than emit a receipt that may not reproduce.
    max_amount: int = 2 ** 53 - 1

    def snapshot(self) -> dict:
        return {
            "max_credential_bytes": self.max_credential_bytes,
            "max_mandate_bytes": self.max_mandate_bytes,
            "max_charge_id_bytes": self.max_charge_id_bytes,
            "max_payee_bytes": self.max_payee_bytes,
            "max_asset_bytes": self.max_asset_bytes,
            "max_amount": self.max_amount,
        }


DEFAULT_BOUNDS = Bounds()


def profile_ref(bounds: Bounds = DEFAULT_BOUNDS) -> str:
    """``"sha256:" + SHA-256(JCS(bounds))`` — the pinnable address of the limits in force."""
    return "sha256:" + hashlib.sha256(rfc8785.dumps(bounds.snapshot())).hexdigest()


def _n(s: str | None) -> int:
    return len(s.encode("utf-8")) if isinstance(s, str) else 0


def check(*, passport_credential, mandate, charge_id, amount, payee,
          asset=None, bounds: Bounds = DEFAULT_BOUNDS) -> list[str]:
    """Return a list of ``bounds:<code>`` violations (empty == within bounds). Never raises."""
    v: list[str] = []
    if not isinstance(passport_credential, str) or _n(passport_credential) > bounds.max_credential_bytes:
        v.append("bounds:credential_too_large")
    if not isinstance(mandate, str) or _n(mandate) > bounds.max_mandate_bytes:
        v.append("bounds:mandate_too_large")
    if not isinstance(charge_id, str) or not charge_id or _n(charge_id) > bounds.max_charge_id_bytes:
        v.append("bounds:charge_id_invalid")
    if not isinstance(payee, str) or not payee or _n(payee) > bounds.max_payee_bytes:
        v.append("bounds:payee_invalid")
    if asset is not None and _n(asset) > bounds.max_asset_bytes:
        v.append("bounds:asset_too_large")
    if not isinstance(amount, int) or amount <= 0 or amount > bounds.max_amount:
        v.append("bounds:amount_out_of_range")
    return v


__all__ = ["Bounds", "DEFAULT_BOUNDS", "profile_ref", "check"]
