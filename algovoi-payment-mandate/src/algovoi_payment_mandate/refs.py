"""
The Payment Mandate's content address — ``mandate_ref``.

``mandate_ref = "sha256:" + SHA-256(JCS({payer, cap, period, revocation_state}))`` is the open,
content-addressed spend-authority address and the exact ``mandate_ref`` the commercial Spend Guardrail
derives. ``revocation_state`` (``"active"`` / ``"revoked"``) is part of the address, so a revoked mandate
addresses differently from the same mandate while live. Uses RFC 8785 (JCS) + SHA-256, no new dependency.
"""
from __future__ import annotations

import hashlib

import rfc8785

from algovoi_payment_mandate import signing


def _prefixed(value) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def mandate_ref_from_payload(payload: dict, *, revocation_state: str = "active") -> str:
    """Compute ``mandate_ref`` from a mandate payload dict + the live revocation state."""
    return _prefixed({
        "payer": payload.get("payer"),
        "cap": int(payload.get("max_amount") or 0),
        "period": payload.get("period"),
        "revocation_state": revocation_state,
    })


def mandate_ref(mandate: str, *, revocation_state: str = "active") -> str:
    """Compute ``mandate_ref`` from a mandate envelope (verify the signature separately)."""
    payload, _, _ = signing.open_envelope(mandate)
    return mandate_ref_from_payload(payload, revocation_state=revocation_state)


__all__ = ["mandate_ref", "mandate_ref_from_payload"]
