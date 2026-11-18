"""
The Agent Passport's content address — ``passport_ref``.

``passport_ref = "sha256:" + SHA-256(JCS({agent_id, issuer, scope, validity_window}))`` is the open,
content-addressed identity address an AP2/A2A adopter pins (the lite tier) and the exact ``agent_ref``
the commercial Spend Guardrail derives from a verified credential. Emitting it here makes the
composition provable from the passport itself: the same credential addresses identically wherever it is
checked. Uses RFC 8785 (JCS) + SHA-256, no new dependency.
"""
from __future__ import annotations

import hashlib

import rfc8785

from algovoi_agent_passport import signing


def _prefixed(value) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def passport_ref_from_payload(payload: dict) -> str:
    """Compute ``passport_ref`` from a passport payload dict (its issued claim set)."""
    return _prefixed({
        "agent_id": payload.get("agent_did"),
        "issuer": payload.get("issuer_did"),
        "scope": list(payload.get("scopes") or []),
        "validity_window": {
            "issued_at": payload.get("issued_at"),
            "expires_at": payload.get("expires_at"),
        },
    })


def passport_ref(credential: str) -> str:
    """Compute ``passport_ref`` from a credential envelope (verify the signature separately)."""
    payload, _, _ = signing.open_envelope(credential)
    return passport_ref_from_payload(payload)


__all__ = ["passport_ref", "passport_ref_from_payload"]
