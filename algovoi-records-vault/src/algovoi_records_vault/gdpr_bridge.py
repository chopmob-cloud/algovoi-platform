"""Optional bridge: mirror Records Vault legal holds onto the control_plane GDPR purge gate.

Decoupled by design — this lives in the *vault* package and calls control_plane's
``POST /internal/compliance/legal-hold`` over HTTP. control_plane never imports the vault (it has no
commercial-package dependency). Enabled only when a bridge URL + admin token are configured; otherwise
every call is a no-op.

The vault's Falcon-signed ``holds/`` chain stays the tamper-evident **system-of-record** (FRCP 37(e)
defensibility); this bridge only flips the operational ``legal_hold`` gate so the payment-ledger reaper
skips a held payer's PII (GDPR Art 17(3)(e)). Because the gate is local control_plane state, the purge
never depends on the vault being reachable at purge time — the bridge runs at hold *placement/release*
(rare), plus an idempotent :meth:`reconcile` to repair any drift.
"""
from __future__ import annotations

import os
from typing import Iterable


class LegalHoldBridge:
    """HTTP client that mirrors vault legal holds onto control_plane's payment-ledger gate.

    ``subject_of`` maps a vault hold's ``query.subject_ref`` to the control_plane ``subject_ref`` (the
    payer_address the matter concerns). Identity by default; override to translate identifiers.
    """

    def __init__(self, base_url: str, admin_token: str, *, timeout: float = 10.0,
                 subject_of=None) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token
        self.timeout = timeout
        self._subject_of = subject_of or (lambda s: s)

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.admin_token)

    def _post(self, body: dict) -> dict:
        import httpx  # lazy — control_plane/no-op deployments never import httpx for this

        resp = httpx.post(
            f"{self.base_url}/internal/compliance/legal-hold",
            json=body, timeout=self.timeout,
            headers={"Authorization": f"Bearer {self.admin_token}"},
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _scope_from_query(query: dict) -> dict:
        dr = (query or {}).get("date_range") or {}
        out: dict = {}
        if dr.get("from"):
            out["date_from"] = dr["from"]
        if dr.get("to"):
            out["date_to"] = dr["to"]
        return out

    def push_hold(self, *, matter_id: str, query: dict, reason: str,
                  preservation_until: str | None = None) -> dict | None:
        """Mirror a placed vault hold → set the control_plane gate. No-op if no mappable subject."""
        if not self.enabled:
            return None
        subject = (query or {}).get("subject_ref")
        if not subject:
            return None  # only payer-subject holds map onto the payment ledger
        body = {"action": "set", "matter_id": matter_id,
                "subject_ref": self._subject_of(subject), "reason": reason,
                **self._scope_from_query(query)}
        if preservation_until:
            body["preservation_until"] = preservation_until
        return self._post(body)

    def release_hold(self, *, matter_id: str, query: dict, reason: str) -> dict | None:
        """Mirror a released vault hold → clear the control_plane gate."""
        if not self.enabled:
            return None
        subject = (query or {}).get("subject_ref")
        if not subject:
            return None
        body = {"action": "release", "matter_id": matter_id,
                "subject_ref": self._subject_of(subject), "reason": reason,
                **self._scope_from_query(query)}
        return self._post(body)

    def reconcile(self, active_holds: Iterable[dict]) -> int:
        """Idempotently re-assert the gate for every currently-active vault hold (drift repair).

        Run periodically. Re-pushing ``set`` is idempotent; matters released in the vault are cleared by
        :meth:`release_hold` at release time, so this only needs to (re)assert the active set.
        """
        if not self.enabled:
            return 0
        n = 0
        for h in active_holds:
            if self.push_hold(matter_id=h.get("matter_id"), query=h.get("query") or {},
                              reason=h.get("reason", "reconcile"),
                              preservation_until=h.get("release_blocked_until")) is not None:
                n += 1
        return n


def bridge_from_env(subject_of=None) -> "LegalHoldBridge | None":
    """Build a bridge from ``VAULT_GDPR_BRIDGE_URL`` + ``VAULT_GDPR_BRIDGE_TOKEN``; ``None`` if unset."""
    url = os.environ.get("VAULT_GDPR_BRIDGE_URL")
    token = os.environ.get("VAULT_GDPR_BRIDGE_TOKEN")
    if not url or not token:
        return None
    return LegalHoldBridge(url, token, subject_of=subject_of)
