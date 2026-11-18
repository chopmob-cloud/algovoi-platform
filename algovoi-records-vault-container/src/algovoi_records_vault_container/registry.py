"""Container registry — issue, list, revoke, and emit a signed revocation list for ``.acv`` containers.

This is the engine the Compliance Command Center drives to **create and revoke** sealed containers. It
persists an append-only index (JSONL) of issued containers, signs each container and the current CRL with
the console signer (or a raw key pair), and exposes a posture summary. Revocation is offline-enforced:
:meth:`current_crl` returns a Falcon-signed list the recipient's extractor checks before it will open a
container (see :mod:`algovoi_records_vault_container.crl`).
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone

from algovoi_records_vault_container import container as _container
from algovoi_records_vault_container import crl as _crl
from algovoi_records_vault_container import licensing


def _iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


class ContainerRegistry:
    def __init__(self, *, index_path: str, out_dir: str, issuer_signer=None,
                 issuer_public_key: bytes | None = None, issuer_secret_key: bytes | None = None,
                 registry: str = "default", escrow_public_key: bytes | None = None,
                 escrow_secret_key: bytes | None = None) -> None:
        self.index_path = index_path
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        os.makedirs(os.path.dirname(index_path) or ".", exist_ok=True)
        self._signer = issuer_signer
        self._pub = issuer_public_key
        self._sec = issuer_secret_key
        self._escrow_pub = escrow_public_key      # console recovery key (public wraps, secret recovers)
        self._escrow_sec = escrow_secret_key
        self.registry = registry
        self._records: list[dict] = self._load()

    @property
    def escrow_available(self) -> bool:
        return self._escrow_pub is not None

    def _load(self) -> list[dict]:
        if os.path.exists(self.index_path):
            with open(self.index_path, encoding="utf-8") as fh:
                return [json.loads(ln) for ln in fh if ln.strip()]
        return []

    def _persist(self) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for r in self._records:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        os.replace(tmp, self.index_path)

    def create(self, *, documents: list[dict], recipient_public_key: bytes, container_id: str | None = None,
               title: str | None = None, expires_at: str | None = None,
               require_revocation_check: bool = True, recovery: dict | None = None,
               console_recoverable: bool = False, opaque_names: bool = False,
               min_crl_at: str | None = None) -> dict:
        """Seal ``documents`` to ``recipient_public_key`` and record the issuance. Returns the manifest
        (which includes ``path`` to the written ``.acv`` and, when ``recovery`` is set, one-time
        ``recovery.shares`` to distribute to custodians). ``recovery`` = ``{"threshold_k", "total_n",
        "include_algovoi_support"?}``. ``console_recoverable=True`` also wraps the content key to the
        console escrow key so this container can be recovered 100% from the console via :meth:`recover`."""
        licensing.require_license()
        cid = container_id or ("acv-" + secrets.token_hex(8))
        if any(r["container_id"] == cid for r in self._records):
            raise ValueError(f"container_id {cid!r} already exists")
        if console_recoverable and self._escrow_pub is None:
            raise ValueError("console recovery requested but no escrow key is configured")
        path = os.path.join(self.out_dir, cid + ".acv")
        man = _container.seal_container(
            documents=documents, recipient_public_key=recipient_public_key,
            issuer_signer=self._signer, issuer_public_key=self._pub, issuer_secret_key=self._sec,
            container_id=cid, out_path=path, title=title, expires_at=expires_at,
            revocation_registry=self.registry, require_revocation_check=require_revocation_check,
            recovery=recovery, escrow_public_key=self._escrow_pub if console_recoverable else None,
            opaque_names=opaque_names, min_crl_at=min_crl_at)
        rec_meta = man.get("recovery", {"enabled": False})
        self._records.append({
            "container_id": cid, "recipient_kid": man["recipient_kid"], "created_at": man["created_at"],
            "documents": man["documents"], "title": title, "path": path, "sha256": man["sha256"],
            "expires_at": expires_at, "revoked": False, "revoked_at": None, "reason": None,
            # record only that recovery exists + its policy; the shares themselves are NEVER stored.
            "recovery": {"enabled": rec_meta.get("enabled", False),
                         "threshold_k": rec_meta.get("threshold_k"), "total_n": rec_meta.get("total_n")},
            "console_recoverable": bool(man.get("escrow", {}).get("enabled")),
        })
        self._persist()
        return man

    def recover(self, container_id: str) -> tuple[dict, dict]:
        """Recover a ``console_recoverable`` container 100% from the console escrow key (no recipient key,
        no custodian shares). Returns ``(header_payload, {name: data})``. Raises if escrow is unavailable
        or the container was not sealed console-recoverable."""
        licensing.require_license()
        if self._escrow_sec is None:
            raise ValueError("no escrow secret key available on this console")
        rec = next((r for r in self._records if r["container_id"] == container_id), None)
        if rec is None:
            raise KeyError(container_id)
        return _container.recover_via_escrow(rec["path"], escrow_secret_key=self._escrow_sec)

    def revoke(self, container_id: str, reason: str = "") -> dict:
        """Mark a container revoked. It will be refused by any extractor given the updated CRL."""
        licensing.require_license()
        rec = next((r for r in self._records if r["container_id"] == container_id), None)
        if rec is None:
            raise KeyError(container_id)
        if not rec["revoked"]:
            rec["revoked"] = True
            rec["revoked_at"] = _iso()
            rec["reason"] = reason
            self._persist()
        return {"container_id": container_id, "revoked": True, "revoked_at": rec["revoked_at"]}

    def current_crl(self) -> str:
        """The signed revocation list covering every revoked container in this registry."""
        revoked = [{"container_id": r["container_id"], "revoked_at": r["revoked_at"],
                    "reason": r.get("reason") or ""} for r in self._records if r["revoked"]]
        return _crl.build_crl(revoked=revoked, registry=self.registry, issuer_signer=self._signer,
                              issuer_public_key=self._pub, issuer_secret_key=self._sec)

    def list_containers(self) -> list[dict]:
        """All issued containers (server-side ``path`` omitted)."""
        return [{k: v for k, v in r.items() if k != "path"} for r in self._records]

    def posture(self) -> dict:
        issued = len(self._records)
        revoked = sum(1 for r in self._records if r["revoked"])
        return {"issued": issued, "revoked": revoked, "active": issued - revoked}
