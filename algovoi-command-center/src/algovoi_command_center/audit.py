"""Signed console audit chain.

Every console action (login, view, export, user change) is appended to a Falcon-1024 signed,
hash-linked chain — so *who did what in the console, when* is itself tamper-evident, offline-verifiable
evidence. The console dogfoods the product. The signing key is supplied via a :class:`Signer`, so it
can live locally (v1) or in an HSM / KMS / Vault (phase f) without changing this module.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Protocol

import rfc8785

from algovoi_command_center.engine import verify_chain

_TYPE = "command_center_audit"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _jcs(p) -> bytes:
    return rfc8785.dumps(p)


def _payload_hash(p: dict) -> str:
    return "sha256:" + hashlib.sha256(_jcs(p)).hexdigest()


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes: ...
    def public_key(self) -> bytes: ...
    def kid(self) -> str: ...


class LocalSigner:
    """Holds the console's Falcon-1024 key in-process (v1 default). Phase f swaps in a wrapped HSM/KMS
    signer behind the same interface."""

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        self._pk = public_key
        self._sk = secret_key

    def public_key(self) -> bytes:
        return self._pk

    def kid(self) -> str:
        return hashlib.sha256(self._pk).hexdigest()[:16]

    def sign(self, message: bytes) -> bytes:
        from pqcrypto.sign.falcon_1024 import sign as _sign
        return _sign(self._sk, message)


class ConsoleAuditLog:
    """Append-only, Falcon-signed, hash-linked log of console actions.

    Persistence is dual-mode for backward compatibility: pass a **store** (the
    default, SQLite or Postgres via the DSN) for O(1) appends, or a legacy **file
    path** (a ``str``) to keep the original JSON-file behaviour for an existing
    deployment. The signing and hash-linking are identical either way."""

    def __init__(self, store_or_path, signer: Signer, forwarder=None) -> None:
        self._signer = signer
        # optional SIEM forwarder (off unless configured); each appended entry is streamed best-effort
        self._forwarder = forwarder
        if isinstance(store_or_path, str):
            self._path, self._store = store_or_path, None      # legacy file mode
        else:
            self._path, self._store = None, store_or_path      # store mode (default)

    def _file_load(self) -> list[str]:
        if not self._path or not os.path.exists(self._path):
            return []
        with open(self._path, encoding="utf-8") as fh:
            return json.load(fh)

    def _load(self) -> list[str]:
        return self._file_load() if self._store is None else self._store.audit_load()

    def append(self, *, action: str, principal: str, role: str = "", detail: str = "") -> dict:
        if self._store is None:
            envs = self._file_load()
            seq, last = len(envs), (envs[-1] if envs else None)
        else:
            seq, last = self._store.audit_count(), self._store.audit_last()
        prev = None
        if last is not None:
            prev = _payload_hash(json.loads(base64.urlsafe_b64decode(last + "==" * 2))["payload"])
        payload = {
            "type": _TYPE, "seq": seq, "prev_entry_hash": prev,
            "action": action, "principal": principal, "role": role, "detail": detail,
            "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        env = {"payload": payload, "sig": _b64u(self._signer.sign(_jcs(payload))), "kid": self._signer.kid()}
        env_str = _b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())
        if self._store is None:
            envs.append(env_str)
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump(envs, fh)
        else:
            self._store.audit_append(seq, env_str)
        if self._forwarder is not None:
            try:
                self._forwarder.emit(payload, _payload_hash(payload))
            except Exception:  # noqa: BLE001 — forwarding is best-effort; never break the signed chain
                pass
        return payload

    def chain(self) -> list[str]:
        return self._load()

    def entries(self) -> list[dict]:
        return [json.loads(base64.urlsafe_b64decode(e + "==" * 2))["payload"] for e in self._load()]

    def verify(self) -> tuple[bool, str]:
        res = verify_chain(self._load(), self._signer.public_key())
        return res.verified, res.reason
