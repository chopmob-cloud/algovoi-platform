"""F4 — redaction / PII tagging + crypto-shred (GDPR + HIPAA minimum-necessary).

Two needs the evidence layer must serve without breaking integrity:

1. **Disclose less than you hold.** Tag fields ``pii`` / ``privileged`` and emit a *redacted derivation*
   as a NEW record — the original stays ML-KEM-sealed and unchanged. A signed ``redaction_record``
   (``original_doc_hash`` → ``redacted_doc_hash``, the fields removed, the method) proves the redacted
   copy is a faithful derivation of the original, so a disclosure is defensible.
2. **Erase a field without destroying the record (right to be forgotten).** *Crypto-shred*: seal
   sensitive fields under their own per-field AES-256-GCM keys; to erase one, **drop its key** — the
   field is unrecoverable, yet the record (and a signed proof it existed) survives.

No new crypto: AES-256-GCM is the same primitive the engine's encryptor uses; the records are the same
Falcon-1024-signed ``_VaultStream``.
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone

import substrate2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from algovoi_records_vault.principals import Principal, principal_fields
from algovoi_records_vault.vault import _VaultStream

_NONCE = 12
_REDACTED = "[REDACTED]"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def doc_hash(data) -> str:
    """Content hash of a record's canonical (JCS) bytes — the same shape the archive uses for dicts."""
    raw = substrate2.canonicalize_bytes(data) if isinstance(data, (dict, list)) else bytes(data)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _field_hash(value) -> str:
    """SHA-256 of a single field value's canonical bytes — what the ``hash`` method redacts a field to.

    JCS for dict/list values, UTF-8 of ``str(value)`` otherwise. Used both to *produce* a hash
    redaction and to *verify* one, so the two can never drift apart.
    """
    raw = substrate2.canonicalize_bytes(value) if isinstance(value, (dict, list)) else str(value).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def redact(data: dict, *, fields: list[str], method: str = "remove") -> tuple[dict, list[str]]:
    """Return a redacted copy of ``data`` for the given top-level ``fields``. Original is untouched.

    ``method``: ``remove`` (drop the key), ``mask`` (replace with ``[REDACTED]``), or ``hash``
    (replace with the field value's SHA-256, so equality is still checkable without the value).
    """
    if method not in ("remove", "mask", "hash"):
        raise ValueError("method must be remove | mask | hash")
    out = dict(data)
    done: list[str] = []
    for f in fields:
        if f not in out:
            continue
        if method == "remove":
            out.pop(f)
        elif method == "mask":
            out[f] = _REDACTED
        else:  # hash
            out[f] = _field_hash(out[f])
        done.append(f)
    return out, done


class RedactionLedger:
    """Append-only ``redaction/`` stream of signed redaction records proving original→redacted lineage."""

    def __init__(self, *, stream: _VaultStream) -> None:
        self._stream = stream

    async def redact_record(self, *, original_data: dict, fields: list[str], reason: str,
                            method: str = "remove", principal: Principal | None = None) -> tuple[dict, dict]:
        """Redact ``original_data`` and append a signed redaction_record. Returns (redacted_data, rec)."""
        redacted, done = redact(original_data, fields=fields, method=method)
        fields_payload = {
            "redaction_event": "redact",
            "original_doc_hash": doc_hash(original_data),
            "redacted_doc_hash": doc_hash(redacted),
            "redacted_fields": done,
            "method": method,
            "reason": reason,
            "redacted_at": _now(),
            **principal_fields(principal),
        }
        rec = await self._stream.append(fields_payload)
        return redacted, rec

    async def record_shred(self, *, doc_hash_value: str, field: str, reason: str,
                           keymap: dict | None = None, principal: Principal | None = None) -> dict:
        """Append a signed *attestation* that ``field``'s per-field key was crypto-shredded.

        This records, tamper-evidently, that the operator dropped the key — it is **not** cryptographic
        proof that every copy of the key is gone (the ledger cannot observe copies elsewhere). Pass
        ``keymap`` (the map the key was dropped from) to make the attestation evidence-backed: the call
        then refuses if the key is still present, so a "shredded" record can never be signed while the
        field is still recoverable from that keymap.
        """
        if keymap is not None and field in keymap:
            raise ValueError(
                f"refusing to record a crypto-shred for {field!r}: its key is still present in the "
                f"keymap — call crypto_shred(keymap, {field!r}) first")
        fields_payload = {
            "redaction_event": "crypto_shred",
            "doc_hash": doc_hash_value,
            "field": field,
            "reason": reason,
            "shredded_at": _now(),
            **principal_fields(principal),
        }
        return await self._stream.append(fields_payload)

    async def records(self) -> list[dict]:
        return await self._stream.list_payloads()

    async def verify_chain(self):
        """Offline integrity of the redaction stream."""
        return await self._stream.verify_chain()


def verify_derivation(record: dict, original_data: dict, redacted_data: dict) -> bool:
    """Offline: a redaction_record's hashes match the data, and the named fields are truly gone."""
    if record.get("original_doc_hash") != doc_hash(original_data):
        return False
    if record.get("redacted_doc_hash") != doc_hash(redacted_data):
        return False
    method = record.get("method")
    for f in record.get("redacted_fields", []):
        if method == "remove" and f in redacted_data:
            return False
        if method == "mask" and redacted_data.get(f) != _REDACTED:
            return False
        if method == "hash":
            # the redacted copy must carry the field value's hash (recomputed from the original),
            # not the cleartext — otherwise a 'hash' redaction would verify while the value survives
            if f not in original_data or redacted_data.get(f) != _field_hash(original_data[f]):
                return False
    return True


# ── Field-level crypto-shred ──────────────────────────────────────────────────────────────────
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def seal_fields(data: dict, *, fields: list[str]) -> tuple[dict, dict]:
    """Seal ``fields`` under fresh per-field AES-256-GCM keys. Returns (sealed_record, keymap).

    ``sealed_record`` carries the ciphertext in place of each sealed field (so the record's shape and
    existence are intact); ``keymap`` (field → base64 key) is the *only* way to recover a field — drop a
    key to crypto-shred that field forever.
    """
    sealed = dict(data)
    keymap: dict[str, str] = {}
    for f in fields:
        if f not in sealed:
            continue
        key = os.urandom(32)
        nonce = os.urandom(_NONCE)
        pt = substrate2.canonicalize_bytes(sealed[f]) if isinstance(sealed[f], (dict, list)) else str(sealed[f]).encode()
        ct = AESGCM(key).encrypt(nonce, pt, None)
        sealed[f] = {"__sealed__": True, "blob": _b64(nonce + ct)}
        keymap[f] = _b64(key)
    return sealed, keymap


def unseal_field(sealed: dict, keymap: dict, field: str) -> bytes:
    """Recover a sealed field's plaintext bytes. Raises ``KeyError`` if its key was shredded."""
    if field not in keymap:
        raise KeyError(f"field {field!r} is crypto-shredded — key unavailable, content unrecoverable")
    cell = sealed.get(field)
    if not isinstance(cell, dict) or not cell.get("__sealed__"):
        raise ValueError(f"field {field!r} is not sealed")
    blob = _b64d(cell["blob"])
    return AESGCM(_b64d(keymap[field])).decrypt(blob[:_NONCE], blob[_NONCE:], None)


def crypto_shred(keymap: dict, field: str) -> bool:
    """Erase a field by dropping its key. The sealed ciphertext remains (proof of existence) but is now
    permanently unrecoverable. Returns True if a key was dropped."""
    return keymap.pop(field, None) is not None
