"""
The passport event chain: an append-only, hash-linked ledger of signed issue and revoke events.

Beyond issuing and revoking credentials, the issuer can keep every lifecycle event in a tamper-evident
chain signed with the issuer key, and export it as the same no-PII evidence pack the Compliance Command
Center ingests (entry type ``passport_event``). An auditor then sees the full sequence of issuances and
revocations, offline-verifiable, alongside settlement and decision evidence. Altering or dropping one
event breaks the chain from that point on.

Envelope shape and hashing match the rest of the suite
(``{"payload","alg":"Falcon-1024","kid","sig"}``, ``prev_entry_hash = "sha256:"+SHA-256(JCS(payload))``),
with an optional ML-DSA-65 co-signature (``sig2``/``alg2``/``kid2``) when the issuer runs in hybrid mode.
"""
from __future__ import annotations

import base64
import hashlib
import json

import rfc8785

from algovoi_agent_passport import hybrid, signing

ENTRY_TYPE = "passport_event"
CHAIN_FILE = "passport_event_chain.json"
CANON_VERSION = "jcs-rfc8785-v1"


def _prefixed(value) -> str:
    return "sha256:" + hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def make_signed_envelope(payload: dict, sk: bytes, pk: bytes,
                        mldsa_sk: bytes | None, mldsa_pk: bytes | None) -> str:
    """Falcon-1024 envelope (byte-identical to ``signing.make_envelope``), plus an optional ML-DSA-65
    co-signature when hybrid keys are supplied."""
    msg = rfc8785.dumps(payload)
    env = {"payload": payload, "alg": "Falcon-1024", "kid": signing.kid_for(pk),
           "sig": signing.b64u_encode(signing.sign_bytes(sk, msg))}
    if mldsa_sk is not None and mldsa_pk is not None:
        env["alg2"] = hybrid.ALG
        env["kid2"] = hybrid.kid_for(mldsa_pk)
        env["sig2"] = signing.b64u_encode(hybrid.sign_bytes(mldsa_sk, msg))
    return signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


class EventLedger:
    """Append-only, hash-linked ledger of one issuer key's passport lifecycle events."""

    def __init__(self, secret_key: bytes, public_key: bytes,
                 mldsa_secret_key: bytes | None = None, mldsa_public_key: bytes | None = None) -> None:
        self.sk = secret_key
        self.pk = public_key
        self.mldsa_sk = mldsa_secret_key
        self.mldsa_pk = mldsa_public_key
        self.kid = signing.kid_for(public_key)
        self._seq = 0
        self._prev: str | None = None
        self.envelopes: list[str] = []

    @property
    def seq(self) -> int:
        return self._seq

    def append(self, core: dict) -> tuple[str, dict]:
        """Chain-link, sign, and append ``core`` (the event body). Returns ``(envelope, full_payload)``."""
        payload = {
            "canon_version": CANON_VERSION,
            "type": ENTRY_TYPE,
            "seq": self._seq,
            "prev_entry_hash": self._prev,
            **core,
        }
        envelope = make_signed_envelope(payload, self.sk, self.pk, self.mldsa_sk, self.mldsa_pk)
        self.envelopes.append(envelope)
        self._prev = _prefixed(payload)
        self._seq += 1
        return envelope, payload

    def export_pack(self, out_dir: str) -> str:
        """Write a CCC-ingestable evidence pack (event chain + public key)."""
        import os
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
            json.dump(self.envelopes, fh)
        with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(self.pk).decode())
        return out_dir


__all__ = ["ENTRY_TYPE", "CHAIN_FILE", "CANON_VERSION", "EventLedger", "make_signed_envelope"]
