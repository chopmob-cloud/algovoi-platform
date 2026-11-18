"""The edge decision chain: append-only, hash-linked, signed ALLOW/BLOCK decisions.

Same envelope + hashing shape as the rest of the suite (``{"payload","alg":"Falcon-1024","kid","sig"}``,
``prev_entry_hash = "sha256:"+SHA-256(JCS(payload))``), entry type ``edge_decision``, so one Compliance
Command Center instance verifies edge, guard, decision, settlement and payout chains with one code path.
Altering or dropping one decision breaks the chain from that point on.
"""
from __future__ import annotations

import base64
import json
import os

import rfc8785
from algovoi_agent_passport import signing

from algovoi_edge_sentinel import hybrid
from algovoi_edge_sentinel.refs import _prefixed

ENTRY_TYPE = "edge_decision"
CHAIN_FILE = "edge_decision_chain.json"
CANON_VERSION = "jcs-rfc8785-v1"


def _make_envelope(payload: dict, sk: bytes, pk: bytes,
                   mldsa_sk: bytes | None, mldsa_pk: bytes | None) -> str:
    msg = rfc8785.dumps(payload)
    env = {"payload": payload, "alg": "Falcon-1024", "kid": signing.kid_for(pk),
           "sig": signing.b64u_encode(signing.sign_bytes(sk, msg))}
    if mldsa_sk is not None and mldsa_pk is not None:
        env["alg2"] = hybrid.ALG
        env["kid2"] = hybrid.kid_for(mldsa_pk)
        env["sig2"] = signing.b64u_encode(hybrid.sign_bytes(mldsa_sk, msg))
    return signing.b64u_encode(json.dumps(env, separators=(",", ":"), sort_keys=True).encode())


class EdgeLedger:
    """Append-only, hash-linked ledger of one sentinel key's signed edge decisions."""

    def __init__(self, decision_secret_key: bytes, decision_public_key: bytes,
                 mldsa_secret_key: bytes | None = None, mldsa_public_key: bytes | None = None,
                 store=None) -> None:
        self.sk = decision_secret_key
        self.pk = decision_public_key
        self.mldsa_sk = mldsa_secret_key
        self.mldsa_pk = mldsa_public_key
        self.kid = signing.kid_for(decision_public_key)
        self.store = store
        self._mem: list[str] = []
        if store is not None:
            self._seq = store.count()
            last = store.last_envelope()
            self._prev = _prefixed(json.loads(signing.b64u_decode(last))["payload"]) if last else None
        else:
            self._seq = 0
            self._prev = None

    @property
    def envelopes(self) -> list[str]:
        return self.store.load() if self.store is not None else self._mem

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def head(self) -> str | None:
        return self._prev

    def append(self, core: dict) -> tuple[str, dict]:
        payload = {
            "canon_version": CANON_VERSION,
            "type": ENTRY_TYPE,
            "seq": self._seq,
            "prev_entry_hash": self._prev,
            **core,
        }
        envelope = _make_envelope(payload, self.sk, self.pk, self.mldsa_sk, self.mldsa_pk)
        if self.store is not None:
            self.store.append(seq=self._seq, envelope=envelope, decision=payload["decision"],
                              check=payload["check"], reason_code=payload["reason_code"],
                              evaluated_at=payload["evaluated_at"])
        else:
            self._mem.append(envelope)
        self._prev = _prefixed(payload)
        self._seq += 1
        return envelope, payload

    def export_pack(self, out_dir: str) -> str:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
            json.dump(self.envelopes, fh)
        with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(self.pk).decode())
        return out_dir


__all__ = ["ENTRY_TYPE", "CHAIN_FILE", "CANON_VERSION", "EdgeLedger"]
