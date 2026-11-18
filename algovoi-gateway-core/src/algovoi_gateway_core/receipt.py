"""Signed, no-PII settlement receipts: the audit-grade evidence a gateway settlement produces.

Each confirmed settlement becomes a Falcon-1024 signed envelope in a hash-linked chain in the
common evidence-pack format the Compliance Command Center ingests (entry_type
``gateway_settlement``). On-chain addresses are content-addressed (``payer_ref`` /
``payee_ref`` = sha256(network:address)) so the receipt carries no raw counterparty data; the
public ``tx_id`` and amount remain for cross-checking against the chain. The crypto core is
``substrate2`` (byte-identical to the rest of the suite).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone

import substrate2
from substrate2.pqc import falcon_kid, generate_falcon_1024_keypair, sign_falcon_1024

from algovoi_gateway_core.provider import PaymentRequest, SettlementObservation

ENTRY_TYPE = "gateway_settlement"
CHAIN_FILE = "gateway_settlement_chain.json"
PAYOUT_ENTRY_TYPE = "gateway_payout"
PAYOUT_CHAIN_FILE = "gateway_payout_chain.json"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _addr_ref(network: str, address: str | None) -> str | None:
    if not address:
        return None
    return "sha256:" + hashlib.sha256(f"{network}:{address}".encode()).hexdigest()


class SettlementLedger:
    """An append-only, hash-linked ledger of signed settlement receipts for one gateway key."""

    def __init__(self, public_key: bytes, secret_key: bytes) -> None:
        self.pk = public_key
        self.sk = secret_key
        self.kid = falcon_kid(public_key)
        self._seq = 0
        self._prev: str | None = None
        self.envelopes: list[str] = []
        # outbound payouts (custody) keep their own hash-linked chain, signed with the same key
        self._payout_seq = 0
        self._payout_prev: str | None = None
        self.payout_envelopes: list[str] = []

    @classmethod
    def generate(cls) -> "SettlementLedger":
        pk, sk = generate_falcon_1024_keypair()
        return cls(pk, sk)

    def record(self, req: PaymentRequest, obs: SettlementObservation) -> dict:
        """Append a signed receipt for a confirmed settlement. Returns the no-PII payload."""
        if not obs.settled:
            raise ValueError("refusing to record an unsettled observation")
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        payload = {
            "canon_version": "jcs-rfc8785-v1",
            "type": ENTRY_TYPE,
            "seq": self._seq,
            "prev_entry_hash": self._prev,
            "network": obs.network,
            "asset": obs.asset or req.asset,
            # on-chain amounts can be uint64 (> 2^53), so carry them as decimal strings
            # (the blockchain convention) to stay within JCS/JSON-safe integer bounds.
            "amount_minor": str(obs.amount_minor if obs.amount_minor is not None else req.amount_minor),
            "tx_id": obs.tx_id,
            "payee_ref": _addr_ref(obs.network, obs.pay_to or req.pay_to),
            "payer_ref": _addr_ref(obs.network, obs.payer),
            "reference_ref": "sha256:" + hashlib.sha256(req.reference.encode()).hexdigest(),
            "confirmations": obs.confirmations,
            "finalized": bool(obs.finalized),
            "settled_at_ms": obs.observed_at_ms or now_ms,
            # the Spend Guardrail decision that authorized this spend, if any (no-PII content ref)
            "authorized_by_ref": req.authorized_by_ref,
        }
        env = {"payload": payload, "alg": "Falcon-1024", "kid": self.kid,
               "sig": _b64u(sign_falcon_1024(self.sk, substrate2.canonicalize_bytes(payload)))}
        self.envelopes.append(_b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()))
        self._prev = substrate2.sha256_jcs_prefixed(payload)
        self._seq += 1
        return payload

    def record_payout(self, *, network: str, asset: str, amount_minor: int, pay_to: str,
                      tx_id: str, reference: str, authorized_by_ref: str | None = None) -> dict:
        """Append a signed, no-PII receipt for a confirmed outbound payout. Returns the payload."""
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        payload = {
            "canon_version": "jcs-rfc8785-v1",
            "type": PAYOUT_ENTRY_TYPE,
            "seq": self._payout_seq,
            "prev_entry_hash": self._payout_prev,
            "network": network,
            "asset": asset,
            "amount_minor": str(amount_minor),
            "tx_id": tx_id,
            "payee_ref": _addr_ref(network, pay_to),
            "reference_ref": "sha256:" + hashlib.sha256(reference.encode()).hexdigest(),
            "paid_at_ms": now_ms,
            # the Spend Guardrail decision that authorized this payout, if any (no-PII content ref)
            "authorized_by_ref": authorized_by_ref,
        }
        env = {"payload": payload, "alg": "Falcon-1024", "kid": self.kid,
               "sig": _b64u(sign_falcon_1024(self.sk, substrate2.canonicalize_bytes(payload)))}
        self.payout_envelopes.append(_b64u(json.dumps(env, separators=(",", ":"), sort_keys=True).encode()))
        self._payout_prev = substrate2.sha256_jcs_prefixed(payload)
        self._payout_seq += 1
        return payload

    def export_pack(self, out_dir: str) -> str:
        """Write a CCC-ingestable evidence pack (settlement + payout chains + public key)."""
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, CHAIN_FILE), "w", encoding="utf-8") as fh:
            json.dump(self.envelopes, fh)
        if self.payout_envelopes:
            with open(os.path.join(out_dir, PAYOUT_CHAIN_FILE), "w", encoding="utf-8") as fh:
                json.dump(self.payout_envelopes, fh)
        with open(os.path.join(out_dir, "public_key.b64"), "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(self.pk).decode())
        return out_dir


__all__ = ["ENTRY_TYPE", "CHAIN_FILE", "SettlementLedger"]
