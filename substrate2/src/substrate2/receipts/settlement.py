"""
substrate2.receipts.settlement — settlement attestation (SETTLED / PENDING_FINALITY / REVERSED).

From draft-hopley-x402-settlement-attestation-02 + settlement_attestation_v1 vectors.
content_hash = sha256_jcs(attestation). Not derived from v1 source.
"""
from __future__ import annotations

from ..canon import CANON_VERSION
from ._common import (
    ReceiptError,
    caip_strict,
    require_amount,
    require_caip2_chain,
    require_enum,
    require_int_ms,
    require_jurisdiction_flags,
    require_positive_int,
    require_str,
)

SETTLEMENT_RESULTS = frozenset({"SETTLED", "PENDING_FINALITY", "REVERSED"})


class SettlementAttestationError(ReceiptError):
    pass


def build_settlement_attestation(
    *,
    settled_payment_ref: str,
    settlement_result: str,
    settlement_timestamp_ms: int,
    settlement_provider_did: str,
    settlement_amount: dict,
    settlement_chain: str,
    jurisdiction_flags: list,
    settlement_chain_caip: str | None = None,
    settlement_round: int | None = None,
    canon_version: str = CANON_VERSION,
) -> dict:
    """Build a settlement attestation body.

    ``settlement_chain`` is a free-form operator label and stays that way: it is part of
    the preimage of every attestation already anchored, so its meaning cannot change
    without those records ceasing to recompute. It is, however, not interoperable --
    callers in the wild spell one chain ``algorand``, ``algorand_mainnet`` and ``algo``,
    which yields three different content hashes for the same settlement.

    ``settlement_chain_caip`` is the chain-agnostic answer, added additively. Pass a
    CAIP-2 chain id and it is gated with :func:`require_caip2` and emitted as its own
    key. Omit it and the body serialises byte-for-byte as it did before this parameter
    existed, so nothing already anchored is disturbed. Under
    ``SUBSTRATE2_CAIP_STRICT=1`` it becomes mandatory, which is the posture a new
    deployment should adopt from its first record.

    ``settlement_round`` follows the same additive discipline: the confirmed
    round/block of the settling transaction, added so evidence anchored in chain
    state proofs (e.g. avm-proofpack bundles) can be bound to the attestation.
    Pass a positive integer and it is emitted as its own key; omit it and the
    body serialises byte-for-byte as before the parameter existed.
    """
    try:
        if settlement_chain_caip is None and caip_strict():
            raise ReceiptError(
                "settlement_chain_caip is required when " + "SUBSTRATE2_CAIP_STRICT is set"
            )
        body = {
            "canon_version": require_str("canon_version", canon_version),
            "jurisdiction_flags": require_jurisdiction_flags(jurisdiction_flags),
            "settled_payment_ref": require_str("settled_payment_ref", settled_payment_ref),
            "settlement_amount": require_amount("settlement_amount", settlement_amount),
            "settlement_chain": require_str("settlement_chain", settlement_chain),
            "settlement_provider_did": require_str("settlement_provider_did", settlement_provider_did),
            "settlement_result": require_enum("settlement_result", settlement_result, SETTLEMENT_RESULTS),
            "settlement_timestamp_ms": require_int_ms("settlement_timestamp_ms", settlement_timestamp_ms),
        }
        if settlement_chain_caip is not None:
            body["settlement_chain_caip"] = require_caip2_chain(
                "settlement_chain_caip", settlement_chain_caip
            )
        if settlement_round is not None:
            body["settlement_round"] = require_positive_int(
                "settlement_round", settlement_round
            )
        return body
    except ReceiptError as exc:
        raise SettlementAttestationError(str(exc)) from exc


__all__ = ["SETTLEMENT_RESULTS", "SettlementAttestationError", "build_settlement_attestation"]
