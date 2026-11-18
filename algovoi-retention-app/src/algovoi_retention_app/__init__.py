"""AlgoVoi Retention App -- stateful payment-receipt retention service.

COMMERCIAL / LOCAL-ONLY. Builds on the public ``algovoi-retention-chain``
primitive (the open reference) and adds the stateful product: a DSN-backed,
append-only, per-issuer retention store; a Falcon-1024 signed, offline-verifiable
regulator evidence pack (the ``.epi`` pattern); and a Compliance Command Center
live-service + evidence bolt-in.

Trust is store-independent: every chain_ref is content-addressed and every
exported pack is signed and re-verifiable offline, so a database swap or
corruption cannot forge integrity.

Regulatory alignment: MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77.
"""
from __future__ import annotations

__version__ = "0.1.1"

ENTRY_TYPE = "retention_chain_link"
"""The CCC evidence entry_type this product emits (see posture._TYPE_LABEL)."""

REG_BASIS = ["MiCA-80", "DORA-14", "AMLR-56"]
