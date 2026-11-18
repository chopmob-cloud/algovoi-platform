# Copyright (c) 2026 AlgoVoi (chopmob-cloud). All Rights Reserved.
# AlgoVoi Commercial License v1.0 — see LICENSE for terms.
# Evaluation use only. Commercial use: hello@algovoi.co.uk
"""AlgoVoi ZKP Receipt — zero-knowledge proof-bound payment receipt attestation.

Binds an ATB Phase 2 ZKP credential to a specific on-chain payment receipt.
Proves "the agent that made this payment has ATB score >= threshold."

IETF anchor: draft-hopley-x402-pqc-credential-binding-00
"""
from algovoi_zkp_receipt._version import __version__
from algovoi_zkp_receipt.models import (
    PaymentReceipt,
    ZkpReceiptEnvelope,
    ZkpReceiptVerifyResult,
)
from algovoi_zkp_receipt.receipt import (
    build_zkp_receipt_payload,
    verify_zkp_receipt,
)

__all__ = [
    "__version__",
    "PaymentReceipt",
    "ZkpReceiptEnvelope",
    "ZkpReceiptVerifyResult",
    "build_zkp_receipt_payload",
    "verify_zkp_receipt",
]
