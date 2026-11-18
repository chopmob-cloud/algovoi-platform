# SPDX-License-Identifier: LicenseRef-AlgoVoi-Proprietary
"""Evidence-pack integrity (security fix 2026-08-19): stable-key required, signed manifest pins
count+head (truncation-evident), and a shipped verifier that can anchor to a pinned kid."""
from __future__ import annotations

import json
import os

import pytest

from algovoi_doc_archive import signing
from algovoi_recovery_vault.evidence_export import (
    export_evidence_pack,
    verify_evidence_pack,
    CHAIN_FILE,
)


class _StubVault:
    def status(self) -> dict:
        return {
            "archives": {
                "a1": {"threshold_k": 2, "total_n": 3, "support_assisted": False, "has_envelope": True},
                "a2": {"threshold_k": 2, "total_n": 3, "support_assisted": True, "has_envelope": True},
            },
            "keys": {
                "k1": {"kind": "key", "threshold_k": 2, "total_n": 3, "support_assisted": False, "has_envelope": True},
            },
            "algovoi_access": "assisted",
        }


def test_ephemeral_key_requires_opt_in(tmp_path):
    with pytest.raises(ValueError, match="stable public_key"):
        export_evidence_pack(_StubVault(), str(tmp_path / "p0"))


def test_pack_verifies_and_anchors(tmp_path):
    pk, sk = signing.generate_keypair()
    out = export_evidence_pack(_StubVault(), str(tmp_path / "p1"), public_key=pk, secret_key=sk)
    r = verify_evidence_pack(out)
    assert r["valid"] is True and r["entry_count"] == 3
    # anchoring: a wrong pinned kid is rejected even though the pack self-verifies
    assert verify_evidence_pack(out, expected_kid="deadbeefdeadbeef")["valid"] is False
    # correct pinned kid passes
    assert verify_evidence_pack(out, expected_kid=signing.kid_for(pk))["valid"] is True


def test_truncation_detected_by_manifest(tmp_path):
    pk, sk = signing.generate_keypair()
    out = export_evidence_pack(_StubVault(), str(tmp_path / "p2"), public_key=pk, secret_key=sk)
    path = os.path.join(out, CHAIN_FILE)
    chain = json.load(open(path, encoding="utf-8"))
    # drop one custody entry, keep the signed manifest trailer -> count/head no longer match
    truncated = chain[:-2] + [chain[-1]]
    json.dump(truncated, open(path, "w", encoding="utf-8"))
    assert verify_evidence_pack(out)["valid"] is False
