"""Consolidated auditor evidence-pack export.

Bundles the ingested evidence packs plus a verification summary into a single archive the customer
hands to an auditor — who re-verifies it offline, independently.
"""
from __future__ import annotations

import io
import json
import os
import zipfile

from algovoi_command_center.engine import PackResult
from algovoi_command_center.posture import Posture


def _summary(packs: list[PackResult], posture: Posture) -> dict:
    return {
        "report": "AlgoVoi Compliance Command Center — auditor evidence summary",
        "estate": posture.estate,
        "all_verified": posture.all_verified,
        "metrics": {m.key: {"label": m.label, "value": m.value, "verified": m.verified}
                    for m in posture.metrics},
        "packs": [
            {"pack": p.pack, "kid": p.kid, "verified": p.verified,
             "timestamp_binding": p.timestamp_binding,
             "chains": [{"name": c.name, "type": c.entry_type, "entries": c.entries,
                         "verified": c.verified, "head": c.head, "reason": c.reason}
                        for c in p.chains]}
            for p in packs],
        "how_to_verify": "Install pqcrypto + rfc8785, then run the bundled verifier against each pack "
                         "directory. Offline, public key only — no AlgoVoi software or service.",
    }


def build_auditor_pack(ingest_dir: str, packs: list[PackResult], posture: Posture) -> bytes:
    """Return a ZIP (bytes) of the evidence packs + a verification summary."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("VERIFICATION-SUMMARY.json", json.dumps(_summary(packs, posture), indent=2))
        for p in packs:
            src = os.path.join(ingest_dir, p.pack)
            base = src if os.path.isdir(src) else ingest_dir
            for root, _dirs, files in os.walk(base):
                for f in files:
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, ingest_dir)
                    z.write(full, f"evidence/{rel}")
            if not os.path.isdir(src):  # single-pack ingest dir
                break
    return buf.getvalue()
