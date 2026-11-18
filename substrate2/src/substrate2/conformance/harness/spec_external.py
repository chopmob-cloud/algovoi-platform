"""
Section 3 — external spec verifier round-trip.

The gold-standard provenance-independent check. substrate2 builds a Falcon-1024 ATB
envelope from the cert_response payload, writes temp envelope.b64 + pubkey.b64, then runs
the UNMODIFIED verify_from_spec.py (stdlib + rfc8785 + pqcrypto only, no AlgoVoi code) as
a subprocess and asserts exit 0. Also re-verifies the shipped envelope through substrate2.

If substrate2's output is accepted by an external verifier that imports no substrate2
code, wire-identity is proven without trusting substrate2's own verifier.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .._paths import (
    ATB_ENVELOPE_B64,
    ATB_PUBKEY_B64,
    VERIFY_FROM_SPEC,
)


def _load_score_payload() -> dict:
    """The shipped envelope's payload (correct issuer, correct shape) as the basis.

    Its validity window is RE-STAMPED on the copy used to build the fresh envelope. The
    shipped fixture was issued 2026-06-01 and expired 2026-07-01, so from that date on the
    external verifier rejected it as expired and this section went RED every run -- not
    because wire identity had broken, but because a hardcoded date had passed.

    What this section exists to prove is that an external verifier importing no substrate2
    code accepts substrate2's canonicalisation and Falcon-1024 signature. Expiry is not
    part of that claim, and a test that dies on a calendar date measures the calendar. So
    the window is moved forward here while every other field, including the issuer and the
    score components, is left exactly as shipped. The shipped envelope itself is untouched
    and is still cross-checked verbatim below.
    """
    from datetime import datetime, timedelta, timezone

    from substrate2.atb_credential import decode_payload

    payload = decode_payload(ATB_ENVELOPE_B64.read_text(encoding="utf-8").strip())
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload["issued_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["expires_at"] = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return payload


def run():
    from substrate2 import pqc
    from substrate2.atb_credential import build_atb_envelope_b64

    if not VERIFY_FROM_SPEC.exists():
        return False, f"external verifier missing: {VERIFY_FROM_SPEC}"

    # Build a fresh keypair + envelope with substrate2.
    pk, sk = pqc.generate_falcon_1024_keypair()
    payload = _load_score_payload()
    env_b64 = build_atb_envelope_b64(payload, sk, pk)

    with tempfile.TemporaryDirectory() as td:
        env_path = Path(td) / "env.b64"
        pk_path = Path(td) / "pk.b64"
        env_path.write_text(env_b64, encoding="utf-8")
        pk_path.write_text(base64.b64encode(pk).decode(), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(VERIFY_FROM_SPEC), str(env_path), str(pk_path)],
            capture_output=True,
            text=True,
        )
    if proc.returncode != 0:
        return False, f"verify_from_spec rejected v2 envelope (exit {proc.returncode}): {proc.stdout.strip()} {proc.stderr.strip()}"

    # Cross-check: substrate2 must also verify the shipped reference envelope.
    shipped_env = ATB_ENVELOPE_B64.read_text(encoding="utf-8").strip()
    shipped_pk = base64.b64decode(ATB_PUBKEY_B64.read_text(encoding="utf-8").strip())
    res = pqc  # placeholder to keep import used if verify path moves
    from substrate2.atb_credential import verify_atb_envelope

    shipped_ok = bool(verify_atb_envelope(shipped_env, shipped_pk))
    if not shipped_ok:
        return False, "substrate2 failed to verify the shipped reference envelope"

    return True, f"v2 envelope accepted by external verifier ({proc.stdout.strip()}); shipped envelope verified"
