"""
Runtime licence enforcement for the Mandate Auditor Suite.

Two valid tiers:
  commercial  -- standard paid AlgoVoi licence
  v0          -- free tier for pinned substrate-v0 adopters; issued by AlgoVoi on request

Verification is fully OFFLINE: same Falcon-1024 issuer key as the rest of the AlgoVoi suite.
No network call; no phone-home. The verifier (verify_audit_report) is exempt -- it is the
free client-sovereign trust surface and carries no licence check.

Provide the licence via either:
  ALGOVOI_LICENSE_KEY   -- the licence key string (whitespace/comma-separated for multi-package)
  ALGOVOI_LICENSE_FILE  -- path to a file containing it
"""
from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone

import rfc8785

try:
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
    _HAS_FALCON = True
except Exception:  # pragma: no cover
    _HAS_FALCON = False

# Same AlgoVoi licence-fulfilment issuer Falcon-1024 public key (kid ce299eca183dc4e3).
_ISSUER_PUBKEY_B64 = (
    "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"
    "l9TKjR0plrzxAlz0lNVC5bLjsRMFtig2A5A="
)
_PUBLIC_KEY_BYTES = 1793

PACKAGE_NAME = "algovoi-mandate-auditor"

# Both commercial and pinned-v0 tier keys are accepted.
# v0 keys are issued free to adopters who have pinned to substrate v0 (Apache-2.0 layer).
# commercial keys are issued with a paid AlgoVoi licence.
_VALID_TIERS = {"commercial", "v0"}


class LicenseError(RuntimeError):
    """Raised when no valid licence is present. The auditor will not initialise."""


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def _is_expired(iso: str | None) -> bool:
    if not iso:
        return True
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return True
    return datetime.now(timezone.utc) >= exp


def _load_license_keys() -> list[str]:
    raw = os.environ.get("ALGOVOI_LICENSE_KEY", "") or ""
    path = os.environ.get("ALGOVOI_LICENSE_FILE")
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                raw = raw + " " + fh.read()
        except Exception:  # noqa: BLE001
            pass
    return [t for t in re.split(r"[\s,]+", raw) if t]


def verify_license_offline(license_key: str) -> tuple[bool, str]:
    """Return (ok, reason). Validates signature + type + package + tier + expiry."""
    if not _HAS_FALCON:
        return False, "pqcrypto unavailable"
    try:
        pub = base64.b64decode(_ISSUER_PUBKEY_B64)
        env = json.loads(_b64u_decode(license_key))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception:  # noqa: BLE001
        return False, "malformed licence key"
    if not isinstance(payload, dict) or payload.get("type") != "oem_license":
        return False, "not an oem_license"
    if len(pub) != _PUBLIC_KEY_BYTES:
        return False, "bad issuer key"
    try:
        ok = bool(_falcon_verify(pub, rfc8785.dumps(payload), sig))
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        return False, "signature verification failed"
    if payload.get("package") != PACKAGE_NAME:
        return False, f"licence is for {payload.get('package')!r}, not {PACKAGE_NAME!r}"
    tier = payload.get("tier", "commercial")
    if tier not in _VALID_TIERS:
        return False, f"unrecognised tier {tier!r}"
    if _is_expired(payload.get("expires_at")):
        return False, "licence has expired"
    return True, f"active:{tier}"


def require_license() -> dict:
    """Enforce a valid commercial or v0 licence, or raise LicenseError.

    Accepts both commercial and v0 tier keys. v0 keys are issued free to
    pinned substrate-v0 adopters; commercial keys are issued with a paid licence.
    verify_audit_report() is exempt from this check -- it is the free trust surface.
    """
    keys = _load_license_keys()
    if not keys:
        raise LicenseError(
            f"No licence found for {PACKAGE_NAME}. "
            "Set ALGOVOI_LICENSE_KEY to a commercial or v0 tier key. "
            "v0 keys are issued free to pinned substrate-v0 adopters -- contact chopmob@gmail.com."
        )
    reason = "no matching licence"
    for key in keys:
        ok, reason = verify_license_offline(key)
        if ok:
            return json.loads(_b64u_decode(key))["payload"]
    raise LicenseError(f"Invalid licence for {PACKAGE_NAME}: {reason}")
