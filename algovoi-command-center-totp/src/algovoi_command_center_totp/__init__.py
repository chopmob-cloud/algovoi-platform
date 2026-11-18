"""TOTP (RFC 6238) authenticator-app second factor for the AlgoVoi Compliance Command Center.

Standard library only, so it installs and runs anywhere the console does, fully offline and air-gap
friendly. The console discovers this add-on through the ``algovoi_command_center.auth_factors`` entry
point: ``pip install algovoi-command-center-totp`` and the console offers TOTP enrollment with no config.

The factor contract the console drives:
  - ``name`` / ``label`` — identity for storage and the UI;
  - ``enroll(username)`` -> ``{"secret", "provisioning_uri"}`` — a fresh shared secret plus the
    ``otpauth://`` URI to hand to an authenticator app (Google Authenticator, Authy, 1Password, ...);
  - ``verify(secret, code)`` -> ``bool`` — check a 6-digit code against the shared secret, with a small
    time window for clock skew.
No secrets are stored by this package; the console persists the shared secret in its own account store.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

__version__ = "0.1.2"

_DIGITS = 6
_PERIOD = 30
_SKEW_WINDOWS = 1  # accept the code from the previous / next step to tolerate clock drift


def _b32_secret() -> str:
    """A fresh 160-bit base32 secret (RFC 4648, no padding) — the size RFC 6238 recommends for SHA-1."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int, digits: int = _DIGITS) -> str:
    """RFC 4226 HOTP for one counter value, as a zero-padded decimal string."""
    pad = "=" * ((-len(secret_b32)) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def totp_at(secret_b32: str, when: float | None = None, period: int = _PERIOD,
            digits: int = _DIGITS) -> str:
    """The TOTP code valid at ``when`` (defaults to now)."""
    when = time.time() if when is None else when
    return _hotp(secret_b32, int(when // period), digits)


def verify(secret_b32: str, code: str, *, when: float | None = None, period: int = _PERIOD,
           digits: int = _DIGITS, windows: int = _SKEW_WINDOWS) -> bool:
    """True iff ``code`` matches the secret within +/- ``windows`` time steps (constant-time compare)."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != digits:
        return False
    when = time.time() if when is None else when
    counter = int(when // period)
    ok = False
    # iterate the whole window (do not short-circuit) so timing does not leak which step matched
    for step in range(-windows, windows + 1):
        if hmac.compare_digest(_hotp(secret_b32, counter + step, digits), code):
            ok = True
    return ok


def provisioning_uri(secret_b32: str, username: str, issuer: str) -> str:
    """The ``otpauth://totp/...`` URI an authenticator app imports (also renderable as a QR code)."""
    label = urllib.parse.quote(f"{issuer}:{username}")
    q = urllib.parse.urlencode({"secret": secret_b32, "issuer": issuer,
                                "algorithm": "SHA1", "digits": _DIGITS, "period": _PERIOD})
    return f"otpauth://totp/{label}?{q}"


def qr_svg(uri: str) -> str | None:
    """An inline SVG QR code for ``uri`` an authenticator app can scan, or None if ``segno`` is not
    installed (the console then falls back to showing the setup key). No network, pure-Python."""
    try:
        import io
        import segno
    except Exception:  # noqa: BLE001 — segno absent: caller shows the setup key instead
        return None
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, border=2, dark="#1d1d1b", light=None)
    svg = buf.getvalue().decode("utf-8")
    i = svg.find("<svg")   # drop the XML prolog so it embeds cleanly inline
    return svg[i:] if i != -1 else svg


class TotpFactor:
    """The discovered factor object the console instantiates and drives.

    Commercial add-on: construction enforces a valid AlgoVoi suite licence, fail-closed, the same way
    the rest of the suite does. In a licensed Command Center the bundle licence is present, so the
    factor loads normally; without one it raises and the console simply does not offer TOTP.
    """

    name = "totp"
    label = "Authenticator app (TOTP)"
    issuer = "AlgoVoi Compliance Command Center"

    def __init__(self) -> None:
        from algovoi_command_center_totp import licensing
        licensing.require_license()  # fail-closed — no valid suite licence, no factor

    def enroll(self, username: str) -> dict:
        secret = _b32_secret()
        uri = provisioning_uri(secret, username, self.issuer)
        out = {"secret": secret, "provisioning_uri": uri, "label": self.label,
               "instructions": ("Scan the QR code with an authenticator app (Google Authenticator, "
                                "Authy, 1Password), or add the setup key by hand. Then enter the "
                                "6-digit code the app shows to activate.")}
        svg = qr_svg(uri)
        if svg:
            out["qr_svg"] = svg
        return out

    def verify(self, secret: str, code: str) -> bool:
        return verify(secret, code)
