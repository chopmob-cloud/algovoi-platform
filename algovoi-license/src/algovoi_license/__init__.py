"""algovoi-license — the shared offline licence gate for AlgoVoi commercial add-ons (Tier B).

A tiny reusable helper so a licence-gated add-on is a two-line gate rather than a copied module with an
embedded key to keep in sync::

    from algovoi_license import require_license
    require_license("algovoi-command-center-totp")   # fail-closed at load time

Verification is fully OFFLINE: the buyer's licence key (a Falcon-1024-signed envelope issued by AlgoVoi
on purchase) is checked against the embedded issuer public key — signature + type + package/bundle match
+ expiry. It accepts either the suite ``bundle_license`` (runs every component in the on-prem bundle) or
a per-package ``oem_license`` matching the caller's distribution name. No network call, no phone-home.

``rfc8785`` (JCS) and ``pqcrypto`` (Falcon) are **soft imports**: both ship with the licensed suite, so
they are present wherever a gated add-on legitimately runs; if either is absent (e.g. the add-on is
lifted and pip-installed standalone) verification cannot run and the gate fails closed.

Provide the licence via env ``ALGOVOI_LICENSE_KEY`` (the key string) or ``ALGOVOI_LICENSE_FILE`` (a path).
"""
from __future__ import annotations

__version__ = "0.1.0"

import base64
import json
import os
import re
from datetime import datetime, timezone

# rfc8785 (JCS) and pqcrypto (Falcon) are soft imports: both ship with the licensed Command Center, so
# they are present wherever this add-on legitimately runs. If either is absent (e.g. the add-on is
# lifted and pip-installed standalone), verification cannot run and the licence check fails closed.
try:
    import rfc8785
    _HAS_JCS = True
except Exception:  # pragma: no cover
    _HAS_JCS = False

try:
    from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
    _HAS_FALCON = True
except Exception:  # pragma: no cover
    _HAS_FALCON = False

# AlgoVoi licence-fulfilment issuer Falcon-1024 PUBLIC key (kid ce299eca183dc4e3). Public key only —
# safe to embed. Real licences are signed by the matching private key, held only by AlgoVoi.
_ISSUER_PUBKEY_B64 = "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"
_PUBLIC_KEY_BYTES = 1793

_BUNDLE = "algovoi-substrate2-onprem"   # the suite bundle licence runs every component in the bundle

# A root-signed, name-constrained delegated issuer (e.g. an AV-RAILS operator's federation). The root
# vouches for a federation key, scoped to ONE package and constrained to a DID namespace, so the
# operator may mint licences for its OWN members without a per-agent purchase and for nobody else.
_FED_ISSUER_CERT_TYPE = "fed_issuer_v1"
_NAME_CONSTRAINT_DELIMS = (":", "/", "#", "?")


class LicenseError(RuntimeError):
    """Raised when no valid licence is present. The package will not initialise."""


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))


def within_name_constraint(did: str, constraints) -> bool:
    """True iff ``did`` falls within one of the DID-prefix ``constraints`` at a *syntax boundary*.

    Boundary-aware to stop the classic name-constraint escape: constraint ``did:web:acme.example``
    matches ``did:web:acme.example:agent-7`` (next char is a DID delimiter) but NOT
    ``did:web:acme.example.evil.com`` (next char ``.`` is an arbitrary continuation, so the evil
    domain is a *different* name that merely shares a textual prefix). Empty / ``*`` / non-DID
    constraints are ignored, so a delegated issuer must be genuinely constrained. Fail-closed."""
    if not isinstance(did, str) or not did.startswith("did:"):
        return False
    for c in constraints or ():
        if not isinstance(c, str) or not c.startswith("did:") or len(c) < 8:
            continue
        if did == c:
            return True
        if did.startswith(c) and did[len(c):len(c) + 1] in _NAME_CONSTRAINT_DELIMS:
            return True
    return False


def verify_fed_issuer_cert(cert, root_pub: bytes, package: str | None):
    """Verify a root-signed delegated-issuer cert. Returns ``(ok, fed_pub, constraints, reason)``.

    The cert is signed by the AlgoVoi root over its JCS-canonical ``payload``; it names the federation
    Falcon-1024 public key (``fed_pub``), is scoped to one ``package``, time-limited, and carries a
    non-empty list of DID-prefix name constraints. Every check fails closed."""
    if not (_HAS_FALCON and _HAS_JCS):
        return False, None, None, "pqcrypto/rfc8785 unavailable"
    if not isinstance(cert, dict):
        return False, None, None, "no issuer cert"
    cp = cert.get("payload")
    csig = cert.get("sig")
    if not isinstance(cp, dict) or cp.get("type") != _FED_ISSUER_CERT_TYPE:
        return False, None, None, "not a federation issuer cert"
    if package is not None and cp.get("package") != package:
        return False, None, None, f"issuer cert is for {cp.get('package')!r}, not {package!r}"
    if _is_expired(cp.get("expires_at")):
        return False, None, None, "issuer cert has expired"
    constraints = cp.get("name_constraint")
    if not isinstance(constraints, list) or not constraints or not all(
            isinstance(c, str) and c.startswith("did:") and len(c) >= 8 for c in constraints):
        return False, None, None, "issuer cert has no valid name constraint"
    try:
        fed_pub = base64.b64decode(cp["fed_pub"])
    except Exception:  # noqa: BLE001
        return False, None, None, "issuer cert has no federation key"
    if len(fed_pub) != _PUBLIC_KEY_BYTES:
        return False, None, None, "bad federation key"
    try:
        ok = bool(_falcon_verify(root_pub, rfc8785.dumps(cp), _b64u_decode(csig)))
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        return False, None, None, "issuer cert signature invalid (not signed by AlgoVoi root)"
    return True, fed_pub, constraints, "ok"


def _is_expired(iso: str | None) -> bool:
    if not iso:
        return True
    try:
        exp = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return True
    return datetime.now(timezone.utc) >= exp


def _load_license_keys() -> list[str]:
    """All licence keys available, from ALGOVOI_LICENSE_KEY (whitespace/comma-separated) and/or the
    ALGOVOI_LICENSE_FILE (one per line). A multi-package deployment can carry several; each package
    picks the one that matches its own name."""
    raw = os.environ.get("ALGOVOI_LICENSE_KEY", "") or ""
    path = os.environ.get("ALGOVOI_LICENSE_FILE")
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                raw = raw + " " + fh.read()
        except Exception:  # noqa: BLE001
            pass
    return [t for t in re.split(r"[\s,]+", raw) if t]


def verify_license_offline(license_key: str, package: str | None = None,
                           *, root_pub: bytes | None = None) -> tuple[bool, str]:
    """Return ``(ok, reason)``. Checks the Falcon signature, type, expiry, and either the suite bundle
    match or (for a per-package ``oem_license``) the ``package`` name when one is given.

    Delegated (federation) licences: if the envelope carries an ``issuer_cert`` (a root-signed,
    name-constrained :data:`_FED_ISSUER_CERT_TYPE`), the licence signature is verified against the
    federation key the root vouched for, and every ``agent_dids`` entry must fall inside the cert's
    name constraint. This lets an AV-RAILS operator allocate mesh licences to its OWN federation
    members with no per-agent purchase, while the root signature + name constraint stop it minting for
    anyone outside its namespace. ``root_pub`` overrides the embedded root key (tests only)."""
    if not _HAS_FALCON:
        return False, "pqcrypto unavailable"
    if not _HAS_JCS:
        return False, "rfc8785 unavailable"
    try:
        root = base64.b64decode(_ISSUER_PUBKEY_B64) if root_pub is None else root_pub
        env = json.loads(_b64u_decode(license_key))
        payload = env["payload"]
        sig = _b64u_decode(env["sig"])
    except Exception:  # noqa: BLE001
        return False, "malformed licence key"
    if not isinstance(payload, dict) or payload.get("type") not in ("oem_license", "bundle_license"):
        return False, "not a licence"
    if len(root) != _PUBLIC_KEY_BYTES:
        return False, "bad issuer key"

    # Delegated federation licence? Establish the verifying key + the namespace the holder must be in.
    issuer_cert = env.get("issuer_cert")
    constraints = None
    if issuer_cert is not None:
        if payload.get("type") != "oem_license":
            return False, "only per-package licences may be delegated"
        scope = payload.get("package")
        if package is not None and scope != package:
            return False, f"licence is for {scope}, not {package}"
        ok, verify_key, constraints, reason = verify_fed_issuer_cert(issuer_cert, root, scope)
        if not ok:
            return False, reason
    else:
        verify_key = root

    try:
        ok = bool(_falcon_verify(verify_key, rfc8785.dumps(payload), sig))
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        return False, "signature verification failed"
    if payload.get("type") == "bundle_license":
        if payload.get("bundle") != _BUNDLE:
            return False, f"bundle licence is for {payload.get('bundle')!r}"
        if _is_expired(payload.get("expires_at")):
            return False, "bundle licence has expired"
        return True, "active"
    if package is not None and payload.get("package") != package:
        return False, f"licence is for {payload.get('package')}, not {package}"
    if _is_expired(payload.get("expires_at")):
        return False, "licence has expired"
    # A delegated licence's named holder must live inside the federation's namespace.
    if constraints is not None:
        dids = payload.get("agent_dids")
        if isinstance(dids, str):
            dids = [dids]
        if not isinstance(dids, list) or not dids:
            return False, "delegated licence names no holder (agent_dids)"
        for d in dids:
            if not within_name_constraint(d if isinstance(d, str) else "", constraints):
                return False, f"holder {d!r} is outside the federation's name constraint"
    return True, "active"


def require_license(package: str | None = None) -> dict:
    """Enforce a valid AlgoVoi licence or raise :class:`LicenseError`; returns the licence payload.

    Accepts the suite ``bundle_license`` or a per-package ``oem_license`` (matched to ``package`` when
    given). Tries every available licence, so a deployment carrying several suite licences works. Call
    at the add-on's load point (e.g. its factory / constructor) to fail closed."""
    who = package or "this AlgoVoi add-on"
    keys = _load_license_keys()
    if not keys:
        raise LicenseError(
            f"No licence found for {who}. Set ALGOVOI_LICENSE_KEY (or ALGOVOI_LICENSE_FILE) "
            "to the licence key issued at purchase.")
    reason = "no matching licence"
    for key in keys:
        ok, reason = verify_license_offline(key, package)
        if ok:
            return json.loads(_b64u_decode(key))["payload"]
    raise LicenseError(f"Invalid licence for {who}: {reason}")


__all__ = [
    "require_license", "verify_license_offline", "LicenseError",
    "within_name_constraint", "verify_fed_issuer_cert",
]
