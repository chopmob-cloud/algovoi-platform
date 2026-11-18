"""Second-factor (2FA) discovery and per-user enrollment for the Compliance Command Center.

The console does not implement any 2FA method itself. Instead it **discovers** installed factor add-ons
through the ``algovoi_command_center.auth_factors`` entry-point group, so a method is adopted simply by
installing its package (for example ``pip install algovoi-command-center-totp``) with no configuration.

A factor add-on provides an object with:
  - ``name`` / ``label`` — identity for storage and the UI;
  - ``enroll(username)`` -> ``{"secret", "provisioning_uri"}``;
  - ``verify(secret, code)`` -> ``bool``.

Enrollment is **opt-in, then required**: a user enrolls a factor voluntarily from the Security page;
once a factor is active for that user, their sign-in requires a code. Per-user factor state (the shared
secret + active flag) is persisted in the same account store the local auth provider uses, so no new
storage is introduced. The shared secret is stored alongside the password hash on the appliance.
"""
from __future__ import annotations

import importlib.metadata as _im

from algovoi_command_center import auth as _auth

_ENTRY_GROUP = "algovoi_command_center.auth_factors"


def discover() -> dict:
    """Every installed factor add-on, ``{name: factor_object}``. Empty if none is installed."""
    out: dict = {}
    try:
        eps = _im.entry_points(group=_ENTRY_GROUP)
    except TypeError:  # pragma: no cover - Python < 3.10 selection API
        eps = _im.entry_points().get(_ENTRY_GROUP, [])  # type: ignore[attr-defined]
    for ep in eps:
        try:
            factor = ep.load()()
            if getattr(factor, "name", None):
                out[factor.name] = factor
        except Exception:  # noqa: BLE001 — a broken add-on must never take the console down
            continue
    return out


def available() -> bool:
    """Is any 2FA method installed and discoverable?"""
    return bool(discover())


def catalog() -> list[dict]:
    """UI listing of installed methods: ``[{"name", "label"}]``."""
    return [{"name": n, "label": getattr(f, "label", n)} for n, f in sorted(discover().items())]


# ── per-user factor state (stored under users[username]["mfa"][name]) ──────────────

def _user_mfa(username: str) -> dict:
    return ((_auth.load_users().get(username) or {}).get("mfa") or {})


def active_factors(username: str) -> list[str]:
    """The names of factors the user has enrolled AND confirmed (active)."""
    return sorted(n for n, v in _user_mfa(username).items() if v.get("active"))


def has_active(username: str) -> bool:
    return bool(active_factors(username))


def status(username: str) -> list[dict]:
    """Per-method status for the Security page: installed methods flagged enrolled / active."""
    mine = _user_mfa(username)
    out = []
    for name, factor in sorted(discover().items()):
        rec = mine.get(name) or {}
        out.append({"name": name, "label": getattr(factor, "label", name),
                    "enrolled": bool(rec), "active": bool(rec.get("active"))})
    return out


def begin_enroll(username: str, name: str) -> dict:
    """Start enrollment: mint a secret via the factor, store it inactive, return the enrollment payload
    (secret + provisioning URI) to show once. Activation happens after the user confirms a code."""
    factor = discover().get(name)
    if factor is None:
        raise KeyError(f"2FA method {name!r} is not installed")
    data = factor.enroll(username)
    users = _auth.load_users()
    u = users.get(username)
    if u is None:
        raise KeyError(f"unknown user {username!r}")
    u.setdefault("mfa", {})[name] = {"secret": data["secret"], "active": False}
    _auth.save_users(users)
    return data


def confirm_enroll(username: str, name: str, code: str) -> bool:
    """Verify the first code and activate the factor. Returns False on a bad code (stays inactive)."""
    factor = discover().get(name)
    users = _auth.load_users()
    rec = ((users.get(username) or {}).get("mfa") or {}).get(name)
    if factor is None or rec is None:
        return False
    if not factor.verify(rec["secret"], code):
        return False
    rec["active"] = True
    _auth.save_users(users)
    return True


def verify_code(username: str, code: str) -> bool:
    """Does ``code`` satisfy any of the user's active factors? Used at the 2FA challenge step."""
    factors = discover()
    mine = _user_mfa(username)
    for name in active_factors(username):
        factor = factors.get(name)
        rec = mine.get(name)
        if factor is not None and rec is not None and factor.verify(rec["secret"], code):
            return True
    return False


def disable(username: str, name: str) -> bool:
    """Remove an enrolled factor (turns 2FA back off for that user once none remain active)."""
    users = _auth.load_users()
    mfa = (users.get(username) or {}).get("mfa") or {}
    if mfa.pop(name, None) is None:
        return False
    _auth.save_users(users)
    return True
