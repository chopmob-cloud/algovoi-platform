"""Pluggable authentication providers (SSO) for the Compliance Command Center.

v1 ships **local accounts** and **LDAP / Active Directory**. A provider just maps
``(username, password) -> {"username", "role"} | None``; the configured providers are tried in order,
so an enterprise can run "LDAP first, local fallback" with no code change. OIDC / SAML are the next
providers to add behind this same interface (they add a browser-redirect flow on top).

Directory groups map to Command Center roles via a configurable mapping; an optional default role
applies when a user authenticates but matches no mapped group.
"""
from __future__ import annotations

import os
from typing import Protocol

from algovoi_command_center import auth as _auth
from algovoi_command_center import roles


class AuthProvider(Protocol):
    name: str
    def authenticate(self, username: str, password: str) -> dict | None: ...


class LocalProvider:
    """Local accounts (PBKDF2-hashed), stored on the appliance. Air-gap default."""
    name = "local"

    def authenticate(self, username: str, password: str) -> dict | None:
        u = _auth.load_users().get(username)
        if not u or not _auth.verify_password(password, u["pwd"], u["salt"]):
            return None
        return {"username": username, "role": u["role"]}


class LdapProvider:
    """LDAP / Active Directory bind + directory-group → role mapping.

    ``bind_and_groups`` is the seam: ``(username, user_dn, password) -> list[group] | None`` (None =
    bad credentials). The default implementation uses ``ldap3``; tests inject a fake. Real LDAP support
    needs the optional ``ldap3`` dependency (``pip install algovoi-command-center[ldap]``).
    """
    name = "ldap"

    def __init__(self, *, url: str, user_dn_template: str, group_role_map: dict[str, str],
                 default_role: str | None = None, bind_and_groups=None) -> None:
        self.url = url
        self.user_dn_template = user_dn_template
        self.group_role_map = group_role_map
        self.default_role = default_role
        self._bg = bind_and_groups or self._ldap3_bind_and_groups

    def authenticate(self, username: str, password: str) -> dict | None:
        if not password:  # never allow an unauthenticated/anonymous bind to pass as a login
            return None
        try:
            groups = self._bg(username, self.user_dn_template.format(username=username), password)
        except Exception:  # noqa: BLE001 — any directory/connection error = auth failure, fail closed
            return None
        if groups is None:
            return None
        role = self._role_for(groups) or self.default_role
        return {"username": username, "role": role} if role in roles.ROLES else None

    def _role_for(self, groups: list[str]) -> str | None:
        for g in groups:
            for pattern, role in self.group_role_map.items():
                if pattern.lower() in str(g).lower():
                    return role
        return None

    def _ldap3_bind_and_groups(self, username: str, user_dn: str, password: str):  # pragma: no cover
        import ldap3
        server = ldap3.Server(self.url, get_info=ldap3.NONE)
        conn = ldap3.Connection(server, user=user_dn, password=password)
        if not conn.bind():
            return None
        conn.search(user_dn, "(objectClass=*)", attributes=["memberOf"])
        groups: list[str] = []
        if conn.entries:
            ent = conn.entries[0]
            groups = list(getattr(ent, "memberOf").values) if hasattr(ent, "memberOf") else []
        conn.unbind()
        return groups


def _parse_group_roles(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if ":" in part:
            grp, role = part.rsplit(":", 1)
            out[grp.strip()] = role.strip()
    return out


def build_chain() -> list[AuthProvider]:
    """Build the provider chain from env (``COMMAND_CENTER_AUTH``, default ``local``)."""
    order = (os.environ.get("COMMAND_CENTER_AUTH", "local")).split(",")
    chain: list[AuthProvider] = []
    for name in (n.strip() for n in order):
        if name == "local":
            chain.append(LocalProvider())
        elif name == "ldap":
            chain.append(LdapProvider(
                url=os.environ.get("COMMAND_CENTER_LDAP_URL", ""),
                user_dn_template=os.environ.get("COMMAND_CENTER_LDAP_USER_DN", "{username}"),
                group_role_map=_parse_group_roles(os.environ.get("COMMAND_CENTER_LDAP_GROUP_ROLES", "")),
                default_role=os.environ.get("COMMAND_CENTER_LDAP_DEFAULT_ROLE") or None))
    return chain or [LocalProvider()]


def authenticate(username: str, password: str) -> dict | None:
    """Try each configured provider in order; first success wins.

    A locally-recorded account explicitly marked inactive (``active`` is ``False``) may not sign in,
    whichever provider authenticated it — this is how SCIM deprovisioning (and any manual deactivation)
    takes effect. Accounts with no ``active`` field (every account predating provisioning) are active."""
    for provider in build_chain():
        u = provider.authenticate(username, password)
        if u:
            rec = _auth.load_users().get(u["username"])
            if rec is not None and rec.get("active") is False:
                return None  # deprovisioned / deactivated account: deny
            return u
    return None
