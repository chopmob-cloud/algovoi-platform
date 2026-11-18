"""SCIM 2.0 (RFC 7643/7644) provisioning core for the AlgoVoi Compliance Command Center.

Framework-agnostic. It introduces **no parallel identity model and no new role concept**:

  * a SCIM **User** IS a console account in the existing local-account store
    (``algovoi_command_center.auth`` -> ``load_users`` / ``save_users``); and
  * a SCIM **Group** IS one of the four fixed RBAC roles
    (``algovoi_command_center.roles``: admin, compliance_officer, auditor, viewer).

Every lifecycle change (create / update / deactivate / role assignment) is appended to the console's
existing Falcon-signed, hash-linked audit chain, so provisioning is itself tamper-evident compliance
evidence — the same ``audit.append`` mechanism every other console action uses.

Design notes that keep the single-role RBAC model honest:
  * Each account belongs to exactly ONE group: the group matching its current role. Adding a user to a
    group sets that role; removing a user from their role group drops them to the least-privilege
    ``viewer`` baseline.
  * The four role groups are fixed. ``POST /Groups`` only succeeds for a group naming an existing role
    (idempotent); it cannot mint a new role. ``DELETE /Groups`` is rejected for the same reason.
  * ``DELETE /Users`` is a **soft deactivate** (``active=false``), never a hard delete — the account and
    its audit history are retained as evidence, and a deactivated account can no longer sign in.
  * The console can never be left without an administrator: any op that would deactivate or demote the
    last active admin is refused.

SCIM users authenticate through the console's SSO providers (SAML / OIDC / LDAP / AD); this package
provisions the account and its role, it does not set or store passwords.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone

from algovoi_command_center import auth as _auth
from algovoi_command_center import roles as _roles

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
PATCHOP_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

DEFAULT_ROLE = _roles.VIEWER

# Stable, deterministic SCIM id per account, derived from the userName. Every console account (whether
# created by SCIM or locally) is therefore addressable at /Users/{id} with no extra stored state and no
# mutation-on-read.
_ID_NS = uuid.UUID("6f4e1e2a-0000-4a00-8000-616c676f766f")


def scim_id(username: str) -> str:
    return uuid.uuid5(_ID_NS, username).hex


class ScimError(Exception):
    """A SCIM-shaped error carrying the HTTP status and optional ``scimType`` (RFC 7644 section 3.12)."""

    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_active(rec: dict) -> bool:
    # Backward compatible: an account with no ``active`` field (every pre-SCIM local account) is active.
    return rec.get("active", True) is not False


def _truthy_active(v) -> bool:
    return not (v in (False, "false", "False", 0, "0"))


def _norm_emails(value) -> list | None:
    if value is None:
        return None
    if isinstance(value, str):
        return [{"value": value, "primary": True}]
    out = []
    for e in value:
        if isinstance(e, dict) and e.get("value"):
            item = {"value": e["value"], "primary": bool(e.get("primary"))}
            if e.get("type"):
                item["type"] = e["type"]
            out.append(item)
        elif isinstance(e, str):
            out.append({"value": e, "primary": not out})
    return out or None


def _match_role(name: str | None) -> str | None:
    """Case-insensitively resolve a group name to a fixed role, by role id or by its display label."""
    if not name:
        return None
    n = name.strip().lower()
    for role in _roles.ROLES:
        if n == role.lower() or n == _roles.ROLE_LABEL.get(role, "").lower():
            return role
    return None


def _apply_filter(rows: list[tuple[str, dict]], expr: str | None) -> list[tuple[str, dict]]:
    """Support the simple ``attr eq "value"`` filters SCIM clients use for reconciliation:
    ``userName``, ``emails.value``, ``externalId`` and ``active``."""
    if not expr:
        return rows
    m = re.match(r'\s*([\w.]+)\s+eq\s+"?([^"]*)"?\s*$', expr)
    if not m:
        raise ScimError(400, f"unsupported filter {expr!r}", "invalidFilter")
    attr, val = m.group(1).lower(), m.group(2)

    def match(u: str, r: dict) -> bool:
        sc = r.get("scim") or {}
        if attr == "username":
            return u.lower() == val.lower()
        if attr == "active":
            return _is_active(r) == (val.lower() == "true")
        if attr in ("emails.value", "emails"):
            return any((e.get("value", "").lower() == val.lower()) for e in (sc.get("emails") or []))
        if attr == "externalid":
            return (sc.get("externalId") or "").lower() == val.lower()
        raise ScimError(400, f"unsupported filter attribute {attr!r}", "invalidFilter")

    return [(u, r) for (u, r) in rows if match(u, r)]


class Provisioning:
    """SCIM operations over the console's account store + roles + audit chain.

    ``audit`` is the console's :class:`ConsoleAuditLog` (or anything with the same ``append`` signature);
    every mutating operation records an entry, so provisioning is compliance evidence."""

    def __init__(self, audit, *, base_path: str = "/scim/v2") -> None:
        self._audit = audit
        self._base = base_path

    # ── audit ────────────────────────────────────────────────────────────────
    def _log(self, action: str, username: str, role: str = "", detail: str = "") -> None:
        # Provisioning MUST be evidenced: if the signed chain cannot record it, the operation fails.
        self._audit.append(action=action, principal=f"scim:{username}", role=role, detail=detail)

    # ── mapping helpers ──────────────────────────────────────────────────────
    def _find_by_id(self, users: dict, sid: str) -> tuple[str | None, dict | None]:
        for uname, rec in users.items():
            if scim_id(uname) == sid:
                return uname, rec
        return None, None

    def _etag(self, rec: dict) -> str:
        raw = repr(sorted((rec.get("scim") or {}).items())) + str(rec.get("role", "")) + str(_is_active(rec))
        return 'W/"' + hashlib.sha256(raw.encode()).hexdigest()[:16] + '"'

    def _to_user_resource(self, username: str, rec: dict) -> dict:
        sc = rec.get("scim") or {}
        role = rec.get("role", DEFAULT_ROLE)
        sid = scim_id(username)
        res = {
            "schemas": [USER_SCHEMA],
            "id": sid,
            "userName": username,
            "active": _is_active(rec),
            "groups": [{"value": role, "display": _roles.ROLE_LABEL.get(role, role),
                        "$ref": f"{self._base}/Groups/{role}"}],
            "meta": {"resourceType": "User", "location": f"{self._base}/Users/{sid}",
                     "created": sc.get("created"), "lastModified": sc.get("modified"),
                     "version": self._etag(rec)},
        }
        if sc.get("externalId"):
            res["externalId"] = sc["externalId"]
        if sc.get("displayName"):
            res["displayName"] = sc["displayName"]
        if sc.get("name"):
            res["name"] = sc["name"]
        if sc.get("emails"):
            res["emails"] = sc["emails"]
        return res

    def _group_resource(self, role: str, users: dict) -> dict:
        members = [{"value": scim_id(u), "display": u, "$ref": f"{self._base}/Users/{scim_id(u)}"}
                   for u, r in sorted(users.items()) if r.get("role", DEFAULT_ROLE) == role]
        return {"schemas": [GROUP_SCHEMA], "id": role,
                "displayName": _roles.ROLE_LABEL.get(role, role), "members": members,
                "meta": {"resourceType": "Group", "location": f"{self._base}/Groups/{role}"}}

    # ── guardrails ───────────────────────────────────────────────────────────
    def _guard_last_admin(self, users: dict, username: str, *, new_role: str, active: bool) -> None:
        rec = users.get(username) or {}
        was_admin = rec.get("role") == _roles.ADMIN and _is_active(rec)
        if not was_admin:
            return
        if new_role == _roles.ADMIN and active:
            return  # still an active admin
        active_admins = sum(1 for r in users.values() if r.get("role") == _roles.ADMIN and _is_active(r))
        if active_admins <= 1:
            raise ScimError(409, "cannot deactivate or demote the last administrator", "mutability")

    # ── Users ────────────────────────────────────────────────────────────────
    def list_users(self, *, filter: str | None = None, start_index: int = 1,
                   count: int | None = None) -> dict:
        users = _auth.load_users()
        rows = _apply_filter([(u, r) for u, r in sorted(users.items())], filter)
        total = len(rows)
        start = max(1, start_index)
        page = rows[start - 1:(start - 1 + count)] if count is not None else rows[start - 1:]
        resources = [self._to_user_resource(u, r) for u, r in page]
        return {"schemas": [LIST_SCHEMA], "totalResults": total, "startIndex": start,
                "itemsPerPage": len(resources), "Resources": resources}

    def get_user(self, sid: str) -> dict:
        users = _auth.load_users()
        uname, rec = self._find_by_id(users, sid)
        if rec is None:
            raise ScimError(404, f"user {sid!r} not found")
        return self._to_user_resource(uname, rec)

    def create_user(self, resource: dict) -> dict:
        username = (resource.get("userName") or "").strip()
        if not username:
            raise ScimError(400, "userName is required", "invalidValue")
        users = _auth.load_users()
        if username in users:
            raise ScimError(409, f"userName {username!r} already exists", "uniqueness")
        active = _truthy_active(resource.get("active", True))
        sc = {"externalId": resource.get("externalId"), "displayName": resource.get("displayName"),
              "name": resource.get("name"), "emails": _norm_emails(resource.get("emails")),
              "source": "scim", "created": _now(), "modified": _now()}
        rec = {"role": DEFAULT_ROLE, "active": active, "scim": sc}
        users[username] = rec
        _auth.save_users(users)
        self._log("scim_user_create", username, role=DEFAULT_ROLE,
                  detail=f"active={active} externalId={sc.get('externalId')}")
        return self._to_user_resource(username, rec)

    def _apply_user_fields(self, users: dict, uname: str, rec: dict, fields: dict) -> list[str]:
        """Apply a set of {attribute: value} updates to one account. ``active`` is guarded + audited
        here (it is a lifecycle event); other attributes are collected for a single update audit entry."""
        changed: list[str] = []
        for f, v in fields.items():
            key = f.lower()
            if key == "active":
                want = _truthy_active(v)
                if _is_active(rec) != want:
                    if not want:
                        self._guard_last_admin(users, uname, new_role=rec.get("role", DEFAULT_ROLE),
                                               active=False)
                    rec["active"] = want
                    self._log("scim_user_reactivate" if want else "scim_user_deactivate", uname,
                              role=rec.get("role", ""), detail=f"active={want}")
                changed.append("active")
            elif key == "displayname":
                rec.setdefault("scim", {})["displayName"] = v
                changed.append("displayName")
            elif key == "externalid":
                rec.setdefault("scim", {})["externalId"] = v
                changed.append("externalId")
            elif key == "name":
                rec.setdefault("scim", {})["name"] = v
                changed.append("name")
            elif key in ("emails", "emails.value"):
                rec.setdefault("scim", {})["emails"] = _norm_emails(v)
                changed.append("emails")
            # Unknown attributes are ignored (SCIM servers are tolerant of extra attributes).
        return changed

    def replace_user(self, sid: str, resource: dict) -> dict:
        """PUT: replace the mutable attributes of an account (active, displayName, name, externalId,
        emails). Role is governed by group membership, not the User resource, so it is left unchanged."""
        users = _auth.load_users()
        uname, rec = self._find_by_id(users, sid)
        if rec is None:
            raise ScimError(404, f"user {sid!r} not found")
        fields = {"active": resource.get("active", _is_active(rec)),
                  "displayName": resource.get("displayName"), "name": resource.get("name"),
                  "externalId": resource.get("externalId"), "emails": resource.get("emails")}
        changed = self._apply_user_fields(users, uname, rec, fields)
        rec.setdefault("scim", {})["modified"] = _now()
        _auth.save_users(users)
        if any(c != "active" for c in changed):
            self._log("scim_user_update", uname, role=rec.get("role", ""),
                      detail="replaced " + ",".join(sorted({c for c in changed if c != "active"})))
        return self._to_user_resource(uname, rec)

    def patch_user(self, sid: str, operations: list) -> dict:
        """PATCH (RFC 7644 section 3.5.2): apply add/replace/remove operations. Supports both the
        pathed form ``{op, path, value}`` and the pathless replace ``{op:'replace', value:{...}}`` that
        Okta / Azure AD use for deactivation."""
        users = _auth.load_users()
        uname, rec = self._find_by_id(users, sid)
        if rec is None:
            raise ScimError(404, f"user {sid!r} not found")
        collected: list[str] = []
        for op in operations or []:
            action = (op.get("op") or "").lower()
            path = op.get("path") or ""
            value = op.get("value")
            if action not in ("add", "replace", "remove"):
                raise ScimError(400, f"unsupported PATCH op {action!r}", "invalidSyntax")
            if isinstance(value, dict) and not path:
                fields = value
            elif path:
                fields = {path: (None if action == "remove" else value)}
            else:
                continue
            collected += self._apply_user_fields(users, uname, rec, fields)
        rec.setdefault("scim", {})["modified"] = _now()
        _auth.save_users(users)
        non_active = sorted({c for c in collected if c != "active"})
        if non_active:
            self._log("scim_user_update", uname, role=rec.get("role", ""),
                      detail="updated " + ",".join(non_active))
        return self._to_user_resource(uname, rec)

    def deactivate_user(self, sid: str) -> str:
        """DELETE: soft-deactivate (never a hard delete). Returns the affected userName."""
        users = _auth.load_users()
        uname, rec = self._find_by_id(users, sid)
        if rec is None:
            raise ScimError(404, f"user {sid!r} not found")
        if _is_active(rec):
            self._guard_last_admin(users, uname, new_role=rec.get("role", DEFAULT_ROLE), active=False)
            rec["active"] = False
            rec.setdefault("scim", {})["modified"] = _now()
            _auth.save_users(users)
            self._log("scim_user_deactivate", uname, role=rec.get("role", ""),
                      detail="active=false (soft deprovision via DELETE)")
        return uname

    # ── Groups (fixed RBAC roles) ────────────────────────────────────────────
    def list_groups(self) -> dict:
        users = _auth.load_users()
        resources = [self._group_resource(role, users) for role in _roles.ROLES]
        return {"schemas": [LIST_SCHEMA], "totalResults": len(resources), "startIndex": 1,
                "itemsPerPage": len(resources), "Resources": resources}

    def get_group(self, gid: str) -> dict:
        role = gid if gid in _roles.ROLES else _match_role(gid)
        if role is None:
            raise ScimError(404, f"group {gid!r} not found")
        return self._group_resource(role, _auth.load_users())

    def create_group(self, resource: dict) -> dict:
        """The four role groups are fixed. Accept a group that names an existing role (idempotent —
        return it); reject anything else, since a new group would mean a new role."""
        role = _match_role(resource.get("displayName") or resource.get("id"))
        if role is None:
            raise ScimError(400, "groups map 1:1 onto the four fixed RBAC roles "
                            "(admin, compliance_officer, auditor, viewer); new groups cannot be created",
                            "invalidValue")
        return self._group_resource(role, _auth.load_users())

    def delete_group(self, gid: str) -> None:
        raise ScimError(400, "the four RBAC role groups are fixed and cannot be deleted; "
                        "manage membership with PATCH", "mutability")

    def _member_refs(self, value, path: str) -> list[str]:
        refs: list[str] = []
        if isinstance(value, list):
            for m in value:
                if isinstance(m, dict) and m.get("value"):
                    refs.append(m["value"])
                elif isinstance(m, str):
                    refs.append(m)
        elif isinstance(value, dict) and value.get("value"):
            refs.append(value["value"])
        m = re.search(r'members\[\s*value\s+eq\s+"([^"]+)"', path or "", re.I)
        if m:
            refs.append(m.group(1))
        return refs

    def _username_for_ref(self, users: dict, ref: str) -> str | None:
        uname, _ = self._find_by_id(users, ref)
        if uname:
            return uname
        return ref if ref in users else None  # tolerate clients that send userName as member.value

    def _set_role(self, uname: str, role: str) -> None:
        users = _auth.load_users()
        if uname not in users:
            raise ScimError(404, f"user {uname!r} not found")
        if role not in _roles.ROLES:
            raise ScimError(400, f"unknown role {role!r}", "invalidValue")
        cur = users[uname].get("role", DEFAULT_ROLE)
        if cur == role:
            return
        self._guard_last_admin(users, uname, new_role=role, active=_is_active(users[uname]))
        users[uname]["role"] = role
        _auth.save_users(users)
        self._log("scim_group_add_member", uname, role=role, detail=f"role {cur} -> {role}")

    def _remove_role(self, uname: str, role: str) -> None:
        users = _auth.load_users()
        rec = users.get(uname)
        if rec is None or rec.get("role", DEFAULT_ROLE) != role:
            return  # not a member of this group; nothing to do
        self._guard_last_admin(users, uname, new_role=DEFAULT_ROLE, active=_is_active(rec))
        rec["role"] = DEFAULT_ROLE
        _auth.save_users(users)
        self._log("scim_group_remove_member", uname, role=DEFAULT_ROLE,
                  detail=f"removed from group {role}; role -> {DEFAULT_ROLE}")

    def patch_group(self, gid: str, operations: list) -> dict:
        role = gid if gid in _roles.ROLES else _match_role(gid)
        if role is None:
            raise ScimError(404, f"group {gid!r} not found")
        for op in operations or []:
            action = (op.get("op") or "").lower()
            path = op.get("path") or ""
            value = op.get("value")
            users = _auth.load_users()
            refs = self._member_refs(value, path)
            usernames = [u for u in (self._username_for_ref(users, r) for r in refs) if u]
            if action == "add":
                for uname in usernames:
                    self._set_role(uname, role)
            elif action == "remove":
                for uname in usernames:
                    self._remove_role(uname, role)
            elif action == "replace":
                # replace the whole membership: listed users get this role; others currently in it drop
                # to the baseline. (A pathless replace of the members attribute.)
                target = set(usernames)
                for uname in list(users):
                    cur = users[uname].get("role", DEFAULT_ROLE)
                    if uname in target and cur != role:
                        self._set_role(uname, role)
                    elif uname not in target and cur == role:
                        self._remove_role(uname, role)
            else:
                raise ScimError(400, f"unsupported group PATCH op {action!r}", "invalidSyntax")
        return self._group_resource(role, _auth.load_users())
