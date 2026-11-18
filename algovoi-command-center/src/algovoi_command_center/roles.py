"""Role-based access control for the Compliance Command Center.

Fixed roles for v1 (custom roles are a later iteration). Mirrors the Records Vault least-privilege
model: every console capability is a named permission, and a role is a set of permissions.
"""
from __future__ import annotations

ADMIN = "admin"
COMPLIANCE_OFFICER = "compliance_officer"
AUDITOR = "auditor"
VIEWER = "viewer"

ROLES = (ADMIN, COMPLIANCE_OFFICER, AUDITOR, VIEWER)

# permission -> roles that hold it
_PERMS: dict[str, set[str]] = {
    "view_dashboard": {ADMIN, COMPLIANCE_OFFICER, AUDITOR, VIEWER},
    "view_evidence": {ADMIN, COMPLIANCE_OFFICER, AUDITOR},
    "export_pack": {ADMIN, COMPLIANCE_OFFICER, AUDITOR},
    "view_audit": {ADMIN, COMPLIANCE_OFFICER},
    "manage_users": {ADMIN},
    "manage_containers": {ADMIN, COMPLIANCE_OFFICER},
    "manage_updates": {ADMIN},
    # Records Vault: notarize / retrieve / dispose records, and place / release legal holds.
    "manage_records": {ADMIN, COMPLIANCE_OFFICER},
    "manage_holds": {ADMIN, COMPLIANCE_OFFICER},
}

ROLE_LABEL = {
    ADMIN: "Administrator",
    COMPLIANCE_OFFICER: "Compliance officer",
    AUDITOR: "Auditor",
    VIEWER: "Viewer",
}


def can(role: str, permission: str) -> bool:
    """Does ``role`` hold ``permission``?"""
    return role in _PERMS.get(permission, set())


def permissions_for(role: str) -> list[str]:
    return sorted(p for p, roles in _PERMS.items() if role in roles)
