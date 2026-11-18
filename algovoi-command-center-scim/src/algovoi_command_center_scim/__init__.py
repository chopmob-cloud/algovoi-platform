"""SCIM 2.0 (RFC 7643/7644) auto-provisioning for the AlgoVoi Compliance Command Center.

The console discovers this add-on through the ``algovoi_command_center.provisioning`` entry point:
``pip install algovoi-command-center-scim`` and the console mounts a ``/scim/v2`` endpoint (behind its
own bearer token) with no configuration. An IdP (Okta, Azure AD, OneLogin) then provisions and
deprovisions console accounts, and maps its groups onto the four fixed RBAC roles.

It reuses the console's existing identity machinery rather than inventing a parallel model:
  * accounts live in the same local-account store the SSO providers read;
  * SCIM Groups ARE the fixed RBAC roles;
  * every provisioning change is written to the same Falcon-signed audit chain as every other action.

Commercial add-on: constructing :class:`ScimProvisioner` enforces a valid AlgoVoi suite licence,
fail-closed — without one the console simply does not mount the SCIM endpoint (it stays unreachable).
"""
from __future__ import annotations

__version__ = "0.1.1"


class ScimProvisioner:
    """The object the console discovers and instantiates to mount SCIM.

    Construction enforces the licence gate (fail-closed), identical to the ``algovoi-command-center-totp``
    factor add-on. The console then calls :meth:`build_router` with its signed audit log and the
    SCIM bearer token, and mounts the returned router.
    """

    name = "scim"
    label = "SCIM 2.0 provisioning"

    def __init__(self) -> None:
        from algovoi_command_center_scim import licensing
        licensing.require_license()  # fail-closed — no valid suite licence, no SCIM endpoint

    def build_router(self, *, audit, bearer_token: str):
        """Return the FastAPI ``/scim/v2`` router, wired to the console's audit chain and bearer token."""
        from algovoi_command_center_scim.router import build_router
        return build_router(audit=audit, bearer_token=bearer_token)
