"""FastAPI wiring for the SCIM 2.0 endpoint.

Mounted by the Compliance Command Center when this add-on is installed and licensed. Authentication is a
dedicated **bearer token**, entirely separate from the console's human-user session auth: an IdP (Okta,
Azure AD, OneLogin) presents ``Authorization: Bearer <scim-token>``. The token is supplied and rotated by
the console (env ``COMMAND_CENTER_SCIM_TOKEN`` or a 0600 file in the data dir), mirroring the console's
existing service-registration token.
"""
from __future__ import annotations

import secrets

# Imported at module level (not inside build_router) so the PEP 563 string annotations on the route
# handlers (``request: Request``) resolve against module globals when FastAPI reads their type hints.
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .scim import ERROR_SCHEMA, Provisioning, ScimError

_MEDIA = "application/scim+json"


def build_router(*, audit, bearer_token: str):
    """Build the ``/scim/v2`` APIRouter. ``audit`` is the console's signed audit log; ``bearer_token`` is
    the SCIM client credential the console resolved/rotated."""
    # Fail closed on a missing/blank/too-short credential. Without this, an empty token makes
    # ``secrets.compare_digest("", "")`` return True and authenticate every caller. The console
    # normally bootstraps a strong token, but a truncated/empty bootstrap file must not silently
    # open provisioning — refuse to mount instead (the caller treats a raise as "add-on unavailable").
    if not bearer_token or len(bearer_token.strip()) < 16:
        raise RuntimeError("SCIM bearer token unset or too short (need >=16 chars); refusing to mount /scim/v2")
    prov = Provisioning(audit)
    router = APIRouter(prefix="/scim/v2", tags=["scim"])

    def _err(status: int, detail: str, scim_type: str | None = None) -> JSONResponse:
        body = {"schemas": [ERROR_SCHEMA], "status": str(status), "detail": detail}
        if scim_type:
            body["scimType"] = scim_type
        return JSONResponse(body, status_code=status, media_type=_MEDIA)

    def _ok(body, status: int = 200) -> JSONResponse:
        return JSONResponse(body, status_code=status, media_type=_MEDIA)

    def _authed(request: "Request") -> bool:
        h = request.headers.get("authorization", "")
        if not bearer_token or not h.startswith("Bearer "):
            return False
        return secrets.compare_digest(h[7:].strip(), bearer_token)

    async def _json(request: "Request") -> dict:
        try:
            return await request.json()
        except Exception:  # noqa: BLE001 — a malformed body is just an empty resource
            return {}

    # ── Users ────────────────────────────────────────────────────────────────
    @router.get("/Users")
    async def list_users(request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        qp = request.query_params
        try:
            return _ok(prov.list_users(
                filter=qp.get("filter"),
                start_index=int(qp.get("startIndex", "1") or 1),
                count=int(qp["count"]) if qp.get("count") else None))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.post("/Users")
    async def create_user(request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            return _ok(prov.create_user(await _json(request)), 201)
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.get("/Users/{sid}")
    async def get_user(sid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            return _ok(prov.get_user(sid))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.put("/Users/{sid}")
    async def put_user(sid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            return _ok(prov.replace_user(sid, await _json(request)))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.patch("/Users/{sid}")
    async def patch_user(sid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        body = await _json(request)
        try:
            return _ok(prov.patch_user(sid, body.get("Operations") or body.get("operations") or []))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.delete("/Users/{sid}")
    async def delete_user(sid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            prov.deactivate_user(sid)
            return Response(status_code=204)
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    # ── Groups (fixed RBAC roles) ────────────────────────────────────────────
    @router.get("/Groups")
    async def list_groups(request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        return _ok(prov.list_groups())

    @router.post("/Groups")
    async def create_group(request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            return _ok(prov.create_group(await _json(request)))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.get("/Groups/{gid}")
    async def get_group(gid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            return _ok(prov.get_group(gid))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.patch("/Groups/{gid}")
    async def patch_group(gid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        body = await _json(request)
        try:
            return _ok(prov.patch_group(gid, body.get("Operations") or body.get("operations") or []))
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    @router.delete("/Groups/{gid}")
    async def delete_group(gid: str, request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        try:
            prov.delete_group(gid)
            return Response(status_code=204)
        except ScimError as e:
            return _err(e.status, e.detail, e.scim_type)

    # ── discovery (RFC 7643 section 5) — helps Okta / Azure AD probe capabilities ──
    @router.get("/ServiceProviderConfig")
    async def service_provider_config(request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        return _ok({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "https://docs.algovoi.co.uk/scim-provisioning",
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": True},
            "authenticationSchemes": [{
                "type": "oauthbearertoken", "name": "OAuth Bearer Token",
                "description": "Authentication via the SCIM bearer token issued by the Command Center.",
                "primary": True}],
            "meta": {"resourceType": "ServiceProviderConfig"},
        })

    @router.get("/ResourceTypes")
    async def resource_types(request: Request):
        if not _authed(request):
            return _err(401, "missing or invalid bearer token")
        types = [
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User",
             "name": "User", "endpoint": "/Users",
             "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
             "meta": {"resourceType": "ResourceType"}},
            {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group",
             "name": "Group", "endpoint": "/Groups",
             "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
             "meta": {"resourceType": "ResourceType"}},
        ]
        return _ok({"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                    "totalResults": len(types), "Resources": types})

    return router
