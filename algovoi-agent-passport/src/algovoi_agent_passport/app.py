"""FastAPI app factory for a standalone Agent Passport service."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from algovoi_agent_passport.issuer import PassportIssuer
from algovoi_agent_passport.models import (
    IssueRequest,
    IssueResponse,
    RevokeRequest,
    VerifyRequest,
    VerifyResult,
)
from algovoi_agent_passport.verifier import verify_passport


def create_app(
    issuer: PassportIssuer,
    *,
    public_key: bytes,
    auth_dependency: Callable | None = None,
    title: str = "Agent Passport",
) -> FastAPI:
    """Build a ready-to-run Agent Passport FastAPI app.

    ``issue`` and ``revoke`` are guarded by ``auth_dependency`` (open if none is supplied —
    set one before deploying). ``verify``, ``status`` and the CRL are public.
    """
    app = FastAPI(title=title)

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health():
        return {"status": "ok", "app": "agent-passport", "kid": issuer.kid}

    @app.post("/v1/passport/issue", response_model=IssueResponse)
    async def issue(req: IssueRequest, _=Depends(auth_dependency)):
        return IssueResponse(**await issuer.issue(
            agent_did=req.agent_did, scopes=req.scopes, spend_limit_microusd=req.spend_limit_microusd,
            spend_window=req.spend_window, ttl_secs=req.ttl_secs))

    @app.post("/v1/passport/verify", response_model=VerifyResult)
    async def verify(req: VerifyRequest):
        return await verify_passport(req.credential, public_key, store=issuer.store,
                                     required_scope=req.required_scope, expected_agent_did=req.expected_agent_did)

    @app.get("/v1/passport/status/{kid}/{passport_id}")
    async def status(kid: str, passport_id: str):
        return {"status": await issuer.status(kid=kid, passport_id=passport_id)}

    @app.post("/v1/passport/revoke")
    async def revoke(req: RevokeRequest, _=Depends(auth_dependency)):
        if not await issuer.revoke(passport_id=req.passport_id, reason=req.reason):
            raise HTTPException(status_code=404, detail="passport not found or already revoked")
        return {"passport_id": req.passport_id, "status": "revoked"}

    @app.get("/passport/crl/{kid}.json")
    async def crl(kid: str):
        revoked = await issuer.list_revoked(kid=kid)
        return JSONResponse(
            {"kid": kid, "revoked": revoked,
             "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            headers={"Cache-Control": "public, max-age=60"},
        )

    @app.get("/passport/verify", response_class=HTMLResponse)
    async def portal():
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Agent Passport — Verify</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Agent Passport — Verify</h1>
<p class="muted">Paste a passport credential to check its signature, expiry and revocation status.</p>
<textarea id="c" placeholder="base64url credential…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste a credential first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/passport/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credential:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
