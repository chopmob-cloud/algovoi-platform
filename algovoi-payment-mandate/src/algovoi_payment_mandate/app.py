"""FastAPI app factory for a standalone Payment Mandate service."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from algovoi_payment_mandate import signing
from algovoi_payment_mandate.issuer import MandateIssuer
from algovoi_payment_mandate.models import (
    ChargeAuthorizationRequest,
    ChargeAuthorizationResult,
    IssueRequest,
    IssueResponse,
    RevokeRequest,
    VerifyRequest,
    VerifyResult,
)
from algovoi_payment_mandate.verifier import verify_mandate


def create_app(
    issuer: MandateIssuer,
    *,
    public_key: bytes,
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
    title: str = "Payment Mandate",
) -> FastAPI:
    """Build a ready-to-run Payment Mandate FastAPI app.

    ``issue``, ``revoke`` and ``authorize-charge`` are guarded by ``auth_dependency`` (open if none
    is supplied — set one before deploying). ``verify``, ``status``, the CRL and the portal are public.
    """
    app = FastAPI(title=title, version="0.1.0")

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "app": "payment-mandate", "kid": issuer.kid, "issuer_did": issuer.issuer_did}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        return {"issuer": issuer.issuer_did, "keys": [{
            "kid": issuer.kid, "alg": "Falcon-1024", "use": "sig",
            "public_key_b64": signing.public_key_b64(public_key)}]}

    @app.post("/v1/mandates/issue", response_model=IssueResponse)
    async def issue(req: IssueRequest, _=Depends(auth_dependency)) -> IssueResponse:
        return IssueResponse(**await issuer.issue(
            payer=req.payer, payee=req.payee, asset=req.asset, chain=req.chain,
            max_amount=req.max_amount, period=req.period, max_per_charge=req.max_per_charge,
            scope=req.scope, ttl_secs=req.ttl_secs))

    @app.post("/v1/mandates/verify", response_model=VerifyResult)
    async def verify(req: VerifyRequest) -> VerifyResult:
        return await verify_mandate(req.mandate, public_key, store=issuer.store,
                                    required_scope=req.required_scope, expected_payee=req.expected_payee)

    @app.post("/v1/mandates/authorize-charge", response_model=ChargeAuthorizationResult)
    async def authorize_charge(req: ChargeAuthorizationRequest, _=Depends(auth_dependency)) -> ChargeAuthorizationResult:
        return await issuer.authorize_charge(
            mandate=req.mandate, charge_id=req.charge_id, amount=req.amount,
            payee=req.payee, asset=req.asset, at=req.at)

    @app.get("/v1/mandates/status/{kid}/{mandate_id}")
    async def status(kid: str, mandate_id: str) -> dict:
        return {"status": await issuer.status(kid=kid, mandate_id=mandate_id)}

    @app.post("/v1/mandates/revoke")
    async def revoke(req: RevokeRequest, _=Depends(auth_dependency)) -> dict:
        if not await issuer.revoke(mandate_id=req.mandate_id, reason=req.reason):
            raise HTTPException(status_code=404, detail="mandate not found or already revoked")
        return {"mandate_id": req.mandate_id, "status": "revoked"}

    @app.get("/mandates/crl/{kid}.json")
    async def crl(kid: str) -> JSONResponse:
        revoked = await issuer.list_revoked(kid=kid)
        return JSONResponse(
            {"kid": kid, "revoked": revoked,
             "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
            headers={"Cache-Control": "public, max-age=60"})

    @app.get("/mandates/verify", response_class=HTMLResponse)
    async def portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Payment Mandate — Verify</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Payment Mandate — Verify</h1>
<p class="muted">Paste a mandate to check its post-quantum signature, terms (cap / period / payee), expiry and revocation.</p>
<textarea id="c" placeholder="base64url mandate…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste a mandate first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/mandates/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mandate:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
