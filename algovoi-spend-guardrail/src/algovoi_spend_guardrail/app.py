"""FastAPI app factory for a standalone Spend Guardrail service."""
from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

from pydantic import BaseModel

from algovoi_spend_guardrail.guardrail import SpendGuardrail
from algovoi_spend_guardrail.models import (
    AuthorizeRequest,
    ChainVerifyResult,
    DecisionResult,
    VerifyDecisionRequest,
    VerifyDecisionResult,
)
from algovoi_spend_guardrail.verifier import verify_decision, verify_decision_chain


class VerifyChainRequest(BaseModel):
    envelopes: list[str]


def create_app(
    guardrail: SpendGuardrail,
    *,
    decision_public_key: bytes,
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
    title: str = "Spend Guardrail",
) -> FastAPI:
    """Build the Spend Guardrail app. ``authorize`` is guarded by ``auth_dependency`` (it is an
    authority decision that consumes the mandate ledger); ``verify-decision`` is public."""
    app = FastAPI(title=title, version="0.2.0")

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "app": "spend-guardrail", "kid": guardrail.kid, "guardrail_did": guardrail.did}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        return {"issuer": guardrail.did, "keys": [{
            "kid": guardrail.kid, "alg": "Falcon-1024", "use": "sig",
            "public_key_b64": base64.b64encode(decision_public_key).decode("ascii")}]}

    @app.post("/v1/guardrail/authorize", response_model=DecisionResult, dependencies=[Depends(auth_dependency)])
    async def authorize(req: AuthorizeRequest) -> DecisionResult:
        return await guardrail.authorize(
            passport_credential=req.passport_credential, mandate=req.mandate, charge_id=req.charge_id,
            amount=req.amount, payee=req.payee, asset=req.asset, at=req.at,
            expected_agent_did=req.expected_agent_did)

    @app.post("/v1/guardrail/verify-decision", response_model=VerifyDecisionResult)
    async def verify(req: VerifyDecisionRequest) -> VerifyDecisionResult:
        return verify_decision(req.decision_receipt, decision_public_key)

    @app.post("/v1/guardrail/verify-chain", response_model=ChainVerifyResult)
    async def verify_chain(req: VerifyChainRequest) -> ChainVerifyResult:
        return verify_decision_chain(req.envelopes, decision_public_key)

    @app.get("/v1/guardrail/decisions/export")
    async def export_chain() -> dict:
        """Return the signed decision chain (the CCC-ingestable evidence pack, inline)."""
        return {"type": "spend_decision", "kid": guardrail.kid, "count": guardrail.ledger.seq,
                "envelopes": list(guardrail.ledger.envelopes)}

    @app.get("/guardrail/verify", response_class=HTMLResponse)
    async def portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Spend Guardrail — Verify a decision</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Spend Guardrail — verify a decision receipt</h1>
<p class="muted">Paste a signed ALLOW/DENY decision receipt to check the guardrail's post-quantum
signature and read back what was decided (and why).</p>
<textarea id="c" placeholder="base64url decision receipt…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste a decision receipt first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/guardrail/verify-decision',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision_receipt:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
