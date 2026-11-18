"""FastAPI app factory for a standalone Compliance Gate service."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI
from fastapi.responses import HTMLResponse

from algovoi_compliance_gate import signing
from algovoi_compliance_gate.gate import ComplianceGate
from algovoi_compliance_gate.models import (
    CertifiedScreenResult,
    ScreenRequest,
    VerifyRequest,
    VerifyResult,
)
from algovoi_compliance_gate.verifier import verify_compliance_receipt


def create_app(
    gate: ComplianceGate,
    *,
    public_key: bytes,
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
    title: str = "Compliance Gate",
) -> FastAPI:
    """Build the Compliance Gate app. ``screen`` is guarded by ``auth_dependency`` (it takes a payer
    address — handle over TLS, gated); ``verify`` is public (the receipt carries no PII)."""
    app = FastAPI(title=title, version="0.1.0")

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "app": "compliance-gate", "kid": gate.kid, "gate_did": gate.gate_did}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        return {"issuer": gate.gate_did, "keys": [{
            "kid": gate.kid, "alg": "Falcon-1024", "use": "sig",
            "public_key_b64": signing.public_key_b64(public_key)}]}

    @app.post("/v1/compliance/screen", response_model=CertifiedScreenResult, dependencies=[Depends(auth_dependency)])
    async def screen(req: ScreenRequest) -> CertifiedScreenResult:
        out = await gate.screen_and_certify(network=req.network, address=req.address,
                                            amount_microusd=req.amount_microusd, context=req.context)
        return CertifiedScreenResult(**out)

    @app.post("/v1/compliance/verify", response_model=VerifyResult)
    async def verify(req: VerifyRequest) -> VerifyResult:
        return verify_compliance_receipt(req.receipt_envelope, public_key)

    @app.get("/compliance/verify", response_class=HTMLResponse)
    async def portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Compliance Gate — Verify a receipt</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Compliance Gate — verify a receipt</h1>
<p class="muted">Paste a signed compliance receipt to check the gate's post-quantum signature and read
back the screen verdict. The receipt contains no PII — only a content-addressed payer reference.</p>
<textarea id="c" placeholder="base64url receipt envelope…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste a receipt first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/compliance/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({receipt_envelope:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
