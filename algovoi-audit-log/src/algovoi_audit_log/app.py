"""FastAPI app factory for a standalone Verifiable Audit Log service."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from algovoi_audit_log import signing
from algovoi_audit_log.log import AuditLog
from algovoi_audit_log.models import (
    AppendRequest,
    AppendResponse,
    VerifyChainResult,
    VerifyEntryRequest,
    VerifyEntryResult,
)
from algovoi_audit_log.verifier import verify_entry


def create_app(
    audit_log: AuditLog,
    *,
    public_key: bytes,
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
    title: str = "Verifiable Audit Log",
) -> FastAPI:
    """Build the Verifiable Audit Log app. ``append`` is guarded by ``auth_dependency`` (it writes the
    chain); ``verify``, ``verify-chain`` and ``entry`` are public."""
    app = FastAPI(title=title, version="0.1.0")

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health() -> dict:
        h = await audit_log.head()
        return {"status": "ok", "app": "audit-log", "kid": audit_log.kid, "entries": h["seq_count"]}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        return {"issuer": audit_log.issuer_did, "keys": [{
            "kid": audit_log.kid, "alg": "Falcon-1024", "use": "sig",
            "public_key_b64": signing.public_key_b64(public_key)}]}

    @app.post("/v1/audit-log/append", response_model=AppendResponse, dependencies=[Depends(auth_dependency)])
    async def append(req: AppendRequest) -> AppendResponse:
        return AppendResponse(**await audit_log.append(event_type=req.event_type, event=req.event, actor=req.actor))

    @app.post("/v1/audit-log/verify", response_model=VerifyEntryResult)
    async def verify(req: VerifyEntryRequest) -> VerifyEntryResult:
        return verify_entry(req.receipt, public_key)

    @app.get("/v1/audit-log/verify-chain", response_model=VerifyChainResult)
    async def verify_chain() -> VerifyChainResult:
        return await audit_log.verify_chain()

    @app.get("/v1/audit-log/entry/{seq}")
    async def entry(seq: int) -> dict:
        receipt = await audit_log.get_entry(seq)
        if receipt is None:
            raise HTTPException(status_code=404, detail="entry not found")
        payload, _, _ = signing.open_envelope(receipt)
        return {"receipt": receipt, "payload": payload}

    @app.get("/audit-log/verify", response_class=HTMLResponse)
    async def portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Verifiable Audit Log — Verify</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Verifiable Audit Log — verify an entry</h1>
<p class="muted">Paste a signed log entry to check its post-quantum signature and event-hash. The whole
chain's integrity is checked at <code>/v1/audit-log/verify-chain</code>.</p>
<textarea id="c" placeholder="base64url entry receipt…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste an entry first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/audit-log/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({receipt:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
