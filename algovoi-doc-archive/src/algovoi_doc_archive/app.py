"""FastAPI app factory for a standalone Verifiable Archive service."""
from __future__ import annotations

import base64
from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, Response

from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.models import (
    NotarizeRequest,
    NotarizeResponse,
    VerifyChainResult,
    VerifyEntryRequest,
    VerifyEntryResult,
)
from algovoi_doc_archive.verifier import verify_entry


def create_app(
    archive: Archive,
    *,
    public_key: bytes,
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
    title: str = "Verifiable Archive",
) -> FastAPI:
    """Build a ready-to-run Verifiable Archive app.

    ``notarize`` and ``retrieve`` are guarded by ``auth_dependency`` (open if none supplied — set one
    before deploying). ``verify``, ``verify-chain``, ``entry`` and the portal are public.
    """
    app = FastAPI(title=title, version="0.1.0")

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health() -> dict:
        h = await archive.head()
        return {"status": "ok", "app": "doc-archive", "kid": archive.kid, "entries": h["seq_count"]}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        return {"issuer": archive.issuer_did, "keys": [{
            "kid": archive.kid, "alg": "Falcon-1024", "use": "sig",
            "public_key_b64": signing.public_key_b64(public_key)}]}

    @app.post("/v1/archive/notarize", response_model=NotarizeResponse)
    async def notarize(req: NotarizeRequest, _=Depends(auth_dependency)) -> NotarizeResponse:
        data = None
        if req.data_b64 is not None:
            try:
                data = base64.b64decode(req.data_b64)
            except Exception:  # noqa: BLE001
                raise HTTPException(status_code=400, detail="data_b64 is not valid base64")
        if data is None and not req.doc_hash:
            raise HTTPException(status_code=400, detail="provide data_b64 or doc_hash")
        try:
            out = await archive.notarize(data=data, doc_hash=req.doc_hash, title=req.title,
                                         content_type=req.content_type, metadata=req.metadata)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return NotarizeResponse(**out)

    @app.post("/v1/archive/verify", response_model=VerifyEntryResult)
    async def verify(req: VerifyEntryRequest) -> VerifyEntryResult:
        return verify_entry(req.receipt, public_key)

    @app.get("/v1/archive/verify-chain", response_model=VerifyChainResult)
    async def verify_chain() -> VerifyChainResult:
        return await archive.verify_chain()

    @app.get("/v1/archive/entry/{seq}")
    async def entry(seq: int) -> dict:
        receipt = await archive.get_entry(seq)
        if receipt is None:
            raise HTTPException(status_code=404, detail="entry not found")
        payload, _, _ = signing.open_envelope(receipt)
        return {"receipt": receipt, "payload": payload}

    @app.get("/v1/archive/retrieve/{doc_hash}")
    async def retrieve(doc_hash: str, _=Depends(auth_dependency)) -> Response:
        try:
            data = await archive.retrieve(doc_hash=doc_hash)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e))
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=409, detail=str(e))
        return Response(content=data, media_type="application/octet-stream",
                        headers={"X-Doc-Hash": doc_hash if ":" in doc_hash else f"sha256:{doc_hash}"})

    @app.get("/archive/verify", response_class=HTMLResponse)
    async def portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Verifiable Archive — Verify</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Verifiable Archive — Verify an entry</h1>
<p class="muted">Paste an archive receipt to check its post-quantum signature and that the document
hash it certifies is intact. The chain's integrity is checked at <code>/v1/archive/verify-chain</code>.</p>
<textarea id="c" placeholder="base64url archive receipt…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste a receipt first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/archive/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({receipt:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
