"""FastAPI app factory for the Archive Auditor (reports, attestations, exports)."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse

from algovoi_doc_archive import signing

from algovoi_archive_auditor import exporters
from algovoi_archive_auditor.auditor import Auditor
from algovoi_archive_auditor.models import AttestRequest, EvidencePackRequest, RetentionPolicyIn
from algovoi_archive_auditor.retention import RetentionPolicy


def create_app(
    auditor: Auditor,
    *,
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
    title: str = "Archive Auditor",
) -> FastAPI:
    """Build the Archive Auditor app. ``attest`` and ``evidence-pack`` are guarded by
    ``auth_dependency`` (open if none supplied); reports, inventory, retention, metrics, and the
    SIEM feed are public read-only."""
    app = FastAPI(title=title, version="0.1.0")

    if auth_dependency is None:
        async def auth_dependency():  # type: ignore[no-redef]
            return None

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "app": "archive-auditor",
                "archive_kid": auditor.archive_kid, "auditor_kid": auditor.kid}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        keys = []
        if auditor.rpk is not None:
            keys.append({"kid": auditor.kid, "alg": "Falcon-1024", "use": "sig",
                         "public_key_b64": signing.public_key_b64(auditor.rpk)})
        return {"issuer": auditor.auditor_did, "keys": keys}

    @app.get("/v1/audit/report")
    async def report() -> dict:
        return await auditor.audit_report(sign=True)

    @app.get("/v1/audit/inventory")
    async def inventory() -> dict:
        return {"entries": await auditor.inventory()}

    @app.post("/v1/audit/retention")
    async def retention(req: RetentionPolicyIn) -> dict:
        policy = RetentionPolicy(default_days=req.default_days, by_content_type=req.by_content_type)
        return await auditor.retention_report(policy)

    @app.post("/v1/audit/attest")
    async def attest(req: AttestRequest, _=Depends(auth_dependency)) -> dict:
        return await auditor.attest(prev_attestation_hash=req.prev_attestation_hash, sign=True)

    @app.post("/v1/audit/evidence-pack")
    async def evidence_pack(req: EvidencePackRequest, _=Depends(auth_dependency)) -> dict:
        return await auditor.evidence_pack(seqs=req.seqs, sign=True)

    @app.post("/v1/audit/verify-report")
    async def verify_report(body: dict) -> dict:
        """Verify a signed report/attestation/manifest envelope against the auditor's public key."""
        if auditor.rpk is None:
            raise HTTPException(status_code=400, detail="auditor has no report public key configured")
        env = body.get("envelope")
        if not isinstance(env, str):
            raise HTTPException(status_code=400, detail="provide 'envelope' (base64url string)")
        try:
            payload, sig, kid = signing.open_envelope(env)
        except Exception:  # noqa: BLE001
            return {"verified": False, "error": "malformed envelope"}
        ok = signing.verify_payload(payload, sig, auditor.rpk)
        return {"verified": ok, "type": payload.get("type"), "kid": kid,
                "archive_kid": payload.get("archive_kid")}

    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics() -> str:
        return exporters.to_prometheus(**await auditor.metrics_inputs())

    @app.get("/v1/audit/events.jsonl", response_class=PlainTextResponse)
    async def events() -> str:
        return exporters.to_jsonl(await auditor.siem_events())

    @app.get("/audit/verify", response_class=HTMLResponse)
    async def portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML)

    return app


_PORTAL_HTML = """<!doctype html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Archive Auditor — Verify a report</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#e6edf3}
 textarea{width:100%;height:140px;background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:.6rem;font-family:ui-monospace,monospace}
 button{margin-top:.6rem;background:#238636;color:#fff;border:0;border-radius:8px;padding:.55rem 1.1rem;cursor:pointer}
 pre{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;white-space:pre-wrap;word-break:break-all;margin-top:1rem}
 .ok{color:#3fb950}.bad{color:#f85149}.muted{color:#8b949e}
</style></head>
<body>
<h1>Archive Auditor — Verify a signed report</h1>
<p class="muted">Paste a signed audit report, attestation, or evidence-pack manifest envelope to
check the auditor's post-quantum signature.</p>
<textarea id="c" placeholder="base64url envelope…"></textarea>
<button id="go">Verify</button>
<pre id="o" class="muted">Result will appear here.</pre>
<script>
document.getElementById('go').addEventListener('click', async function(){
  var o=document.getElementById('o'), c=document.getElementById('c').value.trim();
  if(!c){o.textContent='Paste an envelope first.';return;}
  o.textContent='Verifying…';o.className='muted';
  try{var r=await fetch('/v1/audit/verify-report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({envelope:c})});
    var j=await r.json();o.textContent=JSON.stringify(j,null,2);o.className=j.verified?'ok':'bad';}
  catch(e){o.textContent='Error: '+e;o.className='bad';}
});
</script>
</body></html>
"""
