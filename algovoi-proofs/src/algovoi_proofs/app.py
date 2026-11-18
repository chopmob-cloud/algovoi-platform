"""FastAPI application factory for the Proofs service."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from algovoi_proofs import signing
from algovoi_proofs.auth import bearer_token_auth
from algovoi_proofs.issuer import ProofIssuer
from algovoi_proofs.models import IssueRequest, IssueResponse, VerifyRequest, VerifyResult
from algovoi_proofs.prover import ProverClient, ProverUnavailable
from algovoi_proofs.verifier import verify_proof

_PORTAL_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proofs — Verify</title>
<style>
body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#111}
h1{font-size:1.4rem} textarea{width:100%;height:150px;font-family:monospace;font-size:.8rem}
button{background:#111;color:#fff;border:0;padding:.6rem 1.1rem;border-radius:6px;cursor:pointer}
pre{background:#f5f5f5;padding:1rem;border-radius:6px;overflow:auto;white-space:pre-wrap}
.ok{color:#0a7d28;font-weight:600}.bad{color:#b00020;font-weight:600}.muted{color:#666;font-size:.85rem}
label{display:block;margin:.4rem 0 .2rem}
</style></head><body>
<h1>Proofs — verify a compliance proof</h1>
<p class="muted">Paste a proof envelope. Verification checks the issuer's post-quantum (Falcon-1024)
signature and structure. No PII is ever contained in a proof.</p>
<label for="env">Proof envelope (base64url)</label>
<textarea id="env" placeholder="eyJ..."></textarea>
<label><input type="checkbox" id="rp" checked> re-check the zero-knowledge range proof</label>
<p><button data-action="verify">Verify</button></p>
<pre id="out" class="muted">Result will appear here.</pre>
<script nonce="__NONCE__">
document.addEventListener('click',async e=>{
 if(e.target.getAttribute('data-action')!=='verify')return;
 const env=document.getElementById('env').value.trim();
 const out=document.getElementById('out');
 if(!env){out.textContent='Paste a proof envelope first.';return;}
 out.textContent='Verifying…';
 try{
  const r=await fetch('v1/proofs/verify',{method:'POST',headers:{'content-type':'application/json'},
   body:JSON.stringify({proof_envelope:env,verify_range_proof:document.getElementById('rp').checked})});
  const j=await r.json();
  const head=j.verified?'<span class="ok">VERIFIED</span>':'<span class="bad">NOT VERIFIED</span>';
  out.innerHTML=head+'\\n'+JSON.stringify(j,null,2);
 }catch(err){out.textContent='Error: '+err;}
});
</script></body></html>"""


def create_app(
    *,
    secret_key: bytes,
    public_key: bytes,
    prover_url: str,
    issuer_did: str = "did:web:issuer.example.com",
    api_token: str | None = None,
    prover_timeout: float = 8.0,
    title: str = "AlgoVoi Proofs",
    auth_dependency: Callable[..., Awaitable[None]] | None = None,
) -> FastAPI:
    """Build the Proofs FastAPI app.

    ``secret_key``/``public_key`` are the Falcon issuer keypair; ``prover_url`` points at the
    Bulletproofs range-proof service. ``issue`` requires the bearer token; ``verify`` is public.
    """
    prover = ProverClient(prover_url, timeout=prover_timeout)
    issuer = ProofIssuer(secret_key=secret_key, public_key=public_key, prover=prover, issuer_did=issuer_did)
    auth = auth_dependency or bearer_token_auth(api_token)

    app = FastAPI(title=title, version="0.1.0")

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "app": "proofs", "kid": issuer.kid, "issuer_did": issuer_did}

    @app.get("/.well-known/pqc-keys.json")
    async def pqc_keys() -> dict:
        return {
            "issuer": issuer_did,
            "keys": [{
                "kid": issuer.kid, "alg": "Falcon-1024", "use": "sig",
                "public_key_b64": signing.public_key_b64(public_key),
            }],
        }

    @app.post("/v1/proofs/issue", response_model=IssueResponse, dependencies=[Depends(auth)])
    async def issue(req: IssueRequest) -> IssueResponse:
        try:
            out = await issuer.issue(
                payment=req.payment.model_dump(), screen_result=req.screen_result,
                score_milliunits=req.score_milliunits, threshold_milliunits=req.threshold_milliunits,
                ttl_secs=req.ttl_secs, jurisdiction_flags=req.jurisdiction_flags)
        except ProverUnavailable as e:
            raise HTTPException(status_code=503, detail=f"range-proof service unavailable: {e}")
        return IssueResponse(**out)

    @app.post("/v1/proofs/verify", response_model=VerifyResult)
    async def verify(req: VerifyRequest) -> VerifyResult:
        return await verify_proof(
            req.proof_envelope, public_key, prover=prover,
            verify_range_proof=req.verify_range_proof, compliance_receipt=req.compliance_receipt)

    @app.get("/proofs/verify", response_class=HTMLResponse)
    async def verify_portal() -> HTMLResponse:
        return HTMLResponse(_PORTAL_HTML.replace("__NONCE__", ""))

    return app
