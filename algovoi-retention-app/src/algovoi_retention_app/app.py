"""AlgoVoi Retention App -- stateful FastAPI service.

Ingests payment-receipt hashes and auto-maintains per-issuer, hash-linked
retention chains using the public ``algovoi_retention_chain`` primitive. Exports
Falcon-1024 signed, offline-verifiable regulator evidence packs that double as
Compliance Command Center evidence (entry_type ``retention_chain_link``).

Endpoints:
  POST /v1/receipts            ingest a receipt; app derives seq + prev + chain_ref
  GET  /v1/chains/{issuer}      the issuer's chain records
  POST /v1/verify              verify a sequence of records (contiguous or subset)
  GET  /v1/export/{issuer}      signed evidence pack (zip) for one issuer
  GET  /v1/export              signed evidence pack (zip) for all issuers
  GET  /v1/posture             per-issuer compliance posture
  GET  /health                 liveness
  POST /v1/chain-ref           stateless: compute a chain_ref
  POST /v1/verify-link         stateless: verify one link

Config (env):
  RETENTION_DSN / RETENTION_DB           store location (SQLite default)
  RETENTION_DATA_DIR                     where the signing key bootstraps (0600)
  RETENTION_FALCON_PK_B64/SK_B64         explicit signer keypair (else generated)
  RETENTION_APP_BIND                     bind address (default 0.0.0.0:8097)
  CCC_HUB_URL / CCC_HUB_TOKEN / CCC_HUB_NAME / CCC_HUB_SELF_URL   CCC bolt-in
  S2_HUB_URL / S2_HUB_TOKEN / ...        substrate-2 control plane bridge
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import zipfile

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from algovoi_retention_app import REG_BASIS, __version__
from algovoi_retention_app.export import build_payloads, build_retention_pack
from algovoi_retention_app.signing import LocalSigner
from algovoi_retention_app.store import DuplicateReceipt, RetentionStore
from algovoi_retention_chain import verify_chain_sequence

logger = logging.getLogger(__name__)


# ── signer bootstrap (mirrors the Command Center: explicit env, else persist) ──
def _load_signer() -> LocalSigner:
    pk = os.environ.get("RETENTION_FALCON_PK_B64", "").strip()
    sk = os.environ.get("RETENTION_FALCON_SK_B64", "").strip()
    if pk and sk:
        return LocalSigner.from_b64(pk, sk)
    base = os.environ.get("RETENTION_DATA_DIR", ".")
    path = os.path.join(base, "retention-signing-key.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return LocalSigner.from_b64(d["pk"], d["sk"])
    os.makedirs(base, exist_ok=True)
    signer = LocalSigner.generate()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"pk": signer.public_key_b64(), "sk": signer.secret_key_b64()}, fh)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return signer


_store = RetentionStore()
_signer = _load_signer()


# ── models ─────────────────────────────────────────────────────────────────────
class ReceiptIn(BaseModel):
    issuer_id: str = Field(..., min_length=1)
    receipt_hash: str = Field(..., description='"sha256:<64-hex>" of the receipt JCS bytes.')


class RecordOut(BaseModel):
    issuer_id: str
    chain_seq: int
    prev_receipt_hash: str
    receipt_hash: str
    chain_ref: str
    created_at: str


class VerifyIn(BaseModel):
    records: list[dict] = Field(..., description="Records ordered by ascending chain_seq.")


class VerifyOut(BaseModel):
    valid: bool


class ChainRefIn(BaseModel):
    chain_seq: int = Field(..., ge=0)
    issuer_id: str = Field(..., min_length=1)
    receipt_hash: str
    prev_receipt_hash: str = ""


app = FastAPI(
    title="AlgoVoi Retention App",
    description=(
        "Stateful payment-receipt retention. Auto-maintains per-issuer hash-linked "
        "chains and exports Falcon-1024 signed, offline-verifiable evidence. "
        "MiCA Art. 68(9), DORA Art. 17, AMLR Art. 77."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url=None,
)


@app.on_event("startup")
def _bridge() -> None:
    from algovoi_retention_app.hub_client import (
        register_into_ccc_from_env,
        register_into_s2_from_env,
    )
    if os.environ.get("CCC_HUB_URL", "").strip():
        logger.info("retention_app.ccc.register ok=%s", register_into_ccc_from_env())
    if os.environ.get("S2_HUB_URL", "").strip():
        logger.info("retention_app.s2.register ok=%s", register_into_s2_from_env())


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "retention-app", "version": __version__,
            "kid": _signer.kid}


@app.post("/v1/receipts", response_model=RecordOut)
def ingest_receipt(body: ReceiptIn) -> RecordOut:
    try:
        rec = _store.append(body.issuer_id, body.receipt_hash)
    except DuplicateReceipt as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return RecordOut(**rec.as_dict())


@app.get("/v1/chains/{issuer_id}")
def get_chain(issuer_id: str) -> dict:
    recs = _store.chain(issuer_id)
    return {"issuer_id": issuer_id, "entries": len(recs),
            "records": [r.as_dict() for r in recs]}


@app.post("/v1/verify", response_model=VerifyOut)
def verify(body: VerifyIn) -> VerifyOut:
    return VerifyOut(valid=verify_chain_sequence(body.records))


@app.get("/v1/posture")
def posture() -> dict:
    issuers = []
    total = 0
    all_ok = True
    for issuer in _store.issuers():
        recs = _store.chain(issuer)
        ok = verify_chain_sequence([r.as_dict() for r in recs])
        all_ok = all_ok and ok
        total += len(recs)
        issuers.append({"issuer_id": issuer, "entries": len(recs),
                        "head_chain_ref": recs[-1].chain_ref if recs else None,
                        "verified": ok})
    return {"estate": os.environ.get("RETENTION_ESTATE", "estate"),
            "issuers": issuers, "total_entries": total,
            "all_verified": all_ok, "reg_basis": REG_BASIS}


def _pack_zip(records: list) -> bytes:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        build_retention_pack(records, _signer, td)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in sorted(os.listdir(td)):
                zf.write(os.path.join(td, name), name)
        return buf.getvalue()


@app.get("/v1/export/{issuer_id}")
def export_issuer(issuer_id: str) -> Response:
    recs = _store.chain(issuer_id)
    if not recs:
        raise HTTPException(status_code=404, detail=f"no chain for issuer {issuer_id!r}")
    return Response(content=_pack_zip(recs), media_type="application/zip",
                    headers={"Content-Disposition":
                             f'attachment; filename="retention-{issuer_id}.zip"'})


@app.get("/v1/export")
def export_all() -> Response:
    recs = _store.all_records()
    if not recs:
        raise HTTPException(status_code=404, detail="no records to export")
    return Response(content=_pack_zip(recs), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="retention-all.zip"'})


@app.post("/v1/chain-ref")
def chain_ref_endpoint(body: ChainRefIn) -> dict:
    from algovoi_retention_chain import retention_chain_ref
    try:
        ref = retention_chain_ref(prev_receipt_hash=body.prev_receipt_hash,
                                  receipt_hash=body.receipt_hash,
                                  chain_seq=body.chain_seq, issuer_id=body.issuer_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"chain_ref": ref}


def main() -> None:
    import uvicorn
    bind = os.environ.get("RETENTION_APP_BIND", "0.0.0.0:8097")
    host, _, port = bind.partition(":")
    uvicorn.run(app, host=host, port=int(port or "8097"))
