# HOWTO: add the validation pack to the control plane (Compliance Command Center)

For the commercial products the control plane is **Compliance Command Center**
(CCC). CCC is already the compliance posture and evidence console, so the
system's own validation evidence belongs right next to the customer's compliance
evidence: a new export that produces a signed IQ/OQ/PQ pack on demand.

CCC is a clean fit because it already provides every piece:

- `algovoi_command_center.audit` is a Falcon-1024 **signed console audit chain**
  with a `Signer` (local now, HSM/KMS/Vault in phase f). We sign the pack with
  that same signer.
- `algovoi_command_center.posture` exposes each evidence chain as a `ChainView`
  with `.verified` and `.head`. Those heads are the production integrity evidence.
- `algovoi_command_center.export` already ships an evidence export, so the
  validation pack is a sibling export, not new surface.

## 1. Gather the three sections from CCC

```python
from algovoi_command_center import posture as cc_posture
from validation.adapters import collect_control_plane

# OQ: CCC's own suite plus the products it manages (capture from CI).
suite_results = [
    {"name": "command_center", "total": 36, "passed": 36, "failed": 0,
     "run_at": "2026-06-15T01:00:00Z", "result_digest": "sha256:<run log digest>"},
]

# PQ: the production integrity evidence is CCC's verified chains and their heads.
p = cc_posture.current()                       # the Posture the dashboard renders
verified = [c for c in p.chains if c.verified]
attestation_head = {
    "chain": "command_center_console_audit",
    "head": verified[0].head if verified else None,
    "rows": sum(c.entries for c in verified),
    "attested_at": "2026-06-15T02:00:00Z",
    "chains": [{"name": c.name, "verified": c.verified, "head": c.head} for c in p.chains],
}

iq, oq, pq = collect_control_plane(
    suite_results=suite_results,
    attestation_head=attestation_head,
    packages=["algovoi-command-center"],
    sbom_ref="artifacts/sbom.cdx.json",
)
```

## 2. Sign with CCC's own signer

The collector accepts CCC's `Signer` directly, so it works with the local key
today and the HSM/KMS/Vault signer in phase f without any change here:

```python
from algovoi_command_center import audit
from validation.validation_pack import build_validation_pack

signer = audit.LocalSigner(PUBLIC_KEY, SECRET_KEY)   # or the phase-f HSM signer
build_validation_pack(
    iq=iq, oq=oq, pq=pq,
    signer=signer,
    out_dir="/var/lib/algovoi/ccc-validation-pack",
    artifact_id="urn:algovoi:validation:command-center",
    generator="algovoi-command-center",
)
```

## 3. Expose it as a Command Center export

CCC already serves `/api/posture`, `/export` and `/audit`. Add one route beside
them:

```python
# in algovoi_command_center/app.py, next to the existing export route
@app.get("/validation/pack")
async def validation_pack(request: Request):
    # auth + RBAC exactly as the existing /export route
    out = build_ccc_validation_pack()        # steps 1 and 2
    return zip_response(out, filename="system-validation-pack.zip")
```

Surface it on the dashboard next to the evidence export, labelled something like
"System validation pack (IQ/OQ/PQ)". Because it rebuilds on request it is always
current, which is the whole point: validation that never goes stale.

## 4. Confirm

From a clean machine with no AlgoVoi code:

```bash
pip install pqcrypto rfc8785
python verify_validation_pack.py <unzipped pack>
# exit 0 = installed correctly (IQ), operating to spec (OQ), performing in production (PQ)
```

## Notes

- The only live read is the posture in step 1; everything else is static or from
  CI. CCC already computes the posture for its dashboard, so this reuses work it
  does anyway.
- Confirm the exact accessor for the current posture (`cc_posture.current()` is
  the expected name; CCC's app builds it for `/api/posture`, reuse that path).
- The signing key stays in CCC's existing custody. The verifier never sees it.
