"""Environment collectors for the System Validation Evidence Pack.

Two thin adapters gather the IQ/OQ/PQ inputs from the two contexts the pack is
produced in, the platform control plane and a standalone Records Vault, then
hand them to ``build_validation_pack``. Each adapter auto-collects what can be
read locally (component versions, a configuration fingerprint, an SBOM if one is
present) and takes the live, environment-specific values, the test-suite results
and the integrity-attestation chain head, as arguments. Nothing is fabricated:
the live values come from the running system, and the HOWTO files show exactly
where each one is read.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _versions(packages: list[str]) -> dict:
    from importlib import metadata
    out = {}
    for p in packages:
        try:
            out[p] = metadata.version(p)
        except Exception:  # noqa: BLE001
            out[p] = "unknown"
    return out


def _config_fingerprint(paths: list[str]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        if os.path.exists(p):
            with open(p, "rb") as fh:
                h.update(fh.read())
    return "sha256:" + h.hexdigest()


def collect_standalone_rv(*, suite_results: list[dict], chain_head: dict,
                          packages: list[str] | None = None,
                          config_paths: list[str] | None = None,
                          sbom_ref: str | None = None) -> tuple[dict, dict, dict]:
    """Gather IQ/OQ/PQ for a standalone Records Vault deployment.

    suite_results: a list of ``{name,total,passed,failed,run_at,result_digest}``
        from the deployment's own test or conformance run.
    chain_head: ``{chain,head,rows,attested_at}``, the head of the vault's signed
        archive chain (``RecordsVault`` exposes the signed streams; take the head
        of the archive chain as the integrity attestation).
    """
    packages = packages or ["algovoi-records-vault", "algovoi-doc-archive"]
    iq = {"component_versions": _versions(packages), "installed_at": _now()}
    if sbom_ref:
        iq["sbom_ref"] = sbom_ref
    if config_paths:
        iq["config_fingerprint"] = _config_fingerprint(config_paths)
    oq = {"suites": list(suite_results)}
    pq = {"integrity_attestation": dict(chain_head)}
    return iq, oq, pq


def collect_control_plane(*, suite_results: list[dict], attestation_head: dict,
                          packages: list[str] | None = None,
                          config_paths: list[str] | None = None,
                          sbom_ref: str | None = None) -> tuple[dict, dict, dict]:
    """Gather IQ/OQ/PQ for the platform control plane.

    suite_results: the control plane's own test or conformance results, same shape
        as above.
    attestation_head: ``{chain,head,rows,attested_at}`` read from the control
        plane's SOC-2-grade integrity-attestation chain (the audit service that
        was added in migration 095). This is the production performance evidence.
    """
    packages = packages or ["algovoi-control-plane"]
    iq = {"component_versions": _versions(packages), "installed_at": _now()}
    if sbom_ref:
        iq["sbom_ref"] = sbom_ref
    if config_paths:
        iq["config_fingerprint"] = _config_fingerprint(config_paths)
    oq = {"suites": list(suite_results)}
    pq = {"integrity_attestation": dict(attestation_head)}
    return iq, oq, pq
