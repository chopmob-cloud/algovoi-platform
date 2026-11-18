"""Health & Legal editions — the same engine, sold as two tailored products via config presets.

Records Vault ships one codebase; an **edition** is a named bundle of defaults (retention windows,
whether consent / custody are part of the vertical's core flow, default authorised uses) so a buyer's
deployment is preset for their regulatory shape without forking. Presets are *defaults*, not limits —
any value can be overridden per call.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_YEAR = 365


@dataclass(frozen=True)
class Edition:
    """A vertical preset bundle. ``retention_days`` / ``hold_preservation_days`` feed the retention +
    legal-hold defaults; the ``*_in_core_flow`` flags drive which evidence layers a deployment surfaces.
    """

    name: str
    label: str
    retention_days: int
    hold_preservation_days: int
    consent_in_core_flow: bool
    custody_in_core_flow: bool
    default_authorized_uses: tuple[str, ...] = field(default_factory=tuple)
    default_content_types: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""

    def as_dict(self) -> dict:
        return {
            "edition": self.name, "label": self.label,
            "retention_days": self.retention_days,
            "hold_preservation_days": self.hold_preservation_days,
            "consent_in_core_flow": self.consent_in_core_flow,
            "custody_in_core_flow": self.custody_in_core_flow,
            "default_authorized_uses": list(self.default_authorized_uses),
            "default_content_types": list(self.default_content_types),
        }


# Retention figures are conservative defaults a deployment confirms with counsel — NOT legal advice.
HEALTH = Edition(
    name="health",
    label="Records Vault — Health",
    retention_days=7 * _YEAR,          # common HIPAA-aligned floor; varies by state/record type
    hold_preservation_days=7 * _YEAR,
    consent_in_core_flow=True,         # HIPAA authorization / GDPR lawful basis is part of the flow
    custody_in_core_flow=False,
    default_authorized_uses=("treatment", "payment", "operations"),
    default_content_types=("application/dicom", "application/fhir+json", "application/pdf", "text/plain"),
    notes="HIPAA §164.312(b) access log + consent receipts; air-gap on-prem supported.",
)

LEGAL = Edition(
    name="legal",
    label="Records Vault — Legal",
    retention_days=7 * _YEAR,          # matter-driven in practice; preservation overrides disposal
    hold_preservation_days=7 * _YEAR,
    consent_in_core_flow=False,
    custody_in_core_flow=True,         # chain of custody + custodian handoff is part of the flow
    default_authorized_uses=("discovery", "review", "disclosure"),
    default_content_types=("application/pdf", "message/rfc822", "text/plain", "application/zip"),
    notes="RFC-3161 timestamping + litigation holds + Falcon-signed custody manifests.",
)

EDITIONS = {e.name: e for e in (HEALTH, LEGAL)}


def edition(name: str) -> Edition:
    """Look up an edition preset by name (``health`` | ``legal``)."""
    key = (name or "").strip().lower()
    if key not in EDITIONS:
        raise ValueError(f"unknown edition {name!r}; choose one of {sorted(EDITIONS)}")
    return EDITIONS[key]
