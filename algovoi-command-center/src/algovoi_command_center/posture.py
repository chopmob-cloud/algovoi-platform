"""Compliance-posture aggregation.

Folds the *verified* payloads from one or more evidence packs into a compliance posture — the numbers
the dashboard shows. Every figure here is derived only from chains that passed verification, so the
posture is itself evidence-backed: nothing is asserted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from algovoi_command_center.engine import ChainResult, PackResult

# entry_type -> (posture label, friendly chain name)
_TYPE_LABEL = {
    "archive_entry": ("records_preserved", "Archive · documents"),
    "vault_tsa_token": ("timestamps", "Timestamps · RFC 3161"),
    "vault_access_event": ("access_events", "Read-access log"),
    "vault_legal_hold": ("holds", "Legal / e-discovery holds"),
    "vault_consent_receipt": ("consents", "Consent ledger"),
    "vault_custody_manifest": ("custody", "Chain of custody"),
    "vault_keyring": ("key_rotations", "Key-rotation lineage"),
    "vault_acl_grant": ("acl", "Access-control grants"),
    "vault_redaction_record": ("redactions", "Redaction ledger"),
    "recovery_vault_custody": ("key_custody", "Recovery Vault · key custody"),
    "sanctions_screening_delta": ("sanctions", "Sanctions Monitor · screening deltas"),
    "retention_chain_link": ("retention", "Retention Chain · payment receipts"),
    # Keystone bolt-ons: supply-chain provenance (algovoi-sbom build_ref) and key-custody lifecycle
    # (algovoi-key-ceremony ceremony_ref) fold their signed, hash-linked refs into the same posture.
    "keystone_build_ref": ("supply_chain", "Keystone · supply-chain provenance"),
    "keystone_ceremony_ref": ("key_ceremony", "Keystone · key-custody lifecycle"),
    "compliance_gate_verdict": ("gate_verdicts", "Compliance Gate · policy-bound verdicts"),
    "gateway_settlement": ("settlements", "Payment Gateway · settlement receipts"),
    "gateway_payout": ("payouts", "Payment Gateway · payout receipts"),
    "spend_decision": ("spend_decisions", "Spend Guardrail · decision receipts"),
    "passport_event": ("passport_events", "Agent Passport · issue/revoke events"),
    "mandate_charge": ("mandate_charges", "Payment Mandate · authorized charges"),
    "guard_decision": ("guard_decisions", "Substrate Guard · admission decisions"),
    "edge_decision": ("edge_decisions", "Edge Sentinel · allow/deny decisions"),
    "execution_evidence": ("execution_evidence", "Keystone · execution evidence"),
    "keystone_evidence": ("keystone_lifecycle", "Keystone · full lifecycle"),
}


@dataclass
class Metric:
    key: str
    label: str
    value: int
    verified: bool


@dataclass
class ChainView:
    name: str
    entry_type: str | None
    entries: int
    verified: bool
    head: str | None
    reason: str


@dataclass
class Delta:
    icon: str          # tabler icon name (no leading 'ti-')
    text: str
    signed: bool = True


@dataclass
class Posture:
    estate: str
    packs: int
    all_verified: bool
    metrics: list[Metric] = field(default_factory=list)
    chains: list[ChainView] = field(default_factory=list)
    deltas: list[Delta] = field(default_factory=list)


def _active_holds(payloads: list[dict]) -> int:
    active: dict[str, bool] = {}
    for p in payloads:
        mid = p.get("matter_id")
        if not mid:
            continue
        if p.get("action") == "set":
            active[mid] = True
        elif p.get("action") == "release":
            active.pop(mid, None)
    return len(active)


def _active_consents(payloads: list[dict]) -> tuple[int, int]:
    grants: set[str] = set()
    revoked: set[str] = set()
    for p in payloads:
        cid = p.get("consent_id")
        if not cid:
            continue
        if p.get("consent_event") == "grant":
            grants.add(cid)
        elif p.get("consent_event") == "revoke":
            revoked.add(cid)
    return len(grants - revoked), len(revoked)


def _key_rotations(payloads: list[dict]) -> int:
    return sum(1 for p in payloads if p.get("key_event") == "rotate")


def _recent_deltas(packs: list[PackResult], limit: int = 6) -> list[Delta]:
    out: list[Delta] = []
    chains: dict[str, list[dict]] = {}
    for pk in packs:
        for c in pk.chains:
            chains.setdefault(c.entry_type or "", []).extend(c.payloads)
    for p in chains.get("vault_legal_hold", []):
        if p.get("action") == "set":
            out.append(Delta("gavel", f"Litigation hold placed on matter {p.get('matter_id')}"))
    for p in chains.get("vault_consent_receipt", []):
        if p.get("consent_event") == "revoke":
            out.append(Delta("user-x", f"Consent withdrawn — {p.get('consent_id', 'a subject')}"))
    for p in chains.get("vault_keyring", []):
        if p.get("key_event") == "rotate":
            out.append(Delta("key", "Signing key rotated — successor counter-signed, lineage intact"))
    return out[:limit]


def build_posture(packs: list[PackResult], *, estate: str = "estate") -> Posture:
    """Aggregate verified pack results into a compliance posture."""
    # collect verified payloads per entry_type across all packs
    by_type: dict[str, ChainResult] = {}
    chain_views: list[ChainView] = []
    for pk in packs:
        for c in pk.chains:
            chain_views.append(ChainView(
                _TYPE_LABEL.get(c.entry_type or "", (None, c.name))[1],
                c.entry_type, c.entries, c.verified, c.head, c.reason))
            t = c.entry_type or ""
            if t not in by_type:
                by_type[t] = ChainResult(c.name, c.entry_type, 0, True, c.head, "ok", [])
            agg = by_type[t]
            agg.entries += c.entries
            agg.verified = agg.verified and c.verified
            agg.payloads.extend(c.payloads)

    def m(t: str, key: str, label: str, value: int) -> Metric:
        return Metric(key, label, value, by_type.get(t).verified if t in by_type else True)

    metrics: list[Metric] = []
    if "archive_entry" in by_type:
        metrics.append(m("archive_entry", "records_preserved", "Records preserved",
                         by_type["archive_entry"].entries))
    if "vault_access_event" in by_type:
        metrics.append(m("vault_access_event", "access_events", "Read-access events",
                         by_type["vault_access_event"].entries))
    if "vault_legal_hold" in by_type:
        metrics.append(m("vault_legal_hold", "active_holds", "Active legal holds",
                         _active_holds(by_type["vault_legal_hold"].payloads)))
    if "vault_consent_receipt" in by_type:
        active, _rev = _active_consents(by_type["vault_consent_receipt"].payloads)
        metrics.append(m("vault_consent_receipt", "consents_active", "Consents active", active))
    if "vault_keyring" in by_type:
        metrics.append(m("vault_keyring", "key_rotations", "Key rotations",
                         _key_rotations(by_type["vault_keyring"].payloads)))
    if "keystone_build_ref" in by_type:
        metrics.append(m("keystone_build_ref", "supply_chain_builds", "Supply-chain builds attested",
                         by_type["keystone_build_ref"].entries))
    if "keystone_ceremony_ref" in by_type:
        metrics.append(m("keystone_ceremony_ref", "key_ceremonies", "Key ceremonies recorded",
                         by_type["keystone_ceremony_ref"].entries))

    all_verified = all(pk.verified for pk in packs) and bool(packs)
    return Posture(
        estate=estate, packs=len(packs), all_verified=all_verified,
        metrics=metrics, chains=chain_views, deltas=_recent_deltas(packs))
