"""
substrate2.policy_binding — additive policy-snapshot binding over a frozen subject ref.

Proves which policy/ruleset version was in force when a record was sealed, and makes a
silent policy rotation detectable: a record sealed under policy P fails recomputation
under a rotated P'. Strictly additive over the frozen Layer 1 — no new primitive, the
same RFC 8785 JCS + SHA-256 already in the substrate.

    policy_ref       = "sha256:" + SHA-256(JCS(policy_document))
    policy_bound_ref = "sha256:" + SHA-256(JCS({ "policy_ref": ..., "subject_ref": ... }))

`subject_ref` is imported by hash, so the same construction binds a policy to a
settlement-action binding_ref (v1) or a retention_chain_ref (v0/v1) unchanged.

Byte-for-byte identical to the published `algovoi-policy-binding` (Apache-2.0) and its
TypeScript twin. Normative spec: draft-hopley-x402-retention-chain-04 §7.7 / §8.10.

Implemented from policy-binding.mdx + the published policy_binding_v1 vectors.
Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

from .digest import sha256_jcs_prefixed

# In-band binding rule pin, for receipts that record which binding rule they used.
POLICY_BINDING_VERSION = "policy_binding_v1"


class PolicyBindingError(ValueError):
    """Raised when a policy document or subject ref is not safe to bind."""


def policy_ref(policy_document: dict) -> str:
    """Content hash of a policy/ruleset/mandate snapshot.

    JCS-canonicalised first, so key order in the policy document does not affect the
    result. Returns ``"sha256:<64-hex>"``.
    """
    if not isinstance(policy_document, dict):
        raise PolicyBindingError("policy_document must be a JSON object (dict)")
    return sha256_jcs_prefixed(policy_document)


def policy_bound_ref(subject_ref: str, policy_ref_value: str) -> str:
    """Bind a ``policy_ref`` to a frozen ``subject_ref`` (a settlement-action binding_ref
    or a retention_chain_ref). Version-agnostic: the subject is imported by hash.

    Returns ``"sha256:<64-hex>"``. Any change to the policy (hence its ``policy_ref``) or
    to the subject changes the bound ref — that is the rotation-detection property.
    """
    if not _is_ref(subject_ref):
        raise PolicyBindingError('subject_ref must be "sha256:<64-hex>"')
    if not _is_ref(policy_ref_value):
        raise PolicyBindingError('policy_ref must be "sha256:<64-hex>"')
    return sha256_jcs_prefixed({"policy_ref": policy_ref_value, "subject_ref": subject_ref})


def verify_policy_binding(*, bound_ref: str, subject_ref: str, policy_document: dict) -> bool:
    """Offline check: recompute ``policy_bound_ref`` from the subject + the policy document
    and confirm it equals ``bound_ref``. Returns False on any mismatch (a rotated policy
    document will not recompute). Never raises."""
    try:
        return policy_bound_ref(subject_ref, policy_ref(policy_document)) == bound_ref
    except Exception:  # noqa: BLE001
        return False


def _is_ref(value: str) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    hex_part = value[len("sha256:"):]
    return len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part)


__all__ = [
    "POLICY_BINDING_VERSION",
    "PolicyBindingError",
    "policy_ref",
    "policy_bound_ref",
    "verify_policy_binding",
]
