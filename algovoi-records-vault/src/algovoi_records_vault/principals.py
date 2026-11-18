"""Principal identity for who/why fields on access-log and legal-hold entries.

A :class:`Principal` is the minimal accountable identity recorded against an evidence event: a DID,
the key id of the credential that authenticated it, and the scopes it carried. It is deliberately
small — the vault records *who acted and under what authority*, not a full IAM model (that is the
caller's directory). The same shape is reused by the access log (HIPAA §164.312(b) "who accessed")
and legal hold (who set/released a matter hold).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    """An accountable actor: DID + authenticating key id + granted scopes."""

    did: str
    kid: str = ""
    scopes: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # the whole point of a principal is an accountable identity — an empty DID is never valid
        if not isinstance(self.did, str) or not self.did.strip():
            raise ValueError("Principal.did must be a non-empty identity (the accountable actor)")

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes

    def as_record(self) -> dict:
        """The who-fields recorded on a signed evidence entry (stable, JCS-safe)."""
        return {
            "principal_did": self.did,
            "principal_kid": self.kid or None,
            "principal_scopes": list(self.scopes),
        }


def principal_fields(principal: "Principal | None") -> dict:
    """Who-fields for a possibly-absent principal (an anonymous/system actor records nulls)."""
    if principal is None:
        return {"principal_did": None, "principal_kid": None, "principal_scopes": []}
    return principal.as_record()
