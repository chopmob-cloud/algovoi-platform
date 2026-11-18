# Copyright (c) 2026 AlgoVoi (chopmob-cloud). All Rights Reserved.
# AlgoVoi Commercial License v1.0 — see LICENSE for terms.
# Evaluation use only. Commercial use: hello@algovoi.co.uk
"""AlgoVoi Federation Validator — cross-issuer ZKP credential composition.

Compose independent Falcon-1024 / ML-DSA-65 PQC credentials from different
issuers into a single federation token. No shared trust root required.

IETF anchors:
  draft-hopley-x402-pqc-credential-binding-00
  draft-hopley-x402-federation-zkp-00
"""
from algovoi_federation_validator._version import __version__
from algovoi_federation_validator.models import (
    CredentialVerifyResult,
    FederationResult,
    FederationToken,
    IssuerEntry,
    PqcCredentialFields,
)
from algovoi_federation_validator.validator import FederationValidator
from algovoi_federation_validator._crypto import (
    compose_commitments,
    issue_federation_token,
    verify_federation_token,
    verify_pqc_credential,
)

__all__ = [
    "__version__",
    "FederationValidator",
    "FederationResult",
    "FederationToken",
    "IssuerEntry",
    "CredentialVerifyResult",
    "PqcCredentialFields",
    "verify_pqc_credential",
    "compose_commitments",
    "issue_federation_token",
    "verify_federation_token",
]
