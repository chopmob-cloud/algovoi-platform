"""Voi transaction verifier -- same algod-compatible API as Algorand, different node."""
from algovoi_settlement_verify.verifiers.algorand import AlgorandVerifier


class VoiVerifier(AlgorandVerifier):
    """Voi uses the same algod REST API as Algorand -- same verifier, different node."""
    pass
