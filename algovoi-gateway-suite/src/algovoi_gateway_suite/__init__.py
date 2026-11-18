"""algovoi-gateway-all — all-chains meta-package.

Installing this single commercial licence pulls the AlgoVoi payment gateway core
plus every chain provider (Algorand, Base, Stellar, VOI, Hedera, Solana, Tempo).
Each provider self-registers under the ``algovoi_gateway.providers`` entry point,
so gateway-core discovers all seven chains at import time with nothing further to
configure.
"""

__version__ = "0.1.3"

CHAINS = (
    "algorand",
    "base",
    "stellar",
    "voi",
    "hedera",
    "solana",
    "tempo",
)
