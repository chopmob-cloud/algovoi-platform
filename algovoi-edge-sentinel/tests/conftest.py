import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
# algovoi-agent-passport (Falcon signing dep) is a sibling commercial package, not pip-installed here.
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "algovoi-agent-passport", "src")))

from algovoi_edge_sentinel import EdgeSentinel, EdgePolicy, hybrid, signing  # noqa: E402
from algovoi_edge_sentinel.geo import InMemoryGeoProvider  # noqa: E402


class FakeClock:
    """Deterministic clock for rate/replay tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self.t = start or datetime(2026, 6, 22, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, seconds: int) -> None:
        self.t = self.t + timedelta(seconds=seconds)


def make_sentinel(*, policy: EdgePolicy | None = None, geo=None, mldsa=False, clock=None):
    pk, sk = signing.generate_keypair()
    kw, mpk = {}, None
    if mldsa:
        mpk, msk = hybrid.generate_keypair()
        kw = {"mldsa_secret_key": msk, "mldsa_public_key": mpk}
    s = EdgeSentinel(decision_secret_key=sk, decision_public_key=pk,
                     policy=policy or EdgePolicy(), geo_provider=geo,
                     clock=clock or FakeClock(), _skip_license=True, **kw)
    return s, pk, mpk
