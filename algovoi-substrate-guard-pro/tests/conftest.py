import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
# algovoi-agent-passport (the Falcon signing dep) is a sibling commercial package, not pip-installed
# in this dev env — make it importable from its source for local validation.
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "algovoi-agent-passport", "src")))

from algovoi_substrate_guard_pro import GuardService, hybrid, signing  # noqa: E402


def make_service(*, mldsa=False, store=None):
    pk, sk = signing.generate_keypair()
    kw, mpk = {}, None
    if mldsa:
        mpk, msk = hybrid.generate_keypair()
        kw = {"mldsa_secret_key": msk, "mldsa_public_key": mpk}
    svc = GuardService(decision_secret_key=sk, decision_public_key=pk, store=store,
                       _skip_license=True, **kw)
    return svc, pk, mpk
