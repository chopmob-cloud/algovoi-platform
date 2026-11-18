"""
substrate2 conformance gate.

Run after install:   python -m substrate2.conformance.run_all
Run pre-install:     python <repo>/substrate2/src/substrate2/conformance/run_all.py

Prints a per-section GREEN/RED table. Exit 0 only when ALL GREEN. v2 is "done" only at
ALL GREEN.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Bootstrap: make the substrate2 package importable when run as a bare script.
_SRC = Path(__file__).resolve().parents[2]  # .../substrate2/src
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from substrate2.conformance.harness import (  # noqa: E402
    caip_vectors,
    exactly_once_adversarial,
    jcs_vectors,
    jws_anchor,
    jws_roundtrip,
    receipt_examples,
    retention_chain,
    rfc8032_fixture,
    spec_external,
    zkp_federation,
)

SECTIONS = [
    ("1. JCS vector convergence", jcs_vectors.run),
    ("2. RFC 8032 / RFC 9421 fixture", rfc8032_fixture.run),
    ("3. External spec verifier round-trip", spec_external.run),
    ("4. Receipt builders vs vectors", receipt_examples.run),
    ("5. JWS receipt round-trip", jws_roundtrip.run),
    ("6. ZKP + federation", zkp_federation.run),
    ("7. Exactly-once + adversarial isolation", exactly_once_adversarial.run),
    ("8. Retention chain + signed link verify", retention_chain.run),
    ("9. CAIP identifier grammar", caip_vectors.run),
    ("10. Signed-token anchoring", jws_anchor.run),
]


def main() -> int:
    results = []
    for name, fn in SECTIONS:
        try:
            ok, detail = fn()
        except NotImplementedError as exc:
            ok, detail = False, f"not implemented yet ({exc})"
        except Exception as exc:  # pragma: no cover
            ok, detail = False, f"ERROR {type(exc).__name__}: {exc}"
        results.append((name, ok, detail))

    width = max(len(n) for n, _, _ in results)
    print("\nSubstrate 2 — conformance gate")
    print("=" * (width + 14))
    for name, ok, detail in results:
        tag = "GREEN" if ok else " RED "
        print(f"[{tag}] {name.ljust(width)}  {detail}")
    print("=" * (width + 14))

    failures = sum(1 for _, ok, _ in results if not ok)
    if failures == 0:
        print("ALL GREEN\n")
        return 0
    print(f"{failures} FAILURE(S) — not done\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
