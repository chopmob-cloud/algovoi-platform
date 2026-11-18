"""
substrate2.release.sbom — deterministic CycloneDX 1.5 SBOM for a substrate2 release.

Why this exists: substrate2 ships to regulated fintechs as an on-prem wheel, and the
first thing their procurement asks for is a bill of materials. Generating it from the
installed distributions rather than from `pyproject.toml` means it describes what the
customer will actually run, including transitive pins.

Determinism is a hard requirement, not a nicety: the SBOM's own sha256 is bound into the
signed release manifest, so two runs over the same environment must produce byte-identical
output. That rules out serial numbers, build timestamps and set iteration order.
"""
from __future__ import annotations

import re
from importlib import metadata
from typing import Any, Iterable

SPEC_VERSION = "1.5"

# Requirement strings arrive as "cryptography>=42" or "pqcrypto>=0.4.0; extra == 'pqc'".
# Parsed by hand so the SBOM generator carries no dependency of its own -- a build-tooling
# dependency would itself need to appear in the bill of materials it produces.
_NAME_RE = re.compile(r"\A\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_EXTRA_RE = re.compile(r"extra\s*==\s*['\"]([^'\"]+)['\"]")


class SbomError(RuntimeError):
    """Raised when the dependency closure cannot be resolved from the environment."""


def _split_requirement(req: str) -> tuple[str, str | None, bool]:
    """Return (distribution name, extra it is gated behind or None, has other marker)."""
    base, _, marker = req.partition(";")
    match = _NAME_RE.match(base)
    if not match:
        raise SbomError(f"unparseable requirement: {req!r}")
    extra = _EXTRA_RE.search(marker)
    # Anything left in the marker once `extra == ...` is removed is an environment
    # condition -- python_version, sys_platform, implementation_name.
    residue = _EXTRA_RE.sub("", marker).strip(" \t'\"()andor")
    return match.group(1), (extra.group(1) if extra else None), bool(residue)


def _closure(root: str, extras: frozenset[str]) -> dict[str, str]:
    """Resolve root plus its requirements to {canonical name: installed version}.

    Environment markers are not evaluated -- that would need a full marker grammar, and a
    build-tooling dependency is exactly what this module refuses to take on. Instead
    absence is read as the answer: a dependency carrying an environment marker that is
    not installed had its marker evaluate false here, so it is correctly absent from an
    SBOM describing THIS environment. A dependency with no marker that is missing is a
    genuinely broken environment and is refused, because guessing would produce a
    disclosure document that understates what ships.
    """
    resolved: dict[str, str] = {}
    queue: list[str] = [root]
    conditional: set[str] = set()
    while queue:
        name = queue.pop()
        key = name.lower().replace("_", "-")
        if key in resolved:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError as exc:
            if key in conditional:
                continue  # marker excluded it in this environment
            raise SbomError(
                f"{name!r} is required unconditionally but is not installed; an SBOM "
                f"must describe a complete environment, so this is refused rather "
                f"than guessed"
            ) from exc
        resolved[key] = dist.version
        for req in dist.requires or []:
            dep, gated_on, conditional_dep = _split_requirement(req)
            # Only follow an optional dependency when its extra was actually requested,
            # otherwise a `pip install substrate2` SBOM would claim pqcrypto is present.
            if gated_on is not None and gated_on not in extras:
                continue
            if conditional_dep:
                conditional.add(dep.lower().replace("_", "-"))
            queue.append(dep)
    return resolved


def build_sbom(
    root: str = "substrate2",
    *,
    extras: Iterable[str] = (),
    bundled: Iterable[tuple[str, str]] = (),
) -> dict[str, Any]:
    """Build a deterministic CycloneDX 1.5 document for `root` as installed.

    `bundled` carries (name, version) pairs for components delivered as wheels alongside
    the release rather than resolved from an index -- `algovoi-bpverify` is the standing
    case, since it is commercial and deliberately on no public index. Omitting it would
    make the SBOM describe a package the customer cannot actually install.
    """
    extras_set = frozenset(e.lower() for e in extras)
    resolved = _closure(root, extras_set)
    root_key = root.lower().replace("_", "-")
    root_version = resolved.pop(root_key)

    for name, version in bundled:
        resolved.setdefault(name.lower().replace("_", "-"), version)

    components = [
        {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
            "scope": "required",
        }
        # Sorted so the document -- and therefore its sha256 -- is stable across runs.
        for name, version in sorted(resolved.items())
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": root_key,
                "version": root_version,
                "purl": f"pkg:pypi/{root_key}@{root_version}",
            },
            # Extras are recorded because they change the closure: an SBOM for the `zkp`
            # install is a different document from one for the base install.
            "properties": [
                {"name": "substrate2:extra", "value": extra}
                for extra in sorted(extras_set)
            ],
        },
        "components": components,
    }


__all__ = ["SPEC_VERSION", "SbomError", "build_sbom"]
