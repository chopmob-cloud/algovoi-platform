"""The v1 compat shim must cover everything the real algovoi_substrate package exposes.

The shim synthesises the ``algovoi_substrate`` namespace out of substrate2 so existing v1
call sites keep working with SUBSTRATE2_ENABLED=1. That only holds while the shim keeps up
with the package it is impersonating. It did not: ``caip`` and ``settlement_binding``
shipped in algovoi-substrate 0.5.x and were never mapped, so code that imported either one
worked on v1 and raised under substrate2 -- a difference that only shows up in production,
under a flag, at import time.

These tests compare the shim against the installed package rather than against a hand-kept
list, so a module added upstream fails here instead of being noticed by accident.
"""
from __future__ import annotations

import importlib
import importlib.util
import pathlib

import pytest

from substrate2.compat import v1_shim

# Discover the REAL package's submodules from disk, at collection time, before any shim is
# installed. Asking the imported package would be worse than useless: once install() runs,
# `algovoi_substrate` in sys.modules is the synthesised stand-in with `__path__ = []`, so a
# pkgutil walk returns nothing and every assertion below would pass vacuously.
def _v1_submodules() -> list[str]:
    spec = importlib.util.find_spec("algovoi_substrate")
    if spec is None or not spec.origin:
        return []
    root = pathlib.Path(spec.origin).parent
    return sorted(
        p.stem for p in root.glob("*.py") if not p.stem.startswith("_")
    )


V1_SUBMODULES = _v1_submodules()


@pytest.fixture
def shim():
    v1_shim.uninstall()
    v1_shim.install()
    yield
    v1_shim.uninstall()


def test_discovery_is_not_vacuous():
    """Guard the guard: if discovery silently returns nothing, every check below passes
    while proving nothing."""
    assert len(V1_SUBMODULES) >= 8, V1_SUBMODULES
    assert "caip" in V1_SUBMODULES and "settlement_binding" in V1_SUBMODULES


def test_every_v1_submodule_resolves_to_the_shim(shim):
    """Every algovoi_substrate.<mod> must resolve to the SYNTHESISED module, not the real one.

    Asserting merely that the import succeeds is not enough, and gets weaker the more
    developer-friendly the machine is. Editable installs put a per-distribution
    _EditableFinder on sys.meta_path, and meta-path finders are consulted ahead of the
    parent package's __path__. So an unmapped submodule does not raise here: it silently
    loads the REAL v1 module, and the process ends up running v1 primitives for that one
    import while everything else runs on substrate2. Silent is worse than loud.

    A shim-provided module is built by types.ModuleType and has no __file__. That is the
    property worth asserting, and it holds whether or not the real package is importable.
    """
    unmapped = []
    for name in V1_SUBMODULES:
        try:
            mod = importlib.import_module(f"algovoi_substrate.{name}")
        except ImportError:
            unmapped.append(f"{name} (ImportError)")
            continue
        origin = getattr(mod, "__file__", None)
        if origin is not None:
            unmapped.append(f"{name} (fell through to {origin})")
    assert not unmapped, f"shim does not map algovoi_substrate submodules: {unmapped}"


def test_caip_resolves_and_works(shim):
    from algovoi_substrate import caip

    assert caip.require_caip2("eip155:1") == "eip155:1"
    assert not caip.is_caip2("eip155:1\n")


def test_settlement_binding_resolves_and_works(shim):
    from algovoi_substrate import settlement_binding as sb

    ref = sb.settlement_action_binding("a" * 64, "a" * 64, "a" * 64, "sha256:" + "b" * 64)
    assert ref.startswith("sha256:")


def test_top_level_names_resolve(shim):
    """The flat `from algovoi_substrate import X` form, which some call sites use."""
    import algovoi_substrate as a

    for name in ("canonicalize", "sha256_jcs", "action_ref", "require_caip2",
                 "settlement_action_binding"):
        assert hasattr(a, name), name


def test_shim_is_reversible(shim):
    """install()/uninstall() must not leave the namespace behind: the flag has to be a
    genuine toggle, or turning substrate2 off would not restore v1."""
    import algovoi_substrate  # noqa: F401  (present while the fixture holds it installed)

    v1_shim.uninstall()
    import sys

    assert "algovoi_substrate.caip" not in sys.modules
    v1_shim.install()  # restore for fixture teardown
