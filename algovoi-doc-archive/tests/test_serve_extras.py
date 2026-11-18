"""The base install must be importable, and the serve extra must fail with an instruction.

``pyproject.toml`` declares the ``algovoi-doc-archive-serve`` console script unconditionally, but
FastAPI lives in the optional ``serve`` extra. An earlier revision imported ``create_app`` and
``bearer_token_auth`` at module scope, so on a base install the console script installed cleanly and
then died with a bare ``ModuleNotFoundError: No module named 'fastapi'``. These tests pin the two
properties that make that impossible:

  1. importing ``algovoi_doc_archive.serve`` works without the extra, so the script can be found and
     ``--help`` style inspection does not explode;
  2. building the app without the extra raises a message that names the extra to install.
"""
from __future__ import annotations

import builtins
import importlib
import sys

import pytest


def test_serve_module_imports_without_fastapi():
    """A base install must be able to import the module the console script points at."""
    mod = importlib.import_module("algovoi_doc_archive.serve")
    assert hasattr(mod, "main")
    assert hasattr(mod, "build_app")


def test_missing_serve_extra_names_the_extra(monkeypatch):
    """If FastAPI is genuinely absent, the error must say what to install."""
    import algovoi_doc_archive.serve as serve

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        # Only sabotage the from-import of the service symbols, not the whole interpreter.
        if name == "algovoi_doc_archive" and fromlist and (
                "create_app" in fromlist or "bearer_token_auth" in fromlist):
            raise ModuleNotFoundError("No module named 'fastapi'", name="fastapi")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ModuleNotFoundError) as exc:
        serve._service_layer()
    message = str(exc.value)
    assert "extra" in message
    assert "[serve]" in message, message
    assert "fastapi" in message


def test_missing_uvicorn_names_the_extra(monkeypatch):
    """The ASGI server is the other half of the extra; main() must name it too."""
    import algovoi_doc_archive.serve as serve

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "uvicorn":
            raise ModuleNotFoundError("No module named 'uvicorn'", name="uvicorn")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ModuleNotFoundError) as exc:
        serve.main()
    message = str(exc.value)
    assert "[serve]" in message, message
    assert "uvicorn" in message, message


def test_service_layer_returns_callables_when_available():
    """With the extra installed (the dev environment has it), the layer resolves."""
    import algovoi_doc_archive.serve as serve

    create_app, bearer = serve._service_layer()
    assert callable(create_app)
    assert callable(bearer)
