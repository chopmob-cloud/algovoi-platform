"""serve.py security tests: key-file permissions at creation, and the bind guard.

Added 2026-11-14 after a reviewer found two BLOCKERs in the serve wrapper the moment it became visible
in the diff: the key file was created at the process umask and only chmod'ed afterwards (a TOCTOU
window in which signing and ML-KEM secrets were world-readable), and the non-loopback bind guard read
ARCHIVE_HOST only, so `uvicorn ... --host 0.0.0.0` bypassed it entirely.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from algovoi_doc_archive import serve


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolated archive root plus a licence stub so build_app can run without a real licence."""
    from algovoi_doc_archive import licensing
    monkeypatch.setattr(licensing, "require_license", lambda *a, **k: {"tier": "test"})
    monkeypatch.setenv("ARCHIVE_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("ARCHIVE_KEY_FILE", str(tmp_path / "data" / "archive-key.json"))
    monkeypatch.delenv("ARCHIVE_API_TOKEN", raising=False)
    monkeypatch.delenv("ARCHIVE_HOST", raising=False)
    return tmp_path


def test_key_file_is_created_0600_not_chmoded_afterwards(env):
    """The secret must never exist at a looser mode.

    HONEST LIMITATION: this asserts the FINAL mode, which a write-then-chmod implementation also
    satisfies (verified: the naive form ends at 0o600 on POSIX too). It therefore does not prove the
    absence of the transient TOCTOU window the reviewer described. What it does pin is that the file
    ships 0600 at all and that the atomic path works, so a regression that dropped permissions
    entirely is caught. The window itself is closed by construction in serve.py (os.open with mode
    0o600 + O_EXCL + os.replace); demonstrating the absence of a race needs a filesystem watcher,
    which is out of proportion for this change and is stated here rather than simulated.
    """
    path = env / "data" / "archive-key.json"
    fpk, fsk, kpk, ksk = serve._load_or_bootstrap_keys()
    assert path.exists()

    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"key file mode is {oct(mode)}, expected 0o600"

    data = json.loads(path.read_text())
    assert set(data) == {"pk", "sk", "kem_pk", "kem_sk"}
    assert all(data[k] for k in data)

    # a second boot must load the persisted keys rather than mint new ones
    again = serve._load_or_bootstrap_keys()
    assert again[0] == fpk and again[2] == kpk


def test_key_material_is_never_written_with_a_plain_open(env, monkeypatch):
    """Structural check for the TOCTOU fix: the bootstrap must not use bare open()/Path.write_text.

    A behavioural test cannot observe a transient permission window, so assert the mechanism instead:
    os.open must be used with an explicit 0600 mode and O_EXCL, and the bytes must reach their final
    path by rename. If someone reverts to `with open(path, "w")`, this fails even though the final
    mode is still 0600.
    """
    import inspect

    src = inspect.getsource(serve._load_or_bootstrap_keys)
    assert "os.open(" in src, "bootstrap must create the key file with os.open"
    assert "0o600" in src, "the create mode must be 0o600"
    assert "O_EXCL" in src, "the create must be exclusive so a stale file is not silently reused"
    assert "os.replace(" in src, "the bytes must be moved into place atomically"
    assert 'open(path, "w"' not in src and "open(path, 'w'" not in src, \
        "bare open(path, 'w') creates at the umask, reopening the TOCTOU window"


def test_no_stale_temp_file_is_left_behind(env):
    serve._load_or_bootstrap_keys()
    leftovers = [p for p in (env / "data").iterdir() if p.name.endswith(".tmp")]
    assert not leftovers, f"temp files left: {leftovers}"


def test_a_stale_temp_file_does_not_block_bootstrap(env):
    """A leftover temp from a crashed boot must not break the next start.

    The temp name now includes the pid and a random suffix, so bootstrap never has to delete a file
    another process might own: it simply picks a fresh name. A stale file is therefore left in place
    (harmless, and ignored by .gitignore-adjacent conventions) rather than unlinked, which is what the
    earlier fixed-name design did unsafely.
    """
    path = env / "data" / "archive-key.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    stale = path.parent / (path.name + ".tmp")      # old-style fixed name, as a crashed boot would leave
    stale.write_text("half-written garbage")

    serve._load_or_bootstrap_keys()                 # must not raise
    assert path.exists()
    # the key file is the authoritative artefact; the stale temp is not consumed as it
    assert json.loads(path.read_text())["sk"] != "half-written garbage"


def test_public_bind_without_a_token_is_refused_through_the_argument(env):
    """The bypass the reviewer described: uvicorn --host 0.0.0.0 never sets ARCHIVE_HOST."""
    with pytest.raises(RuntimeError, match="ARCHIVE_API_TOKEN"):
        serve.build_app(host="0.0.0.0")


def test_public_bind_without_a_token_is_refused_through_the_environment(env, monkeypatch):
    monkeypatch.setenv("ARCHIVE_HOST", "0.0.0.0")
    with pytest.raises(RuntimeError, match="ARCHIVE_API_TOKEN"):
        serve.build_app()


def test_public_bind_with_a_token_is_allowed(env, monkeypatch):
    monkeypatch.setenv("ARCHIVE_API_TOKEN", "t" * 32)
    app = serve.build_app(host="0.0.0.0")
    assert app is not None


@pytest.mark.parametrize("loopback", ["127.0.0.1", "localhost", "::1"])
def test_loopback_bind_without_a_token_is_allowed(env, monkeypatch, loopback):
    monkeypatch.setenv("ARCHIVE_API_TOKEN", "")
    app = serve.build_app(host=loopback)
    assert app is not None


def test_asgi_import_path_requires_a_token(env, monkeypatch):
    """An ASGI server's --host is invisible at import time, so the app must never build without a token.

    `uvicorn algovoi_doc_archive.serve:app --host 0.0.0.0` sets no environment variable this module can
    read, so a guard on ARCHIVE_HOST is bypassed by the CLI flag. Rather than offer false assurance the
    import path refuses to build an unauthenticated app at all.
    """
    monkeypatch.delenv("ARCHIVE_API_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="ARCHIVE_API_TOKEN"):
        serve.__getattr__("app")


def test_asgi_import_path_builds_once_a_token_is_set(env, monkeypatch):
    monkeypatch.setenv("ARCHIVE_API_TOKEN", "t" * 32)
    app = serve.__getattr__("app")
    assert app is not None


def test_argument_overrides_the_environment_for_the_guard(env, monkeypatch):
    """If the caller is binding somewhere public, the env var must not launder it."""
    monkeypatch.setenv("ARCHIVE_HOST", "127.0.0.1")     # looks safe in the env
    with pytest.raises(RuntimeError, match="ARCHIVE_API_TOKEN"):
        serve.build_app(host="203.0.113.9")            # but this is what will be bound
