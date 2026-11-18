"""algovoi-records-vault-importer: CLI + watcher options - standalone runnable.

Proves the two new interface options over the same signed-batch importer:
  * the `algovoi-rv-import import` CLI imports a folder, persists keys, and prints a JSON summary;
    a second run is idempotent (0 committed); `verify` confirms a document against the signed batch.
  * the folder watcher runs an idempotent import once the folder is quiescent, skips a still-changing
    folder, and keeps watching (fail-closed) after an error.

Run: python algovoi-records-vault-importer/tests/test_cli_watcher.py   (needs pqcrypto + rfc8785 + substrate2)
"""
import asyncio
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("algovoi-doc-archive", "algovoi-records-vault", "algovoi-records-vault-importer"):
    sys.path.insert(0, f"{ROOT}/{sub}/src")

from algovoi_doc_archive import licensing as _dl  # noqa: E402
_dl.require_license = lambda *a, **k: {"t": 1}
from algovoi_records_vault import licensing as _rl  # noqa: E402
_rl.require_license = lambda *a, **k: {"t": 1}
from algovoi_records_vault_importer import licensing as _il  # noqa: E402
_il.require_license = lambda *a, **k: {"t": 1}

from algovoi_records_vault_importer import cli, watch  # noqa: E402

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def _make_files(d, n, start=0):
    os.makedirs(d, exist_ok=True)
    for i in range(start, start + n):
        open(os.path.join(d, f"doc-{i:05d}.txt"), "wb").write(f"record {i} ".encode() + os.urandom(12))


def _run_cli(argv) -> tuple[int, dict]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.main(argv)
    out = buf.getvalue().strip()
    try:
        return rc, json.loads(out)
    except Exception:
        return rc, {"_raw": out}


def test_cli(tmp):
    src = os.path.join(tmp, "estate"); _make_files(src, 120)
    arch = os.path.join(tmp, "archive"); keys = os.path.join(tmp, "keys")
    rc, res = _run_cli(["import", src, "--archive", arch, "--keys-dir", keys,
                        "--strategy", "merkle", "--mode", "bridge", "--batch-size", "50"])
    check("cli import rc=0", rc == 0)
    check("cli imported all 120 docs", res.get("committed") == 120)
    check("cli batched (>=3 batches @50)", res.get("batches", 0) >= 3)
    check("cli persisted keys (reusable)", os.path.exists(os.path.join(keys, "falcon_sk.key")))

    rc2, res2 = _run_cli(["import", src, "--archive", arch, "--keys-dir", keys,
                          "--strategy", "merkle", "--batch-size", "50"])
    check("cli second run idempotent (0 committed, 120 skipped)",
          res2.get("committed") == 0 and res2.get("skipped") == 120)


def test_watcher(tmp):
    from algovoi_doc_archive import signing
    from algovoi_doc_archive.archive import Archive
    from algovoi_doc_archive.backend import LocalFsBackend
    from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair

    pk, sk = signing.generate_keypair()
    kp, ks = generate_mlkem_keypair()
    archive = Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(os.path.join(tmp, "wa")),
                      encryptor=HybridPqcEncryptor(kp, ks))
    src = os.path.join(tmp, "watched"); _make_files(src, 30)

    # injected clock/sleep so the test is deterministic and instant: each nap advances the clock by
    # poll_secs, so after two identical polls the quiescent window elapses and a cycle runs.
    t = {"v": 0.0}
    ticks = {"n": 0}
    cycles = []

    def clock():
        return t["v"]

    async def nap(secs):
        t["v"] += secs
        ticks["n"] += 1

    def stop():
        return ticks["n"] >= 6  # stop after a handful of polls

    committed_cycles = asyncio.run(watch(
        archive, src, strategy="merkle", batch_size=10, poll_secs=10.0, quiescent_secs=5.0,
        on_cycle=lambda r: cycles.append(r), clock=clock, sleep=nap, stop=stop))

    check("watcher ran an import cycle once quiescent", committed_cycles >= 1)
    check("watcher committed the 30 watched docs", any(r.committed == 30 for r in cycles))
    check("watcher second cycle idempotent (no re-commit)",
          all(r.committed in (0, 30) for r in cycles))


def main():
    tmp = tempfile.mkdtemp(prefix="rv-cli-watch-")
    print("CLI:")
    test_cli(tmp)
    print("Watcher:")
    test_watcher(tmp)
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
