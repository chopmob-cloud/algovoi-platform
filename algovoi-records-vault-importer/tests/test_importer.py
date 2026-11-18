"""algovoi-records-vault-importer: switchable volume importer - standalone runnable.

Proves both signing strategies through one API: falcon (one signature per document) and merkle (one
signature per batch, with offline per-document inclusion proofs). Also covers bridge/store modes,
idempotent resume, parallel-hash filesystem import, the fail-closed licence gate, and rejection of a bad
strategy.

Run: python algovoi-records-vault-importer/tests/test_importer.py   (needs pqcrypto + rfc8785 + substrate2)
"""
import asyncio
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("algovoi-doc-archive", "algovoi-records-vault", "algovoi-records-vault-importer"):
    sys.path.insert(0, f"{ROOT}/{sub}/src")

from algovoi_doc_archive import licensing as _dl  # noqa: E402
_dl.require_license = lambda *a, **k: {"t": 1}
from algovoi_records_vault import licensing as _rl  # noqa: E402
_rl.require_license = lambda *a, **k: {"t": 1}
from algovoi_records_vault_importer import licensing as _il  # noqa: E402
_il.require_license = lambda *a, **k: {"t": 1}   # bypass the add-on gate for the unit test

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault.migrate import FsSource  # noqa: E402
from algovoi_records_vault_importer import (  # noqa: E402
    import_records, import_records_fs, verify_document_in_batch, compact_proof, merkle,
)

PASS = FAIL = 0


def check(label, cond):
    global PASS, FAIL
    PASS, FAIL = (PASS + 1, FAIL) if cond else (PASS, FAIL + 1)
    print(f"  {'PASS' if cond else 'FAIL'}  {label}")


def _archive(d):
    pk, sk = signing.generate_keypair()
    kp, ks = generate_mlkem_keypair()
    return Archive(public_key=pk, secret_key=sk, storage=LocalFsBackend(d),
                   encryptor=HybridPqcEncryptor(kp, ks)), pk


def _make_files(d, n):
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        open(os.path.join(d, f"doc-{i:05d}.txt"), "wb").write(f"record {i} ".encode() + os.urandom(12))


async def main():
    tmp = tempfile.mkdtemp(prefix="importer-")
    src = os.path.join(tmp, "src"); _make_files(src, 200)

    # merkle proof unit
    shas = [f"sha256:{'%064x' % i}" for i in range(13)]
    root = merkle.merkle_root(shas)
    check("merkle inclusion verifies", all(
        merkle.verify_inclusion(shas[i], i, merkle.inclusion_proof(shas, i), root) for i in range(13)))

    # bad strategy rejected
    a, pk = _archive(os.path.join(tmp, "bad"))
    try:
        await import_records(a, FsSource(src), strategy="rsa")
        check("bad strategy rejected", False)
    except ValueError:
        check("bad strategy rejected", True)

    # STRATEGY = falcon (one signature per document)
    af, pkf = _archive(os.path.join(tmp, "falcon"))
    rf = await import_records(af, FsSource(src), strategy="falcon", mode="bridge")
    entries_f = await af.list_entries()
    check("falcon: committed every document", rf.committed == 200 and rf.skipped == 0)
    check("falcon: one signature per document", rf.signatures == 200 == len(entries_f))
    check("falcon: strategy recorded", rf.strategy == "falcon")

    # STRATEGY = merkle (one signature per batch) + inclusion proofs
    am, pkm = _archive(os.path.join(tmp, "merkle"))
    rm = await import_records(am, FsSource(src), strategy="merkle", batch_size=50, mode="bridge")
    entries_m = await am.list_entries()
    check("merkle: committed every document", rm.committed == 200 and rm.skipped == 0)
    check("merkle: one signature per batch (4 for 200@50)", rm.signatures == 4 == len(entries_m))
    check("merkle: far fewer signatures than falcon", rm.signatures * 10 < rf.signatures)
    p0, _, _ = signing.open_envelope(entries_m[0])
    doc = p0["metadata"]["refs"][7]["sha256"]
    check("merkle: a document verifies as included in its signed batch", verify_document_in_batch(doc, entries_m[0], pkm))
    check("merkle: a foreign hash is not in the batch", not verify_document_in_batch("sha256:" + "00" * 32, entries_m[0], pkm))
    cp = compact_proof(entries_m[0], doc)
    check("merkle: compact single-document proof verifies", merkle.verify_inclusion(cp["doc_sha"], cp["index"], cp["proof"], cp["root"]))
    tampered = entries_m[0][:-4] + ("AAAA" if entries_m[0][-4:] != "AAAA" else "BBBB")
    check("merkle: tampered batch rejected (verifier never raises)", not verify_document_in_batch(doc, tampered, pkm))

    # idempotent resume (merkle)
    rm2 = await import_records(am, FsSource(src), strategy="merkle", batch_size=50, mode="bridge")
    check("merkle: idempotent re-run skips everything", rm2.committed == 0 and rm2.skipped == 200)

    # parallel-hash fs + store mode (merkle)
    src2 = os.path.join(tmp, "src2"); _make_files(src2, 80)
    as_, pks = _archive(os.path.join(tmp, "store"))
    rs = await import_records_fs(as_, src2, strategy="merkle", batch_size=40, mode="store", workers=8)
    ents = await as_.list_entries()
    check("merkle store: parallel-hash import committed all", rs.committed == 80 and len(ents) == 2)
    ps, _, _ = signing.open_envelope(ents[0])
    sdoc = ps["metadata"]["refs"][0]["sha256"]
    check("merkle store: blob persisted", (await as_.storage.get(f"blob/{sdoc.split(':', 1)[1]}")) is not None)

    # the gate is real: with the bypass removed, import refuses without a licence
    import importlib
    from algovoi_records_vault_importer import licensing as lic
    orig = lic.require_license
    def _raise():
        raise lic.LicenseError("no licence")
    lic.require_license = _raise
    ag, _ = _archive(os.path.join(tmp, "gated"))
    try:
        await import_records(ag, FsSource(src), strategy="merkle")
        check("licence gate is fail-closed", False)
    except lic.LicenseError:
        check("licence gate is fail-closed", True)
    finally:
        lic.require_license = orig

    print(f"\n=== IMPORTER RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
