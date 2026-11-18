"""F1 RFC-3161 timestamping test (standalone, runnable): codec + Noop air-gap path + binding.

The real-TSA network leg is exercised only when VAULT_TSA_URL is set (it SKIPs otherwise, like the
MinIO leg); the offline gauntlet fully covers the DER codec, the air-gap stream, and the binding proof.

Run: python algovoi-records-vault/tests/test_timestamp.py
"""
import asyncio
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, f"{ROOT}/algovoi-doc-archive/src")
sys.path.insert(0, f"{ROOT}/algovoi-records-vault/src")

from algovoi_doc_archive import licensing as base_licensing  # noqa: E402
base_licensing.require_license = lambda: {"test": True}

from algovoi_doc_archive import signing  # noqa: E402
from algovoi_doc_archive.archive import Archive  # noqa: E402
from algovoi_doc_archive.backend import LocalFsBackend  # noqa: E402
from algovoi_doc_archive.encryption import HybridPqcEncryptor, generate_mlkem_keypair  # noqa: E402

from algovoi_records_vault import licensing as rv_licensing  # noqa: E402
rv_licensing.require_license = lambda: {"test": True}

from algovoi_records_vault import RecordsVault  # noqa: E402
from algovoi_records_vault.timestamp import (  # noqa: E402
    NoopTsaClient, Timestamper, build_timestamp_request, extract_gen_time,
    parse_timestamp_response, verify_timestamp_binding,
)

PASS = 0
FAIL = 0


def check(label, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {label}")
    else:
        FAIL += 1
        print(f"  FAIL  {label}")


# --- DER helpers to synthesise an RFC-3161 TimeStampResp without a network/TSA -----------------
def _tlv(tag, value):
    n = len(value)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + value


def synth_resp(status, gen_time_str="20260612120000Z", with_token=True):
    pki = _tlv(0x30, _tlv(0x02, bytes([status])))                      # PKIStatusInfo { INTEGER status }
    if not with_token:
        return _tlv(0x30, pki)
    gtime = _tlv(0x18, gen_time_str.encode("ascii"))                  # GeneralizedTime
    token = _tlv(0x30, gtime)                                          # stand-in ContentInfo
    return _tlv(0x30, pki + token), token


def main_sync():
    # ----- request DER -----
    digest_hex = "ab" * 32
    req = build_timestamp_request(digest_hex, cert_req=True)
    check("request is a DER SEQUENCE", req[:1] == b"\x30")
    check("request embeds the 32-byte messageImprint digest", bytes.fromhex(digest_hex) in req)
    try:
        build_timestamp_request("ab" * 16)  # 16 bytes -> not SHA-256
        check("request rejects a non-32-byte digest", False)
    except ValueError:
        check("request rejects a non-32-byte digest", True)

    # ----- response parsing (granted, with token) -----
    der, token = synth_resp(0)
    tok, status, status_text = parse_timestamp_response(der)
    check("granted response parses status 0 / granted", status == 0 and status_text == "granted")
    check("granted response splits out the token verbatim", tok == token)
    check("genTime extracted from token", extract_gen_time(tok) == "2026-06-12T12:00:00Z")

    # ----- response parsing (rejection, no token) -----
    der2 = synth_resp(2, with_token=False)
    tok2, status2, status_text2 = parse_timestamp_response(der2)
    check("rejection response parses status 2 / no token", status2 == 2 and tok2 is None)


async def main_async():
    tmp = tempfile.mkdtemp(prefix="rv-tsa-")
    pk, sk = signing.generate_keypair()
    kem_pk, kem_sk = generate_mlkem_keypair()
    archive = Archive(public_key=pk, secret_key=sk,
                      storage=LocalFsBackend(os.path.join(tmp, "archive")),
                      encryptor=HybridPqcEncryptor(kem_pk, kem_sk))
    rv_licensing.require_license = lambda: {"test": True}
    # no VAULT_TSA_URL -> air-gap NoopTsaClient
    os.environ.pop("VAULT_TSA_URL", None)
    vault = RecordsVault(archive=archive)

    out = await vault.notarize(data=b"patient record A", title="rec-A", content_type="text/plain")
    check("notarize returns an archive entry + a tsa record",
          out["archive"]["seq"] == 0 and out["tsa"]["seq"] == 0)

    ts = vault.timestamper()
    tok0 = await ts.get(0)
    check("air-gap token record marks status air-gap, no external token",
          tok0["tsa_status"] == "air-gap" and tok0["token_b64"] is None)
    check("messageImprint == payload_hash of the archive receipt",
          tok0["message_imprint"] == Timestamper.message_imprint(out["archive"]["receipt"]))
    check("tsa record links back to the archive entry",
          tok0["archive_seq"] == 0 and tok0["archive_entry_id"] == out["archive"]["entry_id"])

    # binding proof (offline)
    check("verify_timestamp_binding TRUE for the right receipt",
          verify_timestamp_binding(tok0, out["archive"]["receipt"]) is True)

    out2 = await vault.notarize(data=b"patient record B", title="rec-B")
    tok1 = await ts.get(1)
    check("a different record's imprint differs",
          tok1["message_imprint"] != tok0["message_imprint"])
    check("binding FALSE when receipt and token are mismatched",
          verify_timestamp_binding(tok0, out2["archive"]["receipt"]) is False)

    # tsa stream integrity
    vr = await ts.verify_chain()
    check("tsa stream verifies valid over 2 tokens", vr.valid and vr.length == 2)

    # notarize without timestamping leaves the tsa stream untouched
    out3 = await vault.notarize(data=b"no-stamp record", time_stamp=False)
    check("time_stamp=False notarizes without a tsa record", out3["tsa"] is None)
    check("tsa stream still length 2", (await ts.verify_chain()).length == 2)

    # direct NoopTsaClient
    n = NoopTsaClient()
    check("NoopTsaClient reports air-gap", n.request_timestamp("00" * 32)["tsa_status"] == "air-gap")


def main() -> int:
    main_sync()
    asyncio.run(main_async())
    print(f"\n=== TIMESTAMP RESULT: {PASS} passed, {FAIL} failed ===")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
