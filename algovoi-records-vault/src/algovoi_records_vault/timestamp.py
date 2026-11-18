"""F1 — RFC-3161 trusted timestamping for archive receipts.

A trusted timestamp binds a record's hash to an *independent* notion of time: a Time-Stamping
Authority (TSA) signs ``hash + its clock``, so years later you can prove a record existed no later than
that instant — without trusting the archive's own ``archived_at``. The thing we timestamp is the
**archive receipt's** content hash: ``messageImprint = signing.payload_hash(receipt_payload)``.

Two interchangeable clients implement :class:`TsaClient`, mirroring the engine's ``Noop*`` air-gap
pattern:

- :class:`RequestTsaClient` — talks RFC-3161 to a real TSA over HTTP (``application/timestamp-query``),
  returns the DER ``TimeStampToken`` for external verification.
- :class:`NoopTsaClient` — air-gap default: records the messageImprint in the signed ``tsa/`` stream
  with no external token. The vault stays fully offline; turning on a TSA later changes only config.

The DER for the RFC-3161 request is built here directly (no ASN.1 dependency) so the package stays
dependency-light and air-gap-clean. The opaque signed token is stored verbatim; full CMS verification
of that token is delegated to any standard RFC-3161 verifier — what the vault verifies offline is the
**binding**: that the stored ``message_imprint`` equals the receipt's ``payload_hash`` and that the
``tsa/`` chain is intact.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime
from typing import Protocol, runtime_checkable

from algovoi_doc_archive import signing

from algovoi_records_vault.vault import _VaultStream

# id-sha256 — { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
#               hashAlgs(2) sha256(1) } -> DER of the OID value bytes.
_SHA256_OID_DER = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


# ----- minimal DER builders (just enough for a TimeStampReq) ----------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _der_int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 8) // 8, "big")  # +8 guarantees a leading 0x00 sign pad
        body = body.lstrip(b"\x00") or b"\x00"
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _der_octet_string(b: bytes) -> bytes:
    return _tlv(0x04, b)


def _der_bool(v: bool) -> bytes:
    return _tlv(0x01, b"\xff" if v else b"\x00")


def _der_seq(*parts: bytes) -> bytes:
    return _tlv(0x30, b"".join(parts))


def build_timestamp_request(digest_hex: str, *, cert_req: bool = True,
                            nonce: int | None = None) -> bytes:
    """DER-encode an RFC-3161 ``TimeStampReq`` for a SHA-256 ``messageImprint``.

    ``digest_hex`` is the hex of the SHA-256 digest to be timestamped (no ``sha256:`` prefix).
    """
    digest = bytes.fromhex(digest_hex)
    if len(digest) != 32:
        raise ValueError("messageImprint must be a 32-byte SHA-256 digest")
    if nonce is None:
        nonce = int.from_bytes(os.urandom(8), "big")
    alg_id = _der_seq(_SHA256_OID_DER, _tlv(0x05, b""))            # AlgorithmIdentifier { sha256, NULL }
    message_imprint = _der_seq(alg_id, _der_octet_string(digest))  # MessageImprint
    return _der_seq(
        _der_int(1),                # version v1
        message_imprint,            # messageImprint
        _der_int(nonce),            # nonce (replay protection)
        _der_bool(cert_req),        # certReq — ask the TSA to include its certificate
    )


# ----- minimal DER reader (split TimeStampResp, scan TSTInfo genTime) --------------------------
def _read_tlv(buf: bytes, i: int) -> tuple[int, int, int]:
    """Return (tag, value_start, value_end) for the TLV at offset ``i``."""
    tag = buf[i]
    i += 1
    first = buf[i]
    i += 1
    if first < 0x80:
        length = first
    else:
        nbytes = first & 0x7F
        length = int.from_bytes(buf[i:i + nbytes], "big")
        i += nbytes
    return tag, i, i + length


def parse_timestamp_response(der: bytes) -> tuple[bytes | None, int, str]:
    """Split an RFC-3161 ``TimeStampResp`` into ``(timeStampToken_der, status, status_text)``.

    PKIStatus 0 (granted) / 1 (grantedWithMods) carry a token. The token is returned verbatim (the DER
    of the ``ContentInfo``) for external CMS verification; ``None`` if the TSA refused.
    """
    tag, vs, ve = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("TimeStampResp: expected SEQUENCE")
    # element 1: PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString?, failInfo? }
    stag, svs, sve = _read_tlv(der, vs)
    if stag != 0x30:
        raise ValueError("TimeStampResp: expected PKIStatusInfo SEQUENCE")
    itag, ivs, ive = _read_tlv(der, svs)
    status = int.from_bytes(der[ivs:ive], "big") if itag == 0x02 else -1
    status_text = {0: "granted", 1: "grantedWithMods", 2: "rejection",
                   3: "waiting", 4: "revocationWarning", 5: "revocationNotification"}.get(status, "unknown")
    token = der[sve:ve] if sve < ve and status in (0, 1) else None
    return token, status, status_text


def extract_gen_time(token_der: bytes) -> str | None:
    """Best-effort: pull the TSTInfo ``genTime`` (ASN.1 GeneralizedTime, tag 0x18) from a token.

    Returned as ISO ``YYYY-MM-DDTHH:MM:SSZ`` for metadata. This is informational only — the
    authoritative time is inside the signed token, which a full RFC-3161 verifier checks; the vault
    stores the token verbatim for exactly that. ``None`` if no GeneralizedTime is present.
    """
    i, n = 0, len(token_der)
    while i < n:
        tag = token_der[i]
        try:
            _t, vs, ve = _read_tlv(token_der, i)
        except Exception:  # noqa: BLE001
            return None
        if tag == 0x18:  # GeneralizedTime
            raw = token_der[vs:ve].decode("ascii", "replace")
            digits = raw.rstrip("Z").split(".")[0]
            if len(digits) >= 14 and digits[:14].isdigit():
                iso = (f"{digits[0:4]}-{digits[4:6]}-{digits[6:8]}T"
                       f"{digits[8:10]}:{digits[10:12]}:{digits[12:14]}Z")
                try:  # only emit a genuinely valid calendar date, never a digits-but-impossible one
                    datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    return None
                return iso
            return None
        # descend into constructed types (bit 0x20 set), else step over primitive
        i = vs if (tag & 0x20) else ve
    return None


# ----- TSA clients ----------------------------------------------------------------------------
@runtime_checkable
class TsaClient(Protocol):
    name: str
    def request_timestamp(self, digest_hex: str) -> dict: ...


class NoopTsaClient:
    """Air-gap default: no external call. The messageImprint is still recorded, signed, in ``tsa/``."""

    name = "noop"

    def request_timestamp(self, digest_hex: str) -> dict:
        return {"tsa": "noop", "tsa_status": "air-gap", "token_b64": None, "tsa_gen_time": None,
                "note": "no external TSA configured; messageImprint sealed in the signed vault chain only"}


class RequestTsaClient:
    """RFC-3161 client over HTTP. Posts a ``TimeStampReq``; stores the returned DER ``TimeStampToken``."""

    def __init__(self, url: str, *, timeout: float = 15.0, cert_req: bool = True) -> None:
        self.url = url
        self.name = url
        self.timeout = timeout
        self.cert_req = cert_req

    def request_timestamp(self, digest_hex: str) -> dict:
        import httpx  # lazy — keeps the air-gap path dependency-free

        req = build_timestamp_request(digest_hex, cert_req=self.cert_req)
        resp = httpx.post(self.url, content=req, timeout=self.timeout, headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        })
        resp.raise_for_status()
        token, _status, status_text = parse_timestamp_response(resp.content)
        return {
            "tsa": self.url,
            "tsa_status": status_text,
            "token_b64": base64.b64encode(token).decode("ascii") if token else None,
            "tsa_gen_time": extract_gen_time(token) if token else None,
        }


# RFC-3161 PKIStatus values that actually carry a token. Anything else (rejection, waiting,
# revocationWarning/Notification) grants no trustworthy time.
_GRANTED_STATUSES = frozenset({"granted", "grantedWithMods"})


class TimestampError(RuntimeError):
    """Raised when a *requested* TSA did not grant a token, so no trustworthy stamp could be recorded."""


class Timestamper:
    """Binds a :class:`TsaClient` to the signed ``tsa/`` stream: stamp a receipt, store the token."""

    def __init__(self, *, stream: _VaultStream, client: TsaClient) -> None:
        self._stream = stream
        self._client = client

    @staticmethod
    def message_imprint(receipt_envelope: str) -> str:
        """The hash that is timestamped: ``payload_hash`` of the archive receipt's payload."""
        payload, _sig, _kid = signing.open_envelope(receipt_envelope)
        return signing.payload_hash(payload)

    async def stamp(self, *, receipt_envelope: str, archive_seq: int,
                    archive_entry_id: str) -> dict:
        """Timestamp an archive receipt and append a signed token record to the ``tsa/`` stream."""
        imprint = self.message_imprint(receipt_envelope)
        tok = self._client.request_timestamp(imprint.split(":", 1)[1])
        # Fail closed: a *requested* TSA that returned no token (rejection/waiting/…) must not be
        # recorded as a stamp. Only the air-gap NoopTsaClient legitimately records no token.
        if tok.get("token_b64") is None and tok.get("tsa_status") != "air-gap":
            raise TimestampError(
                f"TSA {tok.get('tsa')!r} did not grant a timestamp (status={tok.get('tsa_status')!r}); "
                f"refusing to record a tokenless stamp")
        fields = {
            "archive_seq": archive_seq,
            "archive_entry_id": archive_entry_id,
            "message_imprint": imprint,
            "tsa": tok.get("tsa"),
            "tsa_status": tok.get("tsa_status"),
            "tsa_gen_time": tok.get("tsa_gen_time"),
            "token_b64": tok.get("token_b64"),
        }
        return await self._stream.append(fields)

    async def get(self, seq: int) -> dict | None:
        return await self._stream.get_payload(seq)

    async def list_tokens(self) -> list[dict]:
        return await self._stream.list_payloads()

    async def verify_chain(self):
        return await self._stream.verify_chain()


def verify_timestamp_binding(tsa_record: dict, receipt_envelope: str) -> bool:
    """Offline: does this ``tsa/`` record's ``message_imprint`` actually match this receipt?

    This proves the *binding* (this record stamps this receipt) — it does **not** assert a trusted
    external time. For air-gap or rejected records there is no token; use :func:`is_trusted_timestamp`
    when you need to know an RFC-3161 authority actually granted the time.
    """
    return tsa_record.get("message_imprint") == Timestamper.message_imprint(receipt_envelope)


def is_trusted_timestamp(tsa_record: dict) -> bool:
    """Does this ``tsa/`` record carry a real RFC-3161 token from a granting TSA?

    ``True`` only when a token is present and the TSA status is ``granted``/``grantedWithMods`` — i.e.
    a trusted external authority attested the time. ``False`` for the air-gap case (imprint sealed in
    the signed chain only) and for any non-granting response.
    """
    return bool(tsa_record.get("token_b64")) and tsa_record.get("tsa_status") in _GRANTED_STATUSES
