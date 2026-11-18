"""
substrate2.timestamp — RFC 3161 trusted timestamps over the retention chain.

Implemented from RFC 3161 (Internet X.509 PKI Time-Stamp Protocol, Standards Track,
August 2001). Not derived from v1 source. See PROVENANCE.md.

## What this is for

Every other time value in this package is SELF-ASSERTED: the issuer writes
``issued_at_ms`` into a preimage and then signs it. That proves the issuer's intent, not
the moment. A sceptic, or an auditor, has no reason to accept it, because the party making
the claim also supplied the clock.

An RFC 3161 timestamp replaces "our system says this happened then" with "an independent
authority attests this digest existed by then". That is the difference that matters in a
regulated evidence product, and it is why this is a ratified external standard rather than
another AlgoVoi convention.

## What gets stamped, and why it is the chain head

``retention_chain.retention_chain_ref`` already hash-links every receipt into a chain. One
token over the CHAIN HEAD therefore gives every receipt beneath it an existence proof, at
one round trip per batch rather than one per receipt. An individual receipt is proven by
chain inclusion plus the head's token, which is how transparency logs work. It also keeps
the signing path usable where outbound network is restricted.

## Privacy

The TSA is sent ONLY a hash (RFC 3161 ``messageImprint``) and by design never sees the
data. That suits a no-PII evidence product exactly: timestamping leaks nothing.

## Scope, stated honestly

This is the equivalent of **JAdES B-T** (ETSI TS 119 182-1) -- an independent signature
timestamp. It is NOT B-LT (no ``xVals``/``rVals`` validation-data capture) and NOT B-LTA
(no archive-timestamp renewal). Do not describe output from this module as JAdES
conformant, eIDAS qualified, or "long-term validation". See TIMESTAMPING.md.

The cryptographic strength of a token is the TSA's, not ours: public TSAs sign with RSA or
ECDSA today. ``TimestampToken.signature_alg`` records which, so a caller can decide rather
than assume.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.request
from dataclasses import dataclass
from datetime import timezone

from .digest import sha256_jcs

_TIMESTAMP_QUERY = "application/timestamp-query"
_TIMESTAMP_REPLY = "application/timestamp-reply"

# RFC 3161 section 2.4.2 PKIStatus: 0 granted, 1 grantedWithMods; anything else is a refusal.
_ACCEPTED_STATUS = frozenset({"granted", "granted_with_mods"})

_HASH_ALGS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}


class TimestampError(ValueError):
    """Raised when a timestamp request cannot be built, or a token cannot be trusted."""


def _tsp():
    """Import asn1crypto lazily, the way zkp.py handles algovoi-bpverify.

    Kept out of the base install so `pip install substrate2` stays rfc8785 + cryptography.
    `cryptography` cannot parse a TimeStampToken at all -- its pkcs7 module only builds and
    envelopes -- so this dependency is unavoidable for real verification, not a convenience.
    """
    try:
        from asn1crypto import tsp
    except ImportError as exc:  # pragma: no cover - exercised by the no-extra install test
        raise TimestampError(
            "asn1crypto is required for RFC 3161 timestamps; install substrate2[timestamp]"
        ) from exc
    return tsp


def _digest_bytes(digest, hash_alg: str) -> bytes:
    """Accept the package-wide ``"sha256:<hex>"`` ref form, bare hex, or raw bytes.

    Taking the ref form directly is deliberate: a retention_chain_ref can be handed to
    timestamp_request() with no reformatting, so there is no opportunity to stamp a
    differently-encoded value than the one that was anchored.
    """
    if isinstance(digest, bytes):
        raw = digest
    elif isinstance(digest, str):
        text = digest.split(":", 1)[1] if ":" in digest else digest
        try:
            raw = bytes.fromhex(text)
        except ValueError as exc:
            raise TimestampError(f"digest is not hex: {digest!r}") from exc
    else:
        raise TimestampError(f"digest must be str or bytes, got {type(digest).__name__}")

    fn = _HASH_ALGS.get(hash_alg)
    if fn is None:
        raise TimestampError(f"unsupported hash_alg {hash_alg!r}; use one of {sorted(_HASH_ALGS)}")
    if len(raw) != fn().digest_size:
        raise TimestampError(
            f"digest is {len(raw)} bytes, but {hash_alg} imprints are {fn().digest_size}"
        )
    return raw


@dataclass
class TimestampToken:
    """The parsed contents of an RFC 3161 token."""

    gen_time_ms: int          # integer ms (Substrate Rule 2); never an RFC 3339 string
    serial: int
    policy_oid: str
    hash_alg: str
    message_imprint: bytes
    signature_alg: str
    tsa_name: str | None
    accuracy_ms: int | None
    nonce: int | None
    raw: bytes                # the DER token, exactly as issued

    @property
    def message_imprint_hex(self) -> str:
        return self.message_imprint.hex()


@dataclass
class TimestampResult:
    valid: bool
    token: TimestampToken | None = None
    #: False whenever no trust anchors were supplied. A caller must never read a parsed
    #: token as a verified one, so this is recorded rather than implied.
    signature_verified: bool = False
    failure_reason: str | None = None

    def __bool__(self) -> bool:
        return self.valid


def timestamp_request(digest, *, hash_alg: str = "sha256", nonce: int | None = None,
                      cert_req: bool = True, req_policy: str | None = None) -> tuple[bytes, int | None]:
    """Build a DER ``TimeStampReq`` over ``digest``.

    Returns ``(der, nonce)``. The nonce is generated when not supplied and returned so the
    caller can pass it to :func:`verify_timestamp_token`; RFC 3161 section 2.4.1 makes it the
    client's replay defence, and a nonce that is never checked is decoration.

    ``cert_req=True`` asks the TSA to include its certificate in the token, which is what
    makes later offline verification possible at all.
    """
    tsp = _tsp()
    imprint = _digest_bytes(digest, hash_alg)
    if nonce is None:
        nonce = secrets.randbits(64)

    req = {
        "version": "v1",
        "message_imprint": {
            "hash_algorithm": {"algorithm": hash_alg},
            "hashed_message": imprint,
        },
        "nonce": nonce,
        "cert_req": cert_req,
    }
    if req_policy:
        req["req_policy"] = req_policy
    return tsp.TimeStampReq(req).dump(), nonce


def fetch_timestamp(url: str, request_der: bytes, *, timeout: int = 10) -> bytes:
    """POST a ``TimeStampReq`` to a TSA and return the raw ``TimeStampResp`` DER.

    The ONLY function in this module that touches the network, deliberately: everything else
    is pure protocol and therefore testable offline against a recorded token.

    stdlib urllib only -- substrate2 does not take an HTTP client dependency.
    """
    req = urllib.request.Request(
        url, data=request_der,
        headers={"Content-Type": _TIMESTAMP_QUERY, "Accept": _TIMESTAMP_REPLY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as exc:
        raise TimestampError(f"TSA request to {url} failed: {exc}") from exc


def parse_timestamp_response(der: bytes) -> TimestampToken:
    """Parse a ``TimeStampResp`` (or a bare ``ContentInfo`` token) into a TimestampToken.

    Parsing is NOT acceptance: use :func:`verify_timestamp_token` for the RFC 3161 section 2.4.2
    recipient checks.
    """
    tsp = _tsp()

    try:
        resp = tsp.TimeStampResp.load(der)
        status = resp["status"]["status"].native
        if status not in _ACCEPTED_STATUS:
            reason = resp["status"]["status_string"].native if resp["status"]["status_string"] else ""
            raise TimestampError(f"TSA refused the request: status={status} {reason}")
        content_info = resp["time_stamp_token"]
    except TimestampError:
        raise
    except Exception:
        # Also accept a bare token, which is how tokens are usually stored once detached.
        from asn1crypto import cms

        try:
            content_info = cms.ContentInfo.load(der)
        except Exception as exc:
            raise TimestampError(f"not a TimeStampResp or ContentInfo: {exc}") from exc

    try:
        signed_data = content_info["content"]
        # asn1crypto knows the eContentType (tst_info) and hands back a ParsableOctetString,
        # so .parsed is already a TSTInfo. Reloading from .native would be wrong: that is the
        # decoded structure, not the DER bytes.
        content = signed_data["encap_content_info"]["content"]
        tst_info = content.parsed if hasattr(content, "parsed") else tsp.TSTInfo.load(content.native)
        signer = signed_data["signer_infos"][0]
        sig_alg = signer["signature_algorithm"]["algorithm"].native

        gen_time = tst_info["gen_time"].native
        if gen_time.tzinfo is None:
            gen_time = gen_time.replace(tzinfo=timezone.utc)
        gen_time_ms = int(gen_time.timestamp() * 1000)

        accuracy_ms = None
        if tst_info["accuracy"]:
            acc = tst_info["accuracy"]
            seconds = acc["seconds"].native or 0
            millis = acc["millis"].native or 0
            accuracy_ms = seconds * 1000 + millis

        # The optional tsa field is a GeneralName, usually a directoryName whose native form
        # is the whole RDN mapping. Reduce it to a readable identifier: a record field should
        # be a string, not a serialised name structure. (Not in the preimage, so purely
        # presentational -- the token's serial and policy OID are what identify it.)
        tsa_name = None
        if tst_info["tsa"]:
            native = tst_info["tsa"].native
            if isinstance(native, dict):
                tsa_name = (native.get("common_name") or native.get("organization_name")
                            or next((v for v in native.values() if isinstance(v, str)), None))
            else:
                tsa_name = str(native)

        return TimestampToken(
            gen_time_ms=gen_time_ms,
            serial=int(tst_info["serial_number"].native),
            policy_oid=tst_info["policy"].native,
            hash_alg=tst_info["message_imprint"]["hash_algorithm"]["algorithm"].native,
            message_imprint=tst_info["message_imprint"]["hashed_message"].native,
            signature_alg=sig_alg,
            tsa_name=tsa_name,
            accuracy_ms=accuracy_ms,
            nonce=int(tst_info["nonce"].native) if tst_info["nonce"] else None,
            raw=content_info.dump(),
        )
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"malformed timestamp token: {exc}") from exc


def verify_timestamp_token(der: bytes, *, expected_digest, hash_alg: str = "sha256",
                           nonce: int | None = None, trust_anchors=None) -> TimestampResult:
    """Run the RFC 3161 section 2.4.2 recipient checks against ``expected_digest``.

    Checked here: the response carries no error status, the token parses, its
    ``messageImprint`` equals the digest we asked about, the hash algorithm is the one we
    used, and the nonce matches when one was sent.

    NOT checked unless ``trust_anchors`` is supplied: the TSA's signature and certificate
    chain. ``TimestampResult.signature_verified`` reports which of the two happened, so a
    caller can never read "the token says this" as "the TSA vouched for this".

    The imprint check is the load-bearing one. A token is only evidence about the digest it
    actually covers; a token that verifies against any digest would be worthless.
    """
    try:
        token = parse_timestamp_response(der)
    except TimestampError as exc:
        return TimestampResult(valid=False, failure_reason=str(exc))

    try:
        want = _digest_bytes(expected_digest, hash_alg)
    except TimestampError as exc:
        return TimestampResult(valid=False, token=token, failure_reason=str(exc))

    if token.hash_alg != hash_alg:
        return TimestampResult(valid=False, token=token,
                               failure_reason=f"token hash_alg is {token.hash_alg}, expected {hash_alg}")
    if token.message_imprint != want:
        return TimestampResult(
            valid=False, token=token,
            failure_reason="messageImprint does not cover the expected digest "
                           f"(token covers {token.message_imprint_hex[:16]}..., "
                           f"expected {want.hex()[:16]}...)")
    if nonce is not None and token.nonce != nonce:
        return TimestampResult(valid=False, token=token,
                               failure_reason=f"nonce mismatch: token {token.nonce}, expected {nonce}")

    signature_verified = False
    if trust_anchors is not None:
        signature_verified = _verify_token_signature(token, trust_anchors)
        if not signature_verified:
            return TimestampResult(valid=False, token=token,
                                   failure_reason="TSA signature did not verify against the supplied anchors")

    return TimestampResult(valid=True, token=token, signature_verified=signature_verified)


def _verify_token_signature(token: TimestampToken, trust_anchors) -> bool:
    """Verify the CMS SignerInfo over TSTInfo against caller-supplied anchors.

    Separated so the imprint checks above stay usable with no PKI at all, which is the
    common case for a chain-head stamp that is re-verified inside our own pipeline.
    """
    from asn1crypto import cms as _cms
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509 import load_der_x509_certificate

    try:
        content_info = _cms.ContentInfo.load(token.raw)
        signed_data = content_info["content"]
        signer = signed_data["signer_infos"][0]
        signed_attrs = signer["signed_attrs"]
        if not signed_attrs:
            return False
        # RFC 5652 section 5.4: the signature is over the DER SET OF, not the implicit [0].
        tbs = signed_attrs.dump()
        tbs = b"\x31" + tbs[1:]

        anchors = trust_anchors if isinstance(trust_anchors, (list, tuple)) else [trust_anchors]
        certs = [load_der_x509_certificate(c.dump()) if not isinstance(c, bytes)
                 else load_der_x509_certificate(c) for c in anchors]

        digest_alg = signer["digest_algorithm"]["algorithm"].native
        hash_map = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
        halg = hash_map.get(digest_alg)
        if halg is None:
            return False

        sig = signer["signature"].native
        for cert in certs:
            pub = cert.public_key()
            try:
                if isinstance(pub, rsa.RSAPublicKey):
                    pub.verify(sig, tbs, padding.PKCS1v15(), halg)
                elif isinstance(pub, ec.EllipticCurvePublicKey):
                    pub.verify(sig, tbs, ec.ECDSA(halg))
                else:
                    continue
                return True
            except InvalidSignature:
                continue
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The sidecar binding: a chain-head timestamp, recorded WITHOUT touching the chain
# ---------------------------------------------------------------------------

def chain_timestamp_preimage(*, chain_ref: str, chain_seq: int, issuer_id: str,
                             token: TimestampToken) -> dict:
    """The canonical preimage binding a retention-chain head to a timestamp token.

    Deliberately a SIDECAR. The retention-chain preimage is fixed at four fields and every
    chain_ref already anchored must keep recomputing, so the timestamp references the chain
    by its existing ref instead of being folded into it. Nothing in retention_chain.py
    changes, and no historical digest moves.

    The raw token is NOT in the preimage -- it travels alongside as base64 in the pack. The
    preimage carries the token's identifying fields so that substituting a different token
    changes the ref.
    """
    if not isinstance(chain_seq, int) or isinstance(chain_seq, bool) or chain_seq < 0:
        raise TimestampError("chain_seq must be a non-negative int")
    if not isinstance(issuer_id, str) or not issuer_id:
        raise TimestampError("issuer_id must be a non-empty string")
    if not isinstance(chain_ref, str) or not chain_ref.startswith("sha256:"):
        raise TimestampError('chain_ref must be of the form "sha256:<64-hex>"')

    return {
        "chain_ref": chain_ref,
        "chain_seq": chain_seq,
        "gen_time_ms": token.gen_time_ms,
        "issuer_id": issuer_id,
        "message_imprint_hex": token.message_imprint_hex,
        "tsa_policy_oid": token.policy_oid,
        "tst_serial": token.serial,
    }


def chain_timestamp_ref(preimage: dict) -> str:
    """``"sha256:" + SHA-256(JCS(preimage))`` -- the package's one hashing rule, reused."""
    return "sha256:" + sha256_jcs(preimage)


def build_chain_timestamp(*, chain_ref: str, chain_seq: int, issuer_id: str,
                          token: TimestampToken) -> dict:
    """Build the full sidecar record: preimage, its ref, and the token as base64."""
    preimage = chain_timestamp_preimage(
        chain_ref=chain_ref, chain_seq=chain_seq, issuer_id=issuer_id, token=token)
    return {
        "type": "chain_timestamp_v1",
        "preimage": preimage,
        "chain_timestamp_ref": chain_timestamp_ref(preimage),
        "token_b64": base64.b64encode(token.raw).decode(),
        "signature_alg": token.signature_alg,
        "tsa_name": token.tsa_name,
    }


def verify_chain_timestamp(record: dict, *, chain_ref: str) -> TimestampResult:
    """Re-verify a sidecar record end to end.

    Three things must all hold: the record's ref recomputes from its own preimage, the
    preimage names the chain head we are asking about, and the embedded token actually
    covers that chain head. The third is what stops a valid token for some other chain being
    pasted onto this record.
    """
    try:
        preimage = record["preimage"]
        token_der = base64.b64decode(record["token_b64"])
    except Exception as exc:
        return TimestampResult(valid=False, failure_reason=f"malformed record: {exc}")

    if chain_timestamp_ref(preimage) != record.get("chain_timestamp_ref"):
        return TimestampResult(valid=False, failure_reason="chain_timestamp_ref does not recompute")
    if preimage.get("chain_ref") != chain_ref:
        return TimestampResult(
            valid=False,
            failure_reason=f"record covers {preimage.get('chain_ref')}, asked about {chain_ref}")

    return verify_timestamp_token(token_der, expected_digest=chain_ref)


__all__ = [
    "TimestampError",
    "TimestampToken",
    "TimestampResult",
    "timestamp_request",
    "fetch_timestamp",
    "parse_timestamp_response",
    "verify_timestamp_token",
    "chain_timestamp_preimage",
    "chain_timestamp_ref",
    "build_chain_timestamp",
    "verify_chain_timestamp",
]
