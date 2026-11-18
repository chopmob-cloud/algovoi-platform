"""
substrate2.rfc9421_verifier — RFC 9421 HTTP Message Signature verification + RFC 9530.

Reconstructs the signing base from request components and the Signature-Input header,
verifies the Ed25519 signature, and checks the Content-Digest. Supports mode "rfc9421"
(default; @method case-preserved, @signature-params line appended) and "algovoi-v0"
(legacy; @method lowercased, no @signature-params line). Validated against the verifier
fixtures (FIXTURE_SIGNING_BASE_V0 / _RFC9421). Not derived from v1 source. See PROVENANCE.md.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .freshness import FreshnessError, check_freshness
from .rfc9421_keycheck import WeakKeyError, check_ed25519_public_key


class SignatureInputParseError(ValueError):
    pass


class SigningBaseError(ValueError):
    pass


class ContentDigestError(ValueError):
    pass


class VerifyError(ValueError):
    pass


@dataclass
class ParsedSignatureInput:
    label: str
    covered_components: list
    parameters: dict
    raw: str
    params_block: str


@dataclass
class VerifyResult:
    valid: bool = False
    signature_valid: bool = False
    content_digest_valid: bool = False
    signing_base: str = ""
    covered_components: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    label: str = ""
    errors: list = field(default_factory=list)


def _count_top_level_component_lists(raw: str) -> int:
    """Count component lists that open at bracket depth 0, ignoring quoted text.

    A Signature-Input dictionary has one member per signature, each opening its
    covered-component list with a top-level ``(``. More than one means the header
    carries multiple signatures; the verifier refuses to silently pick one
    (label-confusion / signature-injection hardening, RC-9).
    """
    depth = 0
    in_quote = False
    prev = ""
    lists = 0
    for ch in raw:
        if ch == '"' and prev != "\\":
            in_quote = not in_quote
        elif not in_quote:
            if ch == "(":
                if depth == 0:
                    lists += 1
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
        prev = ch
    return lists


def parse_signature_input(header_value: str) -> ParsedSignatureInput:
    raw = (header_value or "").strip()
    if not raw:
        raise SignatureInputParseError("empty Signature-Input")
    # RC-9: refuse multi-signature headers. An attacker who can append a second
    # signature they control must not be able to have the verifier reconstruct and
    # check the wrong one; a single, unambiguous signature is required.
    if _count_top_level_component_lists(raw) > 1:
        raise SignatureInputParseError(
            "multiple signatures in Signature-Input are not supported; "
            "supply exactly one"
        )
    if raw.startswith("("):
        label, rest = "", raw
    else:
        eq = raw.find("=(")
        if eq < 0:
            raise SignatureInputParseError(f"no component list in {raw!r}")
        label, rest = raw[:eq], raw[eq + 1:]
    if not rest.startswith("("):
        raise SignatureInputParseError("component list must start with '('")
    close = rest.find(")")
    if close < 0:
        raise SignatureInputParseError("unterminated component list")
    comp_str = rest[1:close]
    params_str = rest[close + 1:]
    covered = re.findall(r'"([^"]*)"', comp_str)
    # RC-9: a covered component identifier MUST NOT appear more than once
    # (RFC 9421 §2.1). A duplicate makes the signing base ambiguous, so reject.
    seen_components: set = set()
    for comp in covered:
        key = comp.lower()
        if key in seen_components:
            raise SignatureInputParseError(
                f"duplicate covered component: {comp!r}"
            )
        seen_components.add(key)
    parameters: dict = {}
    for part in params_str.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        v = v.strip()
        # RC-9: duplicate parameters are a structured-field violation and a
        # last-wins ambiguity (e.g. two `created` or two `alg`); reject instead
        # of silently overwriting.
        if k in parameters:
            raise SignatureInputParseError(
                f"duplicate signature parameter: {k!r}"
            )
        if v.startswith('"') and v.endswith('"'):
            parameters[k] = v[1:-1]
        else:
            try:
                parameters[k] = int(v)
            except ValueError:
                parameters[k] = v
    return ParsedSignatureInput(label=label, covered_components=covered, parameters=parameters, raw=raw, params_block=rest)


def parse_signature_value(header_value: str):
    raw = (header_value or "").strip()
    if "=:" not in raw or not raw.endswith(":"):
        raise SignatureInputParseError("Signature must be of the form label=:base64:")
    label = raw[:raw.index("=:")]
    b64 = raw[raw.index("=:") + 2:-1]
    try:
        # RC-9: validate=True rejects any non-alphabet byte. This is what turns a
        # multi-member Signature header (`sig1=:..:, sig2=:..:`) into an error
        # rather than a silently truncated/garbage decode: the extra `:, sig2=:`
        # is not valid base64.
        sig_bytes = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise SignatureInputParseError(f"signature base64 invalid: {exc}") from exc
    # RC-9 (malleability): validate=True checks the alphabet but not that the
    # trailing pad bits are zero, so many distinct header strings decode to the
    # same signature bytes and would all verify. That breaks any replay/idempotency
    # key derived from the raw Signature header. Require the canonical encoding to
    # round-trip exactly. (Parity with algovoi-rfc9421-verifier.)
    if base64.b64encode(sig_bytes).decode("ascii") != b64:
        raise SignatureInputParseError(
            "signature value is not canonical base64 (non-zero pad bits)"
        )
    return label, sig_bytes


def _component_value(comp, *, mode, method, authority, path, scheme, headers, parameters):
    if comp == "@method":
        return method if mode == "rfc9421" else method.lower()
    if comp == "@authority":
        return authority.lower()
    if comp == "@path":
        return path
    if comp == "@scheme":
        return scheme
    if comp == "created":
        return str(parameters["created"])
    if comp == "expires":
        if "expires" not in parameters:
            raise SigningBaseError("'expires' covered but no 'expires' parameter in Signature-Input")
        return str(parameters["expires"])
    if comp.startswith("@"):
        raise SigningBaseError(f"unsupported derived component: {comp}")
    value = headers.get(comp, headers.get(comp.lower()))
    if value is None:
        raise SigningBaseError(f"missing covered component: {comp}")
    return value


def build_signing_base(covered_components, *, method=None, authority=None, path=None, headers=None, parameters=None, mode="rfc9421", signature_params_raw=None, scheme="https") -> str:
    headers = headers or {}
    parameters = parameters or {}
    lines = [
        f'"{c}": {_component_value(c, mode=mode, method=method, authority=authority, path=path, scheme=scheme, headers=headers, parameters=parameters)}'
        for c in covered_components
    ]
    if mode == "rfc9421":
        if signature_params_raw is None:
            raise SigningBaseError("signature_params_raw is required in rfc9421 mode")
        lines.append(f'"@signature-params": {signature_params_raw}')
    return "\n".join(lines)


def compute_content_digest(body: bytes, alg: str = "sha-256") -> str:
    if alg != "sha-256":
        raise ContentDigestError(f"unsupported content-digest algorithm: {alg}")
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def verify_content_digest(body: bytes, cd_header: str, require_algorithm: str | None = None) -> bool:
    if cd_header != compute_content_digest(body):
        raise ContentDigestError("content-digest mismatch")
    return True


def verify_signature(signing_base: str, signature_bytes: bytes, public_key, *, algorithm: str = "ed25519") -> bool:
    if algorithm != "ed25519":
        return False
    pk = bytes.fromhex(public_key) if isinstance(public_key, str) else bytes(public_key)
    # Trust-boundary key gate (parity with algovoi-rfc9421-verifier): reject
    # non-canonical, off-curve, and small-order public keys BEFORE verification.
    # A basic Ed25519 verify can accept small-order keys, enabling signature
    # malleability / cross-key classes; for an offline verifier that trusts the
    # resolved key as the anchor, that is a defect. Fail closed (return False).
    try:
        check_ed25519_public_key(pk)
    except WeakKeyError:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(signature_bytes, signing_base.encode("utf-8"))
        return True
    except Exception:
        return False


def verify_request(
    *,
    method,
    authority,
    path,
    headers,
    body=b"",
    public_key,
    scheme="https",
    mode="rfc9421",
    require_content_digest=True,
    require_algorithm=None,
    now=None,
    max_age_seconds=None,
    max_skew_seconds=60,
    enforce_expires=True,
    require_created=False,
    expected_tag=None,
    require_tag=False,
    allowed_algorithms=frozenset({"ed25519"}),
    nonce_seen=None,
    required_components=None,
) -> VerifyResult:
    errors = []
    # RC-7: pin the signing-base mode. `mode` is caller-supplied (never taken from
    # the wire), but an unknown value is a caller bug that must fail closed rather
    # than fall through build_signing_base with legacy semantics.
    if mode not in ("rfc9421", "algovoi-v0"):
        return VerifyResult(valid=False, errors=[f"unknown signing-base mode: {mode!r}"])
    # RFC 9421 / RFC 9110 header field names are case-insensitive. Normalise the
    # incoming header keys to lowercase so a caller sending "Signature-Input"
    # (e.g. the gibberlink VAL envelope) verifies the same as "signature-input".
    # The real algovoi-rfc9421-verifier normalises; the substrate2 compat-shim
    # verifier must match it or capitalised-header callers fail closed spuriously.
    headers = {str(k).lower(): v for k, v in (headers or {}).items()}
    if "signature-input" not in headers:
        return VerifyResult(valid=False, errors=["missing Signature-Input header"])
    if "signature" not in headers:
        return VerifyResult(valid=False, errors=["missing Signature header"])
    try:
        si = parse_signature_input(headers["signature-input"])
        label, sig_bytes = parse_signature_value(headers["signature"])
    except SignatureInputParseError as exc:
        return VerifyResult(valid=False, errors=[f"Signature-Input parse error: {exc}"])

    # RC-9: the Signature and Signature-Input labels must agree. When both are
    # present (RFC 9421 labelled form) a mismatch means the covered-component list
    # and the signature bytes belong to different members -> reject. The lenient
    # unlabelled Signature-Input form (si.label == "") cannot be cross-checked, so
    # it is left to the single-signature guard above.
    if si.label and label and si.label != label:
        return VerifyResult(
            valid=False,
            covered_components=si.covered_components,
            parameters=si.parameters,
            label=si.label,
            errors=[
                f"Signature label {label!r} does not match "
                f"Signature-Input label {si.label!r}"
            ],
        )

    # RC-1: caller policy on covered-component completeness. The library returns the
    # covered list either way; when the caller pins a required set (e.g. @method,
    # @authority, @path), a signature that omits any of them is rejected here rather
    # than trusting a narrowly-scoped signature over a rewritten request line.
    if required_components:
        covered_lower = {c.strip().strip('"').lower() for c in si.covered_components}
        missing = [c for c in required_components if c.strip().lower() not in covered_lower]
        if missing:
            return VerifyResult(
                valid=False,
                covered_components=si.covered_components,
                parameters=si.parameters,
                label=si.label,
                errors=[f"required covered components missing: {sorted(missing)}"],
            )

    def _fail(msg, **extra):
        kw = dict(
            valid=False,
            covered_components=si.covered_components,
            parameters=si.parameters,
            label=si.label,
            errors=[msg],
        )
        kw.update(extra)
        return VerifyResult(**kw)

    # Freshness / replay window (item 1). Runs before the cryptographic check so a
    # stale or expired signature is rejected regardless of whether its bytes would
    # verify. Only covered (signed) created/expires are trusted; see freshness.py.
    if now is None:
        now = int(time.time())
    try:
        check_freshness(
            si.parameters,
            si.covered_components,
            now=now,
            max_age_seconds=max_age_seconds,
            max_skew_seconds=max_skew_seconds,
            enforce_expires=enforce_expires,
            require_created=require_created,
            params_signed=(mode == "rfc9421"),
        )
    except FreshnessError as exc:
        return _fail(f"Freshness check failed: {exc}")

    # Anti cross-protocol reuse via the RFC 9421 `tag` parameter (item 2). `tag` rides
    # inside @signature-params, which is signed verbatim, so a present tag is already
    # cryptographically bound; here we enforce the caller's policy on it.
    tag_value = si.parameters.get("tag")
    if require_tag and tag_value is None:
        return _fail("Signature 'tag' parameter required but absent")
    if expected_tag is not None and tag_value != expected_tag:
        return _fail(
            f"Signature 'tag' {tag_value!r} does not match expected {expected_tag!r}"
        )

    try:
        base = build_signing_base(
            si.covered_components, method=method, authority=authority, path=path,
            headers=headers, parameters=si.parameters, mode=mode,
            signature_params_raw=si.params_block, scheme=scheme,
        )
    except SigningBaseError as exc:
        return VerifyResult(valid=False, covered_components=si.covered_components, parameters=si.parameters, label=si.label, errors=[f"signing_base: {exc}"])

    # Algorithm-downgrade hardening (item 3). Do NOT default a missing alg to ed25519:
    # an absent alg is ambiguous and a downgrade-by-omission vector, so reject it. Then
    # pin the alg to the caller's allow-list before verifying.
    alg = si.parameters.get("alg")
    if alg is None:
        return _fail("Signature-Input missing 'alg' parameter", signing_base=base)
    if not isinstance(alg, str):
        return _fail(
            f"Signature-Input 'alg' parameter must be string, got {type(alg).__name__}",
            signing_base=base,
        )
    if alg.lower() not in {a.lower() for a in allowed_algorithms}:
        return _fail(
            f"Signature algorithm {alg!r} is not in the allowed set "
            f"{sorted(allowed_algorithms)}",
            signing_base=base,
        )

    sig_valid = verify_signature(base, sig_bytes, public_key, algorithm=alg)
    if not sig_valid:
        errors.append("signature invalid")

    # Single-use nonce / replay check (item 1). Deferred until after the signature
    # verifies so the caller's store is only ever probed with an authentic message. The
    # caller records the nonce on success; this library stays stateless and only asks
    # "has this (nonce, keyid) been seen?".
    if sig_valid and nonce_seen is not None:
        nonce_value = si.parameters.get("nonce")
        if nonce_value is not None:
            keyid_value = str(si.parameters.get("keyid", ""))
            try:
                already = nonce_seen(str(nonce_value), keyid_value)
            except Exception as exc:  # a store failure must fail closed, not open
                return _fail(
                    f"Nonce store check errored: {exc}",
                    signature_valid=True,
                    signing_base=base,
                )
            if already:
                return _fail(
                    "Signature nonce has already been used (replay)",
                    signature_valid=True,
                    signing_base=base,
                )

    cd_valid = True
    if require_content_digest:
        # The point of require_content_digest is to guarantee the body is bound to the signature. If
        # the signature does not cover content-digest, the body is unbound and we must reject — not
        # silently pass. (Coverage comes from the signed @signature-params, so an attacker cannot add
        # it after the fact; a signer that legitimately omitted it simply fails this stricter check.)
        if "content-digest" not in si.covered_components:
            cd_valid = False
            errors.append("content-digest required but not covered by the signature")
        elif "content-digest" not in headers:
            cd_valid = False
            errors.append("missing Content-Digest header")
        else:
            try:
                cd_valid = verify_content_digest(body, headers["content-digest"], require_algorithm)
            except ContentDigestError as exc:
                cd_valid = False
                errors.append(f"Content-Digest mismatch: {exc}")

    return VerifyResult(
        valid=sig_valid and cd_valid,
        signature_valid=sig_valid,
        content_digest_valid=cd_valid,
        signing_base=base,
        covered_components=si.covered_components,
        parameters=si.parameters,
        label=si.label or label,
        errors=errors,
    )


__all__ = [
    "SignatureInputParseError", "SigningBaseError", "ContentDigestError", "VerifyError",
    "FreshnessError", "check_freshness",
    "WeakKeyError", "check_ed25519_public_key",
    "ParsedSignatureInput", "VerifyResult", "parse_signature_input", "parse_signature_value",
    "build_signing_base", "compute_content_digest", "verify_content_digest",
    "verify_signature", "verify_request",
]
