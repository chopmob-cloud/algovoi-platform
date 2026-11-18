"""
The Travel Rule engine — turn a FATF Recommendation 16 obligation into a signed, **no-PII**,
offline-verifiable Travel Rule receipt, and exchange the IVMS101 PII payload **post-quantum**.

The pattern matches the rest of the suite (cf. Compliance Gate): the regulated data is content-addressed
and the *attestation* is what's signed. The IVMS101 payload (the PII) is sealed to the counterparty
VASP's ML-KEM key and exchanged confidentially; the receipt carries only `ivms101_hash =
sha256(JCS(ivms101))`, the VASP DIDs, the threshold determination, and the result — never the PII.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import substrate2

from algovoi_travel_rule import licensing, signing
from algovoi_travel_rule.encryption import HybridPqcEncryptor

_RESULTS = {"PREPARED", "SENT", "RECEIVED", "ACKNOWLEDGED"}
_DIRECTIONS = {"originator", "beneficiary"}


class TravelRuleError(RuntimeError):
    """Raised on an invalid request (e.g. Travel Rule applies but no IVMS101 payload supplied)."""


def _as_dict(ivms101) -> dict:
    return ivms101.model_dump(exclude_none=True) if hasattr(ivms101, "model_dump") else dict(ivms101)


def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


class TravelRule:
    """Certify a transfer's Travel Rule status as a Falcon-1024-signed, no-PII receipt.

    The receipt format binds into the Substrate 2 evidence chain like every other suite receipt
    (`canon_version: jcs-rfc8785-v1`, content hashes, Falcon-1024 signature). Verification is offline
    from the issuer public key alone.
    """

    def __init__(
        self,
        *,
        secret_key: bytes,
        public_key: bytes,
        originating_vasp_did: str,
        threshold_currency: str = "USD",
        threshold_amount_minor: int = 100_000,   # FATF de-minimis ~ $1,000.00
    ) -> None:
        licensing.require_license()               # fail-closed: no valid AlgoVoi OEM licence -> refuse
        self.sk = secret_key
        self.pk = public_key
        self.vasp_did = originating_vasp_did
        self.threshold_currency = threshold_currency
        self.threshold_amount_minor = int(threshold_amount_minor)
        self.kid = signing.kid_for(public_key)

    def applies(self, *, amount_minor: int, currency: str) -> bool:
        """Whether the Travel Rule applies to a transfer (at/above the configured de-minimis)."""
        return currency == self.threshold_currency and int(amount_minor) >= self.threshold_amount_minor

    def certify(
        self,
        *,
        transfer_ref: str,
        beneficiary_vasp_did: str,
        amount_minor: int,
        currency: str,
        ivms101=None,
        direction: str = "originator",
        result: str = "PREPARED",
    ) -> dict:
        """Produce the signed, no-PII Travel Rule receipt for a transfer."""
        if direction not in _DIRECTIONS:
            raise TravelRuleError(f"direction must be one of {_DIRECTIONS}")
        if result not in _RESULTS:
            raise TravelRuleError(f"result must be one of {_RESULTS}")
        # SECURITY (2026-08-19): the de-minimis threshold is value-based in a specific currency. When the
        # transfer is denominated in a DIFFERENT unit (e.g. an asset symbol like "ETH"), we cannot compare
        # it to the threshold without a conversion, so we must NOT silently return applies=False — that
        # would skip the originator/beneficiary PII exchange for essentially every asset-denominated crypto
        # transfer while still signing a "not applicable" receipt a regulator reads as compliant. Refuse
        # instead: the operator must configure a threshold in the transfer's own unit (per-asset threshold)
        # or supply a converted amount.
        if currency != self.threshold_currency:
            raise TravelRuleError(
                f"transfer currency {currency!r} is not the threshold currency {self.threshold_currency!r}; "
                f"cannot evaluate the value-based Travel Rule de-minimis across units. Configure a threshold "
                f"in {currency!r} (per-asset) or convert the amount first — refusing to certify a "
                f"non-applicability verdict without a comparable value")
        applies = self.applies(amount_minor=amount_minor, currency=currency)
        if applies and ivms101 is None:
            raise TravelRuleError("Travel Rule applies to this transfer but no IVMS101 payload was supplied")
        ivms_hash = signing.payload_hash(_as_dict(ivms101)) if ivms101 is not None else None

        receipt: dict = {
            "canon_version": "jcs-rfc8785-v1",
            "transfer_ref": transfer_ref,
            "originating_vasp_did": self.vasp_did,
            "beneficiary_vasp_did": beneficiary_vasp_did,
            "transfer_amount": {"currency": currency, "amount_minor": int(amount_minor)},
            "threshold": {"currency": self.threshold_currency, "amount_minor": self.threshold_amount_minor},
            "applies": applies,
            "direction": direction,
            "result": result,
            "issued_at_ms": _now_ms(),
        }
        if ivms_hash is not None:
            receipt["ivms101_hash"] = ivms_hash    # binds the data WITHOUT carrying it

        envelope = signing.make_envelope(receipt, self.sk, self.pk)
        return {
            "receipt": receipt,
            "receipt_envelope": envelope,
            "receipt_hash": signing.payload_hash(receipt),
            "applies": applies,
            "ivms101_hash": ivms_hash,
            "kid": self.kid,
        }

    # ---- PQC IVMS101 exchange (the PII goes confidential, post-quantum) -----------------
    @staticmethod
    def seal_ivms101(*, ivms101, beneficiary_mlkem_pubkey: bytes) -> str:
        """Encrypt the IVMS101 payload to the beneficiary VASP's ML-KEM public key for exchange.

        ML-KEM-1024 + AES-256-GCM — confidential and post-quantum. Only the beneficiary VASP (holding
        the matching secret) can open it; the sealed blob plus the receipt's `ivms101_hash` lets the
        recipient confirm they received exactly the data that was attested.
        """
        blob = HybridPqcEncryptor(beneficiary_mlkem_pubkey).encrypt(substrate2.canonicalize_bytes(_as_dict(ivms101)))
        return signing.b64u_encode(blob)

    @staticmethod
    def open_ivms101(*, sealed_b64: str, mlkem_secret: bytes) -> dict:
        """Beneficiary side: decrypt a sealed IVMS101 payload with the VASP's ML-KEM secret key."""
        raw = HybridPqcEncryptor(b"", mlkem_secret).decrypt(signing.b64u_decode(sealed_b64))
        return json.loads(raw)
