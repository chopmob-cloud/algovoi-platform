"""RecordsVault — the product facade: regulated-records preservation over a Verifiable Archive.

Constructing a ``RecordsVault`` enforces a valid ``algovoi-records-vault`` OEM licence, fail-closed,
exactly as the base :class:`Archive` enforces its own. The vault composes the existing archive engine
with the migration on-ramp (bridge / store), reconciliation, signed manifests, drift detection, and the
Phase-1 evidence layers — RFC-3161 trusted timestamping, a read-access audit log, and legal holds —
no cryptography is reimplemented.

Every evidence layer is an independent append-only, ``signing.make_envelope``-signed,
``prev_entry_hash``-linked signed-chain stream (:class:`_VaultStream`) stored via the same
``StorageBackend`` under its own prefix, signed with the *same* archive identity key — so the one
published public key offline-verifies the archive chain **and** every evidence chain.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from uuid import uuid4

from algovoi_doc_archive import signing
from algovoi_doc_archive.archive import Archive
from algovoi_doc_archive.backend import StorageBackend
from algovoi_doc_archive.models import VerifyChainResult
from algovoi_doc_archive.signer import LocalSigner, Signer

from algovoi_records_vault import licensing
from algovoi_records_vault import migrate as _m

# Evidence-stream entry types + storage prefixes. One stream per concern; all under the same backend.
TSA_TYPE, TSA_PREFIX = "vault_tsa_token", "tsa"
ACCESS_TYPE, ACCESS_PREFIX = "vault_access_event", "access"
HOLD_TYPE, HOLD_PREFIX = "vault_legal_hold", "holds"
KEYRING_TYPE, KEYRING_PREFIX = "vault_keyring", "keyring"
CONSENT_TYPE, CONSENT_PREFIX = "vault_consent_receipt", "consent"
CUSTODY_TYPE, CUSTODY_PREFIX = "vault_custody_manifest", "custody"
ACL_TYPE, ACL_PREFIX = "vault_acl_grant", "acl"
REDACTION_TYPE, REDACTION_PREFIX = "vault_redaction_record", "redaction"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


# Reserved keys the stream always sets itself; a feature's field dict may not override them.
_RESERVED = frozenset(
    {"type", "version", "entry_id", "seq", "prev_entry_hash", "issuer_did", "kid", "recorded_at"}
)


class _VaultStream:
    """A generic append-only, Falcon-1024-signed, hash-linked evidence chain over a storage backend.

    This is :meth:`Archive.notarize`'s head+append loop generalised: each entry is a signed envelope
    stored at ``{prefix}/{seq:012d}.json``; ``{prefix}/head.json`` tracks the tip
    (``seq_count`` / ``last_entry_hash`` / ``last_entry_id``); ``prev_entry_hash`` links each entry to
    ``signing.payload_hash`` of its predecessor. Single-writer per stream, exactly like the archive.
    Every Phase-1 feature is just a ``_VaultStream`` with a different ``entry_type`` and ``prefix``.
    """

    def __init__(self, *, storage: StorageBackend, entry_type: str, prefix: str,
                 signer: Signer | None = None,
                 public_key: bytes | None = None, secret_key: bytes | None = None,
                 issuer_did: str = "did:web:issuer.example.com") -> None:
        # Key custody is pluggable via ``signer``; ``public_key`` (+ optional ``secret_key``) wraps an
        # in-process LocalSigner for backward compatibility. Public-key-only = read-only view.
        if signer is None:
            if public_key is None:
                raise ValueError("provide signer= or public_key=")
            signer = LocalSigner(public_key, secret_key)
        self.storage = storage
        self.signer = signer
        self.pk = signer.public_key()
        self.sk = secret_key
        self.entry_type = entry_type
        self.prefix = prefix.rstrip("/")
        self.issuer_did = issuer_did
        self.kid = signer.kid()

    def _head_key(self) -> str:
        return f"{self.prefix}/head.json"

    def _entry_key(self, seq: int) -> str:
        return f"{self.prefix}/{int(seq):012d}.json"

    async def head(self) -> dict:
        raw = await self.storage.get(self._head_key())
        return json.loads(raw) if raw else {"seq_count": 0, "last_entry_hash": None, "last_entry_id": None}

    async def append(self, fields: dict) -> dict:
        """Append one signed entry carrying ``fields`` (feature-specific payload). Append-only."""
        if not self.signer.can_sign():
            raise RuntimeError(f"{self.prefix} stream is read-only (no signing-capable key/signer); cannot append")
        clash = _RESERVED & set(fields)
        if clash:
            raise ValueError(f"fields may not override reserved keys: {sorted(clash)}")
        head = await self.head()
        seq, prev = head["seq_count"], head["last_entry_hash"]
        eid = str(uuid4())
        payload = {
            **fields,
            "type": self.entry_type, "version": "1", "entry_id": eid, "seq": seq,
            "prev_entry_hash": prev, "issuer_did": self.issuer_did, "kid": self.kid,
            "recorded_at": _iso(_now()),
        }
        envelope = signing.make_envelope_with(payload, self.signer)
        await self.storage.put(self._entry_key(seq), envelope.encode())
        await self.storage.put(self._head_key(), json.dumps(
            {"seq_count": seq + 1, "last_entry_hash": signing.payload_hash(payload),
             "last_entry_id": eid}).encode())
        return {"entry_id": eid, "seq": seq, "prev_entry_hash": prev,
                "envelope": envelope, "payload": payload}

    async def get_entry(self, seq: int) -> str | None:
        raw = await self.storage.get(self._entry_key(seq))
        return raw.decode() if raw else None

    async def get_payload(self, seq: int) -> dict | None:
        env = await self.get_entry(seq)
        if env is None:
            return None
        try:
            return signing.open_envelope(env)[0]
        except Exception as e:  # noqa: BLE001
            raise MalformedEntryError(f"{self.prefix}/{int(seq):012d}.json is malformed: {e}") from e

    async def list_entries(self) -> list[str]:
        head = await self.head()
        out: list[str] = []
        for i in range(head["seq_count"]):
            e = await self.get_entry(i)
            if e is None:
                break
            out.append(e)
        return out

    async def list_payloads(self) -> list[dict]:
        out: list[dict] = []
        for i, e in enumerate(await self.list_entries()):
            try:
                out.append(signing.open_envelope(e)[0])
            except Exception as ex:  # noqa: BLE001
                raise MalformedEntryError(f"{self.prefix}/{i:012d}.json is malformed: {ex}") from ex
        return out

    async def verify_chain(self, *, expected_head: dict | None = None) -> VerifyChainResult:
        """Verify the whole stream and detect truncation/holes.

        An interior deletion is caught here: the persisted head's ``seq_count`` will exceed the length of
        a contiguous scan from ``seq 0`` (``list_entries`` would instead silently stop at the hole, hiding
        every entry after it — e.g. a legal hold). A dropped *trailing* entry is caught against the
        separately-persisted head, and — to defend against an attacker who also rewrites that head blob —
        against a caller-supplied out-of-band ``expected_head`` (``{seq_count, last_entry_hash}``) when given.
        """
        head = await self.head()
        entries: list[str] = []
        i = 0
        while True:
            e = await self.get_entry(i)
            if e is None:
                break
            entries.append(e)
            i += 1
        if int(head.get("seq_count") or 0) != len(entries):
            return VerifyChainResult(valid=False, length=len(entries), broken_at=len(entries),
                                     reason="missing_entry")
        anchor = expected_head or {"seq_count": head.get("seq_count"),
                                   "last_entry_hash": head.get("last_entry_hash")}
        return verify_stream(entries, self.pk, self.entry_type, expected_head=anchor)


class MalformedEntryError(ValueError):
    """Raised when a stored stream entry cannot be opened (corrupt, truncated, or foreign envelope).

    The whole-chain ``verify_chain`` already fails closed on such an entry; this gives the convenience
    *read* helpers (``get_payload`` / ``list_payloads``) the same clear, located failure instead of a
    bare JSON/parse exception, so one bad entry surfaces as a diagnosable error rather than an opaque
    crash deep inside a caller.
    """


class ChainIntegrityError(RuntimeError):
    """Raised when an access/consent/hold decision is requested over an evidence stream whose signed
    chain fails offline verification.

    A decision method (``ACLRegistry.check``, ``ConsentLedger.is_authorized``,
    ``LegalHoldRegistry.is_held`` …) must never return a benign ``allow``/``deny`` boolean computed
    from a chain that was altered, reordered, truncated, or signed by the wrong key — that would let a
    tampered stream masquerade as a legitimate decision. The fail-closed guard raises this instead.
    """


async def ensure_chain_valid(stream: "_VaultStream", name: str) -> VerifyChainResult:
    """Fail-closed guard: verify ``stream``'s signed chain before a decision is read from it.

    Returns the :class:`VerifyChainResult` on success; raises :class:`ChainIntegrityError` if the
    chain was altered, inserted into, removed from, reordered, or signed by the wrong key.
    """
    res = await stream.verify_chain()
    if not res.valid:
        raise ChainIntegrityError(
            f"{name} chain failed verification: {res.reason} (broken_at={res.broken_at})")
    return res


def verify_stream(envelopes: list[str], public_key: bytes, entry_type: str, *,
                  expected_head: dict | None = None) -> VerifyChainResult:
    """Offline whole-chain verification of a :class:`_VaultStream` (pure, never raises).

    A pass proves no entry of this stream was altered, inserted, reordered, or back-dated — using only
    the published public key and the exported envelopes. On its own it does **not** prove nothing was
    TRUNCATED: dropping trailing entries yields a shorter chain that still links cleanly. Pass
    ``expected_head`` (``{seq_count, last_entry_hash}`` recorded out-of-band) to detect a removed tail —
    the verified length and head must then match it.
    """
    prev: str | None = None
    for i, r in enumerate(envelopes):
        try:
            payload, sig, _ = signing.open_envelope(r)
        except Exception:  # noqa: BLE001
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="malformed_entry")
        if payload.get("type") != entry_type:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="wrong_type")
        if not signing.verify_payload(payload, sig, public_key):
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="bad_signature")
        if payload.get("seq") != i:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="seq_mismatch")
        if payload.get("prev_entry_hash") != prev:
            return VerifyChainResult(valid=False, length=i, broken_at=i, reason="chain_break")
        prev = signing.payload_hash(payload)
    # SECURITY (2026-08-19): truncation guard — a clean prefix is not a clean whole. When the caller
    # pins the head out-of-band, require length + head to match so a dropped tail is caught.
    if expected_head is not None:
        exp_n = expected_head.get("seq_count")
        exp_head = expected_head.get("last_entry_hash")
        if exp_n is not None and len(envelopes) != int(exp_n):
            return VerifyChainResult(valid=False, length=len(envelopes), broken_at=len(envelopes),
                                     reason="length_mismatch", head_receipt_hash=prev)
        if exp_head is not None and prev != exp_head:
            return VerifyChainResult(valid=False, length=len(envelopes), broken_at=len(envelopes),
                                     reason="head_mismatch", head_receipt_hash=prev)
    return VerifyChainResult(valid=True, length=len(envelopes), head_receipt_hash=prev)


class RecordsVault:
    """Facade over a Verifiable Archive for regulated-records migration + preservation.

    Pass an :class:`Archive` (the storage + crypto). Provide ``signing_secret_key`` +
    ``signing_public_key`` if you want to emit signed migration manifests (typically the archive's own
    identity keys). The evidence streams (timestamping / access log / legal holds) are signed with the
    archive's *own* identity key, so the archive's published public key verifies everything. The licence
    gate runs in ``__init__`` — no valid licence, no vault.
    """

    def __init__(self, *, archive: Archive,
                 signing_secret_key: bytes | None = None,
                 signing_public_key: bytes | None = None,
                 tsa_url: str | None = None,
                 edition: str | None = None) -> None:
        licensing.require_license()  # fail-closed
        self.archive = archive
        self._sk = signing_secret_key
        self._pk = signing_public_key
        # explicit arg wins; else env VAULT_TSA_URL; else None -> air-gap NoopTsaClient
        self._tsa_url = tsa_url if tsa_url is not None else (os.environ.get("VAULT_TSA_URL") or None)
        # optional vertical preset (health | legal): supplies retention/hold defaults
        from algovoi_records_vault.editions import edition as _edition
        self.edition = _edition(edition) if edition else None

    # ----- migration on-ramp (Phase 0) -------------------------------------------------------
    async def migrate(self, source: _m.Source, *, mode: str = "bridge",
                      skip_existing: bool = True) -> _m.MigrationResult:
        """Migrate every record from ``source`` into the archive (``bridge`` hash-only or ``store``)."""
        return await _m.migrate(self.archive, source, mode=mode, skip_existing=skip_existing)

    async def reconcile(self, source: _m.Source) -> dict:
        """Reconcile a source inventory against the chain; returns an unsigned manifest dict."""
        return await _m.reconcile(self.archive, source)

    def sign_manifest(self, manifest: dict) -> str:
        """Falcon-1024-sign a reconciliation manifest into an offline-verifiable envelope."""
        if self._sk is None or self._pk is None:
            raise RuntimeError(
                "RecordsVault needs signing_secret_key + signing_public_key to sign a manifest")
        return _m.sign_manifest(manifest, self._sk, self._pk)

    @staticmethod
    def verify_manifest(manifest_envelope: str, public_key: bytes) -> bool:
        """Offline verification of a signed migration manifest (public key only)."""
        return _m.verify_manifest(manifest_envelope, public_key)

    async def detect_drift(self, source: _m.Source) -> list[dict]:
        """Flag bridged records whose source bytes changed after notarisation."""
        return await _m.detect_drift(self.archive, source)

    # ----- evidence streams (Phase 1) --------------------------------------------------------
    def _stream(self, entry_type: str, prefix: str) -> _VaultStream:
        # Thread the archive's signer (any custody: local / HSM / KMS / Vault) into every stream.
        return _VaultStream(storage=self.archive.storage, signer=self.archive.signer,
                            entry_type=entry_type, prefix=prefix, issuer_did=self.archive.issuer_did)

    def timestamper(self):
        """F1 — RFC-3161 trusted timestamper bound to the ``tsa/`` stream.

        Uses ``RequestTsaClient(tsa_url)`` when a TSA URL is configured (constructor arg or
        ``VAULT_TSA_URL``), else the air-gap :class:`NoopTsaClient`.
        """
        from algovoi_records_vault.timestamp import NoopTsaClient, RequestTsaClient, Timestamper
        client = RequestTsaClient(self._tsa_url) if self._tsa_url else NoopTsaClient()
        return Timestamper(stream=self._stream(TSA_TYPE, TSA_PREFIX), client=client)

    def access_log(self):
        """F3 — read-access audit log bound to the ``access/`` stream, wrapping ``retrieve``."""
        from algovoi_records_vault.access_log import AccessLog
        return AccessLog(stream=self._stream(ACCESS_TYPE, ACCESS_PREFIX), archive=self.archive)

    def holds(self, *, retention_days: int | None = None, bridge=None, use_env_bridge: bool = True):
        """F2 — legal-hold / e-discovery-hold registry bound to the ``holds/`` stream.

        If ``bridge`` is given (or ``use_env_bridge`` and ``VAULT_GDPR_BRIDGE_URL``/``_TOKEN`` are set),
        placing/releasing a payer-subject hold also mirrors the operational ``legal_hold`` gate onto the
        control_plane payment ledger (best-effort; the signed chain stays the system-of-record).
        """
        from algovoi_records_vault.legal_hold import LegalHoldRegistry, RetentionPolicy
        if retention_days is None and self.edition is not None:
            retention_days = self.edition.hold_preservation_days
        retention = RetentionPolicy(retention_days) if retention_days is not None else None
        if bridge is None and use_env_bridge:
            from algovoi_records_vault.gdpr_bridge import bridge_from_env
            bridge = bridge_from_env()
        return LegalHoldRegistry(stream=self._stream(HOLD_TYPE, HOLD_PREFIX), retention=retention,
                                 bridge=bridge)

    def keyring(self):
        """F7 — key archival + rotation-proof registry bound to the ``keyring/`` stream."""
        from algovoi_records_vault.keyring import Keyring
        return Keyring(stream=self._stream(KEYRING_TYPE, KEYRING_PREFIX))

    def consent(self):
        """F5 — consent-receipt ledger bound to the ``consent/`` stream."""
        from algovoi_records_vault.consent import ConsentLedger
        return ConsentLedger(stream=self._stream(CONSENT_TYPE, CONSENT_PREFIX))

    def custody(self):
        """F6 — chain-of-custody manifest log bound to the ``custody/`` stream."""
        from algovoi_records_vault.custody import CustodyLog
        return CustodyLog(stream=self._stream(CUSTODY_TYPE, CUSTODY_PREFIX))

    def acl(self):
        """F8 — fine-grained access-control registry bound to the ``acl/`` stream."""
        from algovoi_records_vault.acl import ACLRegistry
        return ACLRegistry(stream=self._stream(ACL_TYPE, ACL_PREFIX))

    def redaction(self):
        """F4 — redaction / crypto-shred ledger bound to the ``redaction/`` stream."""
        from algovoi_records_vault.redaction import RedactionLedger
        return RedactionLedger(stream=self._stream(REDACTION_TYPE, REDACTION_PREFIX))

    async def notarize(self, *, time_stamp: bool = True, **kwargs) -> dict:
        """Notarize a document into the archive and (by default) trusted-timestamp the receipt.

        Returns ``{"archive": <archive entry>, "tsa": <tsa stream entry or None>}``. The base archive
        receipt is unchanged; the timestamp token lives in the parallel ``tsa/`` stream.
        """
        entry = await self.archive.notarize(**kwargs)
        tsa = None
        if time_stamp:
            tsa = await self.timestamper().stamp(
                receipt_envelope=entry["receipt"], archive_seq=entry["seq"],
                archive_entry_id=entry["entry_id"])
        return {"archive": entry, "tsa": tsa}

    async def retrieve(self, *, doc_hash: str, principal=None, reason: str = "") -> bytes:
        """Retrieve a stored document, logging a signed access event (granted or denied) first."""
        return await self.access_log().retrieve(doc_hash=doc_hash, principal=principal, reason=reason)

    # ----- whole-vault offline verification --------------------------------------------------
    async def verify_chain(self):
        """Base archive chain integrity + ordering, offline, delegated to the engine."""
        return await self.archive.verify_chain()

    async def verify_all_chains(self) -> dict:
        """Verify the archive chain and every evidence stream; returns ``{name: VerifyChainResult}``."""
        out = {"archive": await self.archive.verify_chain()}
        for name, (etype, prefix) in {
            "tsa": (TSA_TYPE, TSA_PREFIX), "access": (ACCESS_TYPE, ACCESS_PREFIX),
            "holds": (HOLD_TYPE, HOLD_PREFIX), "keyring": (KEYRING_TYPE, KEYRING_PREFIX),
            "consent": (CONSENT_TYPE, CONSENT_PREFIX), "custody": (CUSTODY_TYPE, CUSTODY_PREFIX),
            "acl": (ACL_TYPE, ACL_PREFIX), "redaction": (REDACTION_TYPE, REDACTION_PREFIX),
        }.items():
            out[name] = await self._stream(etype, prefix).verify_chain()
        return out
