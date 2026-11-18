"""The Verifiable Archive engine: content-address → encrypt → sign → append to a hash-linked chain."""
from __future__ import annotations

from algovoi_doc_archive import licensing

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from algovoi_doc_archive import signing
from algovoi_doc_archive.backend import StorageBackend
from algovoi_doc_archive.encryption import Encryptor
from algovoi_doc_archive.models import VerifyChainResult
from algovoi_doc_archive.signer import LocalSigner, Signer
from algovoi_doc_archive.verifier import verify_chain as _verify_chain

_HEAD = "archive/head.json"


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


class Archive:
    """Append-only, tamper-evident, encrypted document archive over a pluggable storage backend.

    Each entry binds a document's content hash into a Falcon-1024-signed receipt that links to the
    previous entry (``prev_receipt_hash``), forming an offline-verifiable chain. Documents are
    encrypted by ``encryptor`` **before** they reach the backend, so storage only ever sees
    ciphertext. ``notarize`` is append-only and assumes a single writer per archive.
    """

    def __init__(
        self,
        *,
        public_key: bytes | None = None,
        storage: StorageBackend,
        secret_key: bytes | None = None,
        encryptor: Encryptor | None = None,
        signer: Signer | None = None,
        issuer_did: str = "did:web:issuer.example.com",
    ) -> None:
        licensing.require_license()   # fail-closed: no valid AlgoVoi OEM licence -> refuse
        # Key custody is pluggable via ``signer`` (HSM / KMS / Vault). For backward compatibility,
        # ``public_key`` (+ optional ``secret_key``) wraps an in-process LocalSigner. Omit both
        # secret_key and a signing-capable signer for a read-only / audit view (verify, list, retrieve).
        if signer is None:
            if public_key is None:
                raise ValueError("provide signer= or public_key=")
            signer = LocalSigner(public_key, secret_key)
        self.signer = signer
        self.sk = secret_key            # retained for backward compatibility (may be None)
        self.pk = signer.public_key()
        self.storage = storage
        self.enc = encryptor
        self.issuer_did = issuer_did
        self.kid = signer.kid()

    async def head(self) -> dict:
        raw = await self.storage.get(_HEAD)
        return json.loads(raw) if raw else {"seq_count": 0, "last_receipt_hash": None, "last_entry_id": None}

    async def notarize(
        self,
        *,
        data: bytes | None = None,
        doc_hash: str | None = None,
        title: str = "",
        content_type: str = "application/octet-stream",
        metadata: dict | None = None,
    ) -> dict:
        """Archive a document. Pass ``data`` to store (encrypted), or ``doc_hash`` alone to notarize
        existence without storing the document."""
        if not self.signer.can_sign():
            raise RuntimeError("Archive is read-only (no signing-capable key/signer); cannot notarize")
        if data is None and not doc_hash:
            raise ValueError("provide data or doc_hash")

        stored, enc_alg, doc_size = False, "none", None
        if data is not None:
            h = _sha(data)
            if doc_hash and doc_hash != h:
                raise ValueError("doc_hash does not match data")
            doc_hash, doc_size = h, len(data)
            blob = self.enc.encrypt(data) if self.enc is not None else data
            enc_alg = self.enc.alg if self.enc is not None else "none"
            await self.storage.put(f"blob/{h.split(':', 1)[1]}", blob)
            stored = True

        head = await self.head()
        seq, prev = head["seq_count"], head["last_receipt_hash"]
        now = datetime.now(timezone.utc).replace(microsecond=0)
        eid = str(uuid4())
        payload = {
            "type": "archive_entry", "version": "1", "entry_id": eid, "seq": seq,
            "doc_hash": doc_hash, "doc_size": doc_size, "content_type": content_type,
            "title": title, "metadata": metadata or {}, "enc_alg": enc_alg, "stored": stored,
            "prev_receipt_hash": prev, "issuer_did": self.issuer_did, "kid": self.kid,
            "archived_at": _iso(now),
        }
        receipt = signing.make_envelope_with(payload, self.signer)
        await self.storage.put(f"entry/{seq:012d}.json", receipt.encode())
        await self.storage.put(_HEAD, json.dumps(
            {"seq_count": seq + 1, "last_receipt_hash": signing.payload_hash(payload), "last_entry_id": eid}).encode())
        return {"entry_id": eid, "seq": seq, "doc_hash": doc_hash, "stored": stored, "enc_alg": enc_alg,
                "prev_receipt_hash": prev, "receipt": receipt, "kid": self.kid, "archived_at": _iso(now)}

    async def get_entry(self, seq: int) -> str | None:
        raw = await self.storage.get(f"entry/{int(seq):012d}.json")
        return raw.decode() if raw else None

    async def list_entries(self) -> list[str]:
        head = await self.head()
        out: list[str] = []
        for i in range(head["seq_count"]):
            e = await self.get_entry(i)
            if e is None:
                break
            out.append(e)
        return out

    async def retrieve(self, *, doc_hash: str) -> bytes:
        """Fetch and decrypt a stored document, verifying its hash matches. Raises if absent/altered."""
        hexh = doc_hash.split(":", 1)[1] if ":" in doc_hash else doc_hash
        blob = await self.storage.get(f"blob/{hexh}")
        if blob is None:
            raise FileNotFoundError("document not stored in archive (hash-only entry or unknown hash)")
        if self.enc is not None:
            if not self.enc.can_decrypt:
                raise PermissionError("decryption key not available on this node")
            data = self.enc.decrypt(blob)
        else:
            data = blob
        if hashlib.sha256(data).hexdigest() != hexh:
            raise ValueError("integrity check failed: document does not match its recorded hash")
        return data

    async def verify_chain(self, *, expected_head: dict | None = None) -> VerifyChainResult:
        """Verify the whole chain and detect truncation/holes.

        An interior deletion is caught here: the persisted head's ``seq_count`` will exceed the length of
        a contiguous scan from ``seq 0`` (``list_entries`` would instead silently stop at the hole). A
        dropped *trailing* entry is caught against the separately-persisted head, and — for defence against
        an attacker who also rewrites that head blob — against a caller-supplied out-of-band
        ``expected_head`` (``{seq_count, last_receipt_hash}``) when given.
        """
        # SECURITY (2026-11-14): the head read is the FIRST storage call in this method, so it needs
        # the same treatment as the entry reads below. Left unguarded, a raising backend escaped as an
        # exception out of a method whose contract is to return a result.
        try:
            head = await self.head()
        except (MemoryError, RecursionError):
            raise
        except Exception:  # noqa: BLE001
            return VerifyChainResult(valid=False, length=0, broken_at=0, reason="backend_error")
        receipts: list[str] = []
        i = 0
        while True:
            # SECURITY (2026-11-14): a backend that RAISES must not escape as an exception. An I/O
            # error, a malformed store or a hostile mount previously propagated out of verify_chain,
            # so a caller with a broad except recorded "could not verify" instead of "refused".
            # The catch is deliberately broad but re-raises what cannot be recovered from: a bare
            # `except Exception` also swallows MemoryError (it IS an Exception subclass), which would
            # convert an exhausted process into a tidy "backend_error" and hide the real fault.
            try:
                e = await self.get_entry(i)
            except (MemoryError, RecursionError):
                raise
            except Exception:  # noqa: BLE001
                return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                         reason="backend_error")
            if e is None:
                break
            receipts.append(e)
            i += 1
        # SECURITY (2026-08-14): a persisted head whose seq_count is not an integer is CORRUPTION, not
        # a crash. `int(head.get("seq_count") or 0)` raised ValueError out of verify_chain, so a damaged
        # or hostile head blob reported a traceback instead of a failed verification - and a caller that
        # wraps verification in a broad except reads a crash as "cannot verify" rather than "tampered".
        raw_count = head.get("seq_count") if isinstance(head, dict) else None
        # bool is a subclass of int, so a True/False seq_count would pass `isinstance(x, int)` and
        # then compare equal to 1/0. Rejected explicitly before the int check for that reason.
        if isinstance(raw_count, bool) or not isinstance(raw_count, int) or raw_count < 0:
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="corrupt_head")
        # The tail hash must be None only when the archive is genuinely empty. Both directions are
        # corrupt: a NON-empty store whose head lost its hash, and an EMPTY store whose head claims a
        # hash for an entry that does not exist. Checked here so the failure names the head rather than
        # surfacing later as head_mismatch against an anchor the caller never supplied.
        raw_tail = head.get("last_receipt_hash") if isinstance(head, dict) else None
        if raw_count == 0:
            if raw_tail is not None:                 # claims a tail that cannot exist: corrupted
                return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                         reason="corrupt_head")
        elif not isinstance(raw_tail, str):          # non-empty store with no usable tail hash
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="corrupt_head")
        if raw_count > len(receipts):
            # The head counts MORE entries than a contiguous read from 0 can reach: an interior or
            # trailing entry has been removed and anything after the hole is orphaned. This is the
            # tampering shape.
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=len(receipts),
                                     reason="missing_entry")
        if raw_count < len(receipts):
            # The head counts FEWER entries than are actually present. That is the crash shape, not the
            # attack shape: a writer appended an entry and died before updating the head blob, so the
            # store is merely behind. Reporting it as missing_entry sent an operator looking for a
            # deletion that never happened, so the two are distinguished here.
            return VerifyChainResult(valid=False, length=len(receipts), broken_at=raw_count,
                                     reason="stale_head")
        anchor = expected_head or {"seq_count": raw_count, "last_receipt_hash": raw_tail}
        return _verify_chain(receipts, self.pk, expected_head=anchor)
