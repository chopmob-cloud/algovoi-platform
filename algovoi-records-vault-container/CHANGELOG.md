# Changelog

## 0.2.3
- Hardening from the container security review:
  - **CRL freshness (anti-replay).** Two layers. The signed header carries `min_crl_at` (default: the
    container's `created_at`), and the opener refuses a validly-signed revocation list older than that
    floor, so a pre-creation CRL can never be replayed. On top of that the opener takes an optional
    recipient freshness requirement (`max_crl_age_seconds` in `open_container`, `--max-crl-age-days` in
    the extractor) that refuses any CRL older than the recipient's chosen window, closing the case where
    a still-valid-but-outdated list is used to keep a since-revoked container openable. Enforced in
    `open_container` and the offline extractor.
  - **Loud issuer pin.** The extractor now prints a prominent warning when `--expect-issuer` is not
    supplied, since a valid signature proves internal consistency, not *who* signed. `open_container`
    gains an `expect_issuer` parameter to bind a container to a known issuer kid in-process.
  - **Opaque names.** `seal_container(..., opaque_names=True)` (and `ContainerRegistry.create`) hide
    document names and the title from the cleartext header: the header lists opaque ids and the real
    names travel encrypted in the body, restored only after decryption and re-checked for path-safety.
  Backward compatible: containers sealed by earlier versions (no `min_crl_at` / opaque ids) open
  unchanged.

## 0.2.2
- Security: reject path-traversal document names (zip-slip). A document named with an absolute path, a
  drive letter, or a `..` segment could previously make the recipient's extractor write outside its
  `--out` directory. Names are now validated fail-closed at BOTH seal time (`seal_container`) and open
  time (`open_container` / `acv_unseal.py`), and the extractor additionally confirms every resolved
  output path stays under `--out` (realpath containment). Exposed as `safe_name`. Regression tests
  added for the seal, in-process open, and standalone extractor paths.

## 0.2.1
- `acv_unseal.py` gains a `--genkey PREFIX` mode so a recipient can generate their own ML-KEM-1024
  keypair (`<PREFIX>_pk.b64` to send to the issuer, `<PREFIX>_sk.b64` to keep) without writing any code;
  the container argument is now optional. Ship `RECIPIENT_GUIDE.md`, a one-page handout for opening a
  container offsite.

## 0.2.0
- Add optional per-container **console escrow recovery**. Seal a container `console_recoverable` and the
  content key is additionally wrapped with ML-KEM-1024 to a Command-Center-held recovery key, so the
  operator can recover it 100% from the console with `recover_via_escrow` / `ContainerRegistry.recover`
  (no recipient key, no custodian shares). Opt-in per container and recorded in the signed header; whoever
  holds the console recovery key can decrypt those containers, so it is a deliberate confidentiality
  trade-off. The default remains recipient-only with optional Shamir k-of-n custodian recovery.

## 0.1.0
- Initial release. Sealed, portable, post-quantum encrypted records containers (`.acv`): a set of records
  is sealed into one movable file with an AES-256-GCM body under a Falcon-1024-signed header, and the
  AES content key wrapped with ML-KEM-1024 to a named recipient so only that recipient can open it. The
  header is verified before any decryption and is bound to the ciphertext as AAD. Offline revocation via
  a Falcon-signed revocation list that the recipient's extractor checks (required by default). Ships a
  self-contained `acv_unseal.py` extractor that imports no AlgoVoi packages. `seal_from_archive` pulls a
  record's bytes and its archive receipt straight from a Records Vault archive. A `ContainerRegistry`
  provides create / revoke / posture / signed-CRL, driven by the Compliance Command Center (API endpoints
  and a console panel) so containers can be created and revoked from the CCC. Optional Shamir k-of-n
  key-loss recovery: the content key can be split into n custodian shares at seal time (any k reconstruct
  it and open the container without the recipient's key), reusing the audited SLIP-39 recovery primitive;
  revocation is still enforced on the recovery path and shares are shown once, never stored. Runtime
  licence enforced, fail-closed.
