# Changelog

## 0.4.14
- **Import page (new `Import` tab).** Drive the `algovoi-records-vault-importer` add-on from the console:
  point the importer at a server path and it Merkle-batch-signs the whole estate into the same Records
  Vault the console browses. The browser is never the data path, so volume is bounded by disk and hashing,
  not by an HTTP upload. Three surfaces on one page:
  - **Secure ingest** — the SFTP/rsync landing zones (per-source drop folders + live file counts). Host
    provisioning of the jailed, write-only drop is per `docs/SECURE_INGEST.md`; the console reads landed
    files, it does not reconfigure the host sshd.
  - **Import** — run a one-shot import of a server path (`merkle`/`falcon`, `bridge`/`store`), with live
    progress and a recent-jobs table.
  - **Watcher** — enable a folder watcher that imports whenever a drop folder goes quiescent; shows cycle
    history and a stop control.
  Writers are serialized (one import or the watcher at a time) so the signed archive chain stays linear;
  jobs and watcher state are in-memory (reset on restart) while committed records persist and re-runs are
  idempotent. Gated on `manage_records` with a step-up password; every action is written to the signed
  console audit chain. Degrades gracefully when the importer add-on or Records Vault is absent.

## 0.4.13
- UI: consistent layout across the console. The top navigation is now a right-aligned column, the page
  tab buttons on top with the signed-in `user · role` directly beneath them. Every content page shares a
  single standard content width via one `--wrap` CSS variable (1180px), so the layout no longer shifts
  between pages. The Security (two-factor) page, previously a lone sparse table, now carries a "how it
  works" column and a short audit note so it reads at the same visual weight as the other pages.

## 0.4.12
- UI: the signed-in identity chip (`user · role`) moves to the end of the top navigation, after Sign
  out, so the page tabs lead the row and the identity reads on its own line beneath the nav.

## 0.4.11
- **Live SIEM audit forwarding (optional, off by default).** The signed console audit chain (sign-in,
  two-factor, brute-force blocks, record and hold and erasure actions, and so on) can now stream to a
  customer SIEM as entries are appended, in the formats a SOC expects: **RFC 5424 syslog**, **CEF** (over
  syslog transport), and a generic **webhook** (JSON POST with optional bearer token). Each forwarded
  record carries the entry's `seq` and `sha256` payload hash, so a SIEM record ties back to the
  tamper-evident chain. It is **off unless a sink is configured** (`COMMAND_CENTER_SIEM_SYSLOG` /
  `COMMAND_CENTER_SIEM_WEBHOOK`), so air-gapped installs are unaffected. Forwarding is non-blocking (a
  bounded queue drained by a daemon worker, so a slow or broken SIEM never stalls the console),
  best-effort (a sink failure is recorded and retried but never breaks the signed append), and catches up
  on restart (the last-forwarded `seq` is persisted and anything appended while a sink was down is
  backfilled). The Audit page shows a read-only forwarding-status card.

## 0.4.10
- UI: **clearer two-factor enrollment with a scannable QR code.** The enrollment page now leads with a
  QR code (rendered by the factor add-on) to scan into an authenticator app, numbered steps, and an
  unambiguous "6-digit code from your authenticator app" field (was "Confirm the current code", which
  was mistaken for a password). The setup key and `otpauth` URI remain as manual fallbacks. The QR is
  provided by the factor, so any factor add-on can supply one; when none is available the page falls
  back to the setup key.

## 0.4.9
- Fix: the **update check now detects non-`algovoi` suite packages** as installed. The per-package
  upgrade diff previously consulted only the `algovoi-*` inventory, so the `substrate2` core (no
  `algovoi` prefix) always read as "(not installed)" and was offered as a spurious upgrade even when the
  current version was already present. Each release-manifest package's installed version is now resolved
  by name, so an up-to-date `substrate2` no longer appears in the update list.

## 0.4.8
- Fix: **persist 2FA enrollment in the store backend**, not only in file-mode accounts. 0.4.7 kept a
  user's enrolled second factor under their account record, but the SQLite / PostgreSQL store only
  round-tripped the fixed columns, so an enrolled factor was dropped on save in store-backed (the
  default) deployments and login was never actually challenged. The `cc_users` table now carries an
  `mfa` column (JSON), added automatically by migration to existing tables, and enrollment survives
  restarts on every backend. Adds a store round-trip + migration test.

## 0.4.7
- **Pluggable two-factor authentication (2FA), adopted by install.** The console now discovers second-
  factor add-ons through the `algovoi_command_center.auth_factors` entry-point group, so a 2FA method is
  enabled simply by installing its package, with no configuration. The first such add-on is
  `algovoi-command-center-totp` (RFC 6238 authenticator-app codes); `pip install
  algovoi-command-center-totp` and the console offers TOTP on its **Security** page. Enrollment is
  **opt-in, then required**: a user adds a factor voluntarily (scan the `otpauth://` secret into an
  authenticator app, confirm a code), and from then on their sign-in requires the code. Login holds the
  session behind a challenge, issuing only a short-lived pending token (which grants no access) until the
  code verifies; the 2FA challenge shares the same per-client brute-force backoff as sign-in, and turning
  a factor off requires a step-up re-check. Every enroll, activate, disable, and 2FA sign-in is written
  to the signed console audit chain. Installs with no factor add-on behave exactly as before.

## 0.4.6
- Security: **web-interface hardening** across the whole console. Every response now carries a
  restrictive Content-Security-Policy (`default-src 'self'`, `frame-ancestors 'none'`, `form-action
  'self'`), plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy:
  no-referrer`. The session and step-up cookies are set `Secure` whenever the console is reached over
  HTTPS (directly or through a TLS-terminating proxy via `X-Forwarded-Proto`), while staying usable over
  plain HTTP for air-gapped or local operation. `/login` and the step-up re-check now have a per-client
  brute-force backoff (sliding window, then a short 429 cool-off), and every block is audited. The
  post-login and post-step-up redirect target is sanitised to same-origin absolute paths only, rejecting
  scheme-relative (`//host`) and backslash (`/\\host`) variants that some browsers normalise off-site.

## 0.4.5
- **Records Vault command centre.** The console now drives a self-hosted, offline-verifiable records
  archive directly, not just sealed containers. New `/records` panel: browse every notarized record with
  its signed-chain verification status, notarize a new record (encrypted at rest to the console key,
  RFC-3161 timestamped), and retrieve a stored document (writing a signed read-access event). New
  `/records/holds`: place and release **legal / litigation holds** over a matter (a held record can never
  be purged, and a hold cannot be released before its preservation floor). New `/records/disposition`:
  the **retention + disposition queue** listing records past the retention window and under no hold, with
  hold-preserved records called out; disposition stays operator-driven, never automatic. New
  `/records/evidence`: read-only surfacing of every signed evidence stream — consent receipts,
  chain-of-custody, key custody + rotation proofs, redactions, read-access — each offline-verifiable with
  the one published console public key. New `manage_records` / `manage_holds` permissions (admin +
  compliance officer); notarize requires an inline password re-check, retrieve and hold-release are
  step-up gated. Degrades gracefully (reports unavailable) if the `algovoi-records-vault` product is not
  installed or not licensed.
- **Local accounts management.** The `manage_users` permission finally has a surface: a `/users` panel
  (admin only) to list local accounts, add one, change a role, or remove one, editing the same store the
  local auth provider reads. Guardrails: the console can never be left without an administrator, and an
  operator cannot remove or demote their own account. Adding an account requires an inline password
  re-check; every change is written to the signed console audit chain.
- Security: **step-up credential re-check** before sensitive actions. Downloading an auditor pack, the
  validation pack, or the signed revocation list, and recovering a container from the console, now route
  through a "confirm your identity" password prompt (a short-lived, signed step-up token, 5 min);
  creating a sealed container requires re-entering your password inline. Every step-up attempt is written
  to the console audit chain.
- UI: preset two-row header. A constant top bar (brand + the same navigation in the same place on every
  page) sits above a page header row (title + page-specific actions), so the nav no longer shifts between
  pages.
- UI: unified visual theme across every console page. A shared `theme` module (one CSS, one page shell,
  one top nav) now backs the dashboard, containers, updates, audit, login, and all result/notice pages,
  so they share the same font, palette, header, and navigation. The containers and updates panels
  previously rendered as unstyled `system-ui` HTML; they now match the dashboard.
- Dashboard: a fresh install with no evidence ingested now shows a neutral "no evidence ingested yet,
  nothing to verify" state instead of a red "verification failed" pill. The failed state is reserved for
  the case where evidence exists but a chain does not verify (previously an empty estate was conflated
  with failure because `all_verified` is False when there are zero packs).

## 0.4.4
- **Operator-controlled updates**, driven from the console (`/updates` panel + `manage_updates` admin
  permission). Push future suite upgrades to deployed installs without a phone-home: online update checks
  are **disabled by default**, and even when an operator enables them the console contacts
  `pip.algovoi.co.uk` (the only permitted host, HTTPS-pinned) **only** on an explicit Check / Apply
  action — no timer, no background poll. A release is an `algovoi_release_manifest` Falcon-1024-signed by
  the AlgoVoi issuer key; the signature is verified first, then the downloaded bundle sha256 and every
  wheel sha256 are checked against the signed manifest before `pip install --upgrade`. Airgapped sites
  apply the identical signed manifest + `.algv` from local files with no network (`apply-offline`).
  Updates are operator-approved (never auto-applied) and every check/apply is written to the signed
  console audit chain. Wheel-bundle scope (does not touch service images).

## 0.4.3
- Sealed-container **console escrow recovery**: an optional per-container "console-recoverable" flag wraps
  the content key to a console-held ML-KEM recovery key (bootstrapped at
  `COMMAND_CENTER_CONTAINER_RECOVERY_KEY_FILE`), and a new `POST /v1/containers/{id}/recover` endpoint plus
  a panel Recover button open such containers 100% from the console without the recipient key or custodian
  shares. Protect the escrow key like the console signing key.

## 0.4.2
- Add sealed `.acv` records-container management: create and revoke portable, ML-KEM-sealed encrypted
  containers (via the `algovoi-records-vault-container` add-on) signed by the console key. New
  `manage_containers` permission (admin + compliance officer), a `/containers` console panel, and API
  endpoints `POST /v1/containers`, `POST /v1/containers/{id}/revoke`, `GET /v1/containers`,
  `GET /v1/containers/crl` (the signed revocation list). Optional Shamir k-of-n recovery shares are shown
  once at creation. Degrades gracefully (feature reports unavailable) if the add-on is not installed.

## 0.4.1

### Changed
- Posture labels finalized across the whole compliance suite. Every ingested evidence kind now
  renders a stable, human-readable posture row: Records Vault streams (documents, timestamps,
  read-access, legal holds, consent, custody, key rotations, ACL, redactions), Recovery Vault key
  custody, Sanctions Monitor screening deltas, Retention Chain payment receipts, Compliance Gate
  policy-bound verdicts, Payment Gateway settlements and payouts, Spend Guardrail decisions, Agent
  Passport issue/revoke events, Payment Mandate authorized charges, Substrate Guard admission
  decisions, Edge Sentinel allow/deny decisions, and Keystone execution/lifecycle evidence.
- Console entitlement aligned with the suite-store licence.

## 0.4.0

### Added
- Ingest plus posture for the security-suite signed decision spine: Substrate Guard admission
  decisions (`guard_decision`) and Edge Sentinel allow/deny decisions (`edge_decision`). Each is an
  append-only, offline re-verifiable signed chain, treated exactly like any other evidence stream.

## 0.3.0

### Added
- Ingest plus posture for Agent Passport issue/revoke events (`passport_event`) and Payment Mandate
  authorized charges (`mandate_charge`), carried as hybrid post-quantum signed lifecycle chains
  (Cap A to E parity with the rest of the suite).

## 0.2.0

### Added
- **Pluggable persistence backend.** The console audit chain and the user
  accounts now persist through a store selected by `COMMAND_CENTER_DB`: SQLite by
  default (a single file, air gap friendly, standard library only) or PostgreSQL
  via `postgresql://...` (the optional `[postgres]` extra). Switching backends is
  pure configuration, with no second code path for the signed chain. The legacy
  JSON file behaviour is preserved when `COMMAND_CENTER_AUDIT_FILE` or
  `COMMAND_CENTER_USERS_FILE` is set, so existing deployments are unaffected.
- **System validation pack** at `GET /validation/pack`: a signed, offline
  verifiable IQ/OQ/PQ evidence pack for the console itself (FDA 21 CFR Part 11
  section 11.10(a), ALCOA+, SOC 2), built on request from live self checks and the
  console audit chain head, signed with the console's own key. Ships its own
  standalone verifier.
- **Cached verified head.** Ingested evidence chains are no longer fully
  re verified on every page load. An unchanged chain is trusted from cache, a
  grown chain re verifies only the difference. The chains are append only and
  hash linked, so this is safe.

### Changed
- Audit log append is now constant time (count plus last row) rather than loading
  the whole log on every write.

### Notes
- Default install is SQLite (standard library, no extra dependency). PostgreSQL
  needs `pip install 'algovoi-command-center[postgres]'`.
- Migrating a 0.1.x file based deployment: keep the
  `COMMAND_CENTER_AUDIT_FILE` and `COMMAND_CENTER_USERS_FILE` variables to stay on
  files, or run a one time import of those JSON files into the store.

## 0.1.0
- Initial release: evidence ingest with offline re verification, posture
  dashboard, auditor pack export, local accounts with role based access control,
  LDAP and Active Directory SSO, bring your own key custody (KMS, Vault, PKCS#11),
  and a signed, offline verifiable console audit log.
