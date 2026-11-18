# Secure Ingest — hardened SFTP / rsync landing zone for the Records Vault importer

This runbook stands up a **least-privilege, per-tenant ingest channel** in front of the volume importer.
Files arrive over standard, encrypted transports (SFTP or rsync-over-ssh) into a jailed drop directory that
the [watcher](../src/algovoi_records_vault_importer/watcher.py) picks up and commits with the usual
merkle-batch signing. The web console and CLI never become the data path, so volume is bounded only by disk
and hashing, exactly as designed.

The transport itself is OpenSSH and rsync, which you do not build or patch. What this runbook gives you is
the **envelope**: a write-only, chrooted, key-only drop target that can touch one tenant's dropbox and
nothing else, plus the wiring into the importer. Provenance of *who dropped what* comes from the sshd auth
log here; the commercial Secure Ingest add-on adds a content-addressed `ingest_ref` bound into the keystone
chain before the batch is signed.

Everything below is for a Linux host (the CCC host, or a dedicated ingest host in front of it). Run as root.

---

## 1. Layout and the chroot ownership rule

OpenSSH refuses to chroot into a directory unless that directory **and every parent** is owned by `root`
and not writable by group or others. So the per-tenant chroot root is root-owned, and only the `dropbox`
subdirectory inside it is writable by the tenant.

```
/opt/algovoi/ingest/                     root:root  0755
/opt/algovoi/ingest/<tenant>/            root:root  0755   <- chroot root (must be root-owned)
/opt/algovoi/ingest/<tenant>/dropbox/    <tenant>:algovoi-ingest  2770   <- the only writable path
```

Two groups keep the authentication clean:

- **`algovoi-ingest`** owns every dropbox (mode `2770`). Both tenant account types and the watcher service
  account are members, so uploaders can write and the watcher can read. The setgid bit makes every
  uploaded file inherit this group.
- **`algovoi-sftp`** is the marker for chrooted SFTP accounts only. The sshd `Match Group algovoi-sftp`
  block (below) applies the chroot and forced `internal-sftp` to exactly those accounts, and never to the
  rsync accounts, whose forced `rrsync` command must not be overridden.

```bash
groupadd -r algovoi-ingest
groupadd -r algovoi-sftp
install -d -m 0755 -o root -g root /opt/algovoi/ingest
```

Add the vault service user (the account that runs the watcher/importer) to the group:

```bash
usermod -aG algovoi-ingest <vault-service-user>
```

---

## 2. Per-tenant ingest account

One account per tenant. No shell, no password, no home to log into: the account exists only to land bytes.

```bash
tenant=acme
# SFTP account: primary group algovoi-ingest (dropbox access), supplementary algovoi-sftp (chroot match).
useradd -r -g algovoi-ingest -G algovoi-sftp -s /usr/sbin/nologin -M -p '*' -d /opt/algovoi/ingest/$tenant $tenant
# rsync account: only algovoi-ingest, so the SFTP Match block does not apply and its forced rrsync stands.
# It needs a real shell: an authorized_keys forced command= is exec'd via the login shell (nologin would
# break rsync). The key still cannot get a shell, because command= forces rrsync and no-pty denies a tty.
useradd -r -g algovoi-ingest -s /bin/bash -M -p '*' -d /opt/algovoi/ingest/$tenant ${tenant}-rsync
install -d -m 0755 -o root    -g root           /opt/algovoi/ingest/$tenant
install -d -m 2770 -o $tenant -g algovoi-ingest /opt/algovoi/ingest/$tenant/dropbox
```

`-p '*'` gives the account an **unusable** password (no password login is possible) that is nonetheless
**not locked**. This matters: a locked password (`!`, what `useradd -M` leaves by default) makes OpenSSH
treat the account as disabled and refuse even public-key auth when `UsePAM no` is set. `*` keeps the
account key-only while allowing the pubkey to authenticate.

Public keys live **outside** the tenant's writable area so a compromised dropbox cannot rewrite its own
trust. Store them root-owned under `/etc/ssh/ingest_keys/<user>`:

```bash
install -d -m 0755 -o root -g root /etc/ssh/ingest_keys
install -m 0644 -o root -g root acme.pub /etc/ssh/ingest_keys/$tenant
# the rsync key file carries the forced command (see the rsync tenants section below)
```

---

## 3. sshd configuration

Two transports land in the same dropbox but authenticate differently, because a forced `internal-sftp`
command and an `rrsync` forced command cannot both apply to one session. Split them by group.

Add to `/etc/ssh/sshd_config` (or a drop-in in `/etc/ssh/sshd_config.d/`):

```
# Keys for ingest accounts are root-owned and per-user; the account cannot edit its own.
AuthorizedKeysFile /etc/ssh/ingest_keys/%u

# --- SFTP tenants: chrooted, internal-sftp, land in /dropbox ---
# Matches only the algovoi-sftp group, so rsync accounts (algovoi-ingest only) are untouched.
Match Group algovoi-sftp
    ChrootDirectory /opt/algovoi/ingest/%u
    ForceCommand internal-sftp -d /dropbox
    PasswordAuthentication no
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

`internal-sftp` needs no binary inside the chroot. `-d /dropbox` drops the session straight into the
writable subdirectory (a path relative to the chroot root). The chroot for an SFTP account named `acme` is
`/opt/algovoi/ingest/acme`, so `%u` must equal the tenant directory name.

### rsync tenants

The rsync account (`<tenant>-rsync`) is in `algovoi-ingest` only, so the SFTP `Match` block never applies
and its forced `rrsync` command stands. The restriction is carried **in the authorized_keys entry**.
`rrsync -wo` is write-only: the client can push, never pull.

```
# /etc/ssh/ingest_keys/acme-rsync  (one line)
command="rrsync -wo /opt/algovoi/ingest/acme/dropbox",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ssh-ed25519 AAAA... acme-rsync
```

`rrsync` ships with rsync (often `/usr/bin/rrsync` or `/usr/share/doc/rsync/scripts/rrsync`; if absent,
copy it onto `PATH`). It is a script whose interpreter must exist on the host: older versions are Perl
(`#!/usr/bin/perl`), rsync 3.3+ ships a Python rewrite (`#!/usr/bin/python3`). Both are standard on any
real server; on stripped-down container images confirm the interpreter is present (a common gotcha is a
`#!/usr/bin/python3` shebang when python lives only at `/usr/local/bin/python3`). The `-wo` flag confines
the key to writing into exactly that one directory.

Reload sshd after any change (validate first):

```bash
sshd -t && systemctl reload ssh
```

---

## 4. Client side

SFTP:

```bash
sftp -i acme_ed25519 acme@ingest.example.com
# lands in /dropbox; just: put -r ./estate/*
```

rsync (atomic: rsync writes to a hidden temp name and renames on completion, so partials never look done):

```bash
rsync -a --checksum -e "ssh -i acme_rsync_ed25519" ./estate/ acme@ingest.example.com:
# note the empty remote path: rrsync -wo already pins the destination
```

For very large files, upload into a staging subdirectory and move into `dropbox` only when complete, or set
the watcher's `quiescent_secs` comfortably above your slowest transfer's stall window (see below).

---

## 5. Wire the dropbox to the importer

Point the watcher at the tenant's dropbox. It imports whenever the directory has been quiescent (no size
change) for `quiescent_secs`, which is what makes a still-uploading file safe to ignore until it settles.

```bash
export ALGOVOI_LICENSE_KEY="$(cat /opt/algovoi/vault/licence.key)"   # fail-closed gate
algovoi-rv-import watch \
    --source /opt/algovoi/ingest/acme/dropbox \
    --archive /opt/algovoi/vault/acme/archive \
    --keys-dir /opt/algovoi/vault/acme/keys \
    --strategy merkle --mode bridge \
    --batch-size 1000 --poll-secs 10 --quiescent-secs 15 \
    --checkpoint /opt/algovoi/vault/acme/import.ckpt
```

The `watch` subcommand runs until it receives SIGINT or SIGTERM (so `systemctl stop` shuts it down
cleanly). If you would rather drive the watcher from your own supervisor, call
`algovoi_records_vault_importer.watch(archive, source, ...)` directly; see [USAGE.md](USAGE.md).

- `--mode bridge` records hashes only (no bytes copied out of the dropbox); `--mode store` encrypts and
  stores the bytes in the archive.
- Re-runs are idempotent (already-committed documents are skipped by content), so a redelivered file is not
  double-committed.
- Run one watcher per tenant dropbox. Give each its own `--keys-dir`, `--archive`, and `--checkpoint`.

A minimal systemd unit per tenant:

```ini
[Unit]
Description=AlgoVoi Secure Ingest watcher (%i)
After=network.target

[Service]
User=<vault-service-user>
EnvironmentFile=/opt/algovoi/vault/%i/ingest.env
ExecStart=/usr/bin/algovoi-rv-import watch \
    --source /opt/algovoi/ingest/%i/dropbox \
    --archive /opt/algovoi/vault/%i/archive --keys-dir /opt/algovoi/vault/%i/keys \
    --strategy merkle --mode bridge --checkpoint /opt/algovoi/vault/%i/import.ckpt
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now algovoi-ingest@acme`.

---

## 6. What this stops (threat model)

A stolen ingest key is the worst realistic case. With this configuration it can:

- write only into that one tenant's `dropbox`, nothing else on the host (chroot for SFTP, `rrsync -wo` path
  pin for rsync);
- never read anything back (`internal-sftp` is confined to a write-target it cannot list outside; `rrsync
  -wo` refuses pulls);
- never obtain a shell or run a command (`nologin` shell, `ForceCommand` / forced `rrsync`, `PermitTTY no`);
- never reach another tenant's dropbox or the vault archive (separate chroot per `%u`, vault archive lives
  outside every chroot);
- never pivot (`AllowTcpForwarding no`, `PermitTunnel no`, agent/X11 forwarding off).

The vault's own per-batch Falcon-1024 signature means anything that *does* land is tamper-evident once
imported: altering a document after the fact breaks its inclusion proof against the signed batch root.

## 7. Optional hardening

- **Quota**: cap each tenant dropbox with a filesystem project quota (XFS) or per-user quota so a runaway
  push cannot fill the disk.
- **Per-source keys**: issue one key per source system, not per human, and rotate on the CCC key panel.
- **fail2ban**: rate-limit failed auth against the ingest port.
- **Dedicated ingest host**: run the landing zone on a separate small host and let the watcher push
  (bridge-mode hashes) to the vault host, so the internet-facing surface holds no keys or archive.
- **Post-import disposition**: after `bridge` import you may move committed files to a `processed/` archive
  or delete them; the vault already holds their signed proof.
