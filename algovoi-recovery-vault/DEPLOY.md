# Deploying the Recovery Vault appliance

You receive **one sealed container image** plus a compose file — no source code. This guide gets it
running on your own Docker host and points you at day-to-day use.

You should have:
- `algovoi-recovery-vault-0.1.0.image.tgz` — the sealed image (crypto + custody compiled to native
  modules; no readable Python source ships)
- `docker-compose.yml`

## 1. Prerequisites
- A Linux host with **Docker** (Engine 24+). 1 core / 1 GB RAM / a few GB disk is plenty.
- A way to supply two secrets at runtime (KMS, Vault, Docker/K8s secrets, or systemd `EnvironmentFile`):
  - **`VAULT_UNLOCK_SECRET`** — derives the at-rest encryption key (`scrypt` + AES-256-GCM). Lose it and
    the vault file can't be opened (recover via your threshold shares instead — see HOWTO §5).
  - **`VAULT_API_TOKEN`** — bearer token required on every `/v1` call.

## 2. Load + verify the image
```bash
# verify integrity against the published digest before loading
sha256sum algovoi-recovery-vault-0.1.0.image.tgz
#   expect: e7665a40f38fe1f6ee41...   (v0.1.0)

docker load < algovoi-recovery-vault-0.1.0.image.tgz
docker images algovoi-recovery-vault
```

## 3. Run
Supply the secrets from your manager (never bake them into the compose file):
```bash
export VAULT_UNLOCK_SECRET="$(your-secret-manager get vault/unlock)"
export VAULT_API_TOKEN="$(your-secret-manager get vault/api-token)"
docker compose up -d

curl -fsS http://127.0.0.1:8077/healthz      # {"ok":true}
```
The compose file binds the API to **loopback** (`127.0.0.1:8077`). Keep it there, or front it with your
own mTLS — the API returns secrets (shares, exported keys) and must not be exposed.

Runtime knobs (env): `VAULT_PATH` (default `/data/recovery.vault`), `VAULT_BIND`, `VAULT_PORT`. The
encrypted vault persists in the `vault-data` Docker volume at `/data`.

## 4. First use
Generate your archive keypair, split it into threshold shares, and distribute them:
```bash
H="Authorization: Bearer $VAULT_API_TOKEN"; B="http://127.0.0.1:8077"
curl -fsS -H "$H" -X POST "$B/v1/archives" -H 'content-type: application/json' -d '{"name":"primary"}'
curl -fsS -H "$H" -X POST "$B/v1/archives/primary/split" \
     -H 'content-type: application/json' -d '{"threshold_k":2,"total_n":3}'
#   -> {"envelope":{...}, "shares":[ "...", "..." ]}   # distribute the shares to your custodians
```
Full API + the self-recovery / break-glass / disable-AlgoVoi flows are in **HOWTO.md** (§3–§6).

## 5. Back up the right things
- **The `vault-data` volume** (`/data/recovery.vault`) — your day-to-day encrypted key store.
- **The `VAULT_UNLOCK_SECRET`** — stored *separately* from the vault file.
- **Your threshold shares** — held by separate custodians; these are the disaster-recovery path if the
  vault host *and* unlock secret are ever lost.

## 6. Upgrade
```bash
docker load < algovoi-recovery-vault-<new>.image.tgz   # verify its digest first
# update the image tag in docker-compose.yml, then:
docker compose up -d                                   # vault-data volume persists across the swap
```

## 7. Uninstall
```bash
docker compose down                 # keeps the vault-data volume
docker compose down -v              # ALSO deletes the vault store — only if you have your shares/backup
```

## Security notes
- The image is **sealed**: the signing, encryption, recovery, and vault logic are native compiled
  modules — there is no readable source in the image.
- **AlgoVoi never receives your keys.** Default splits are self-custody only. Support-assisted recovery
  is opt-in and gives AlgoVoi exactly **one** sub-threshold share — useless on its own (see HOWTO §1).
- Keep the API on loopback / behind your own mTLS; pull both secrets from a secret manager at runtime;
  verify the image digest before every load.
