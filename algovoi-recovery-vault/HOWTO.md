# Recovery Vault — deploy, use, and how it works

A practical guide to running the sealed **Recovery Vault** appliance: a private, client-deployed
repository for your **Verifiable Archive** keys, with **threshold (Shamir k-of-n)** recovery and
optional, revocable AlgoVoi assist.

---

## 1. How it works (the model)

The catastrophic failure for any encrypted archive is **losing the master key** — without it, your
encrypted records are gone forever. Recovery Vault removes that single point of failure:

```
            ┌──────────────────────────────────────────────────────────┐
            │  Recovery Vault appliance (you run it; encrypted at rest)  │
            │                                                            │
  generate ─┤  archive keypair  ──► ML-KEM (encrypt) + Falcon (sign)     │
            │                                                            │
   split ───┤  master key ──► random DEK ──► Shamir k-of-n shares        │
            │                    │                                       │
            │         envelope (NON-secret, stored)   shares (SECRET)    │
            └─────────────────────┼───────────────────────┼─────────────┘
                                  │                        │
                                  ▼                        ▼
                        store anywhere            distribute to YOUR custodians
                        (with the archive)        (sites / people / hardware)
                                                  + optionally ONE share to AlgoVoi
```

- The vault holds your archive keys **encrypted at rest** (`scrypt(unlock_secret)` + AES-256-GCM).
- `split` seals the master key under a one-time data key (DEK) and **Shamir-splits the DEK** into *n*
  shares with a recovery threshold *k*. Any *k* shares rebuild it; *k − 1* reveal nothing.
- The **envelope** (wrapped key + parameters) is **not secret** — it can't be opened without *k*
  shares — so you store it next to the archive. The **shares are secret** — you distribute them.
- **AlgoVoi assist is opt-in and inert.** If enabled, AlgoVoi holds **one** share (encrypted to its
  published key, fingerprint `d6031e21cd4126de`). One share is below threshold: it decrypts nothing.
  AlgoVoi can only *contribute* it to a recovery you run, alongside your remaining shares.

**What lives where**

| Item | Secret? | Where it lives |
|---|---|---|
| Unlock secret | yes | your secret manager / KMS / TPM (supplied at run time) |
| Archive master key | yes | inside the vault, encrypted at rest |
| Shares | yes | your custodians (and optionally one with AlgoVoi) |
| Envelope | no | stored with the archive |

---

## 2. Deploy

**Build + verify the sealed image** (on a Docker host — the crypto/custody modules are Nuitka-compiled
to native binaries; no readable source ships):

```bash
IMAGE=algovoi-recovery-vault:0.1.0 ./seal/build.sh
IMAGE=algovoi-recovery-vault:0.1.0 ./seal/verify.sh   # asserts: sources absent + API e2e passes
```

**Run** (supply secrets from your secret manager — never bake them):

```bash
export VAULT_UNLOCK_SECRET="$(your-secret-manager get vault/unlock)"
export VAULT_API_TOKEN="$(your-secret-manager get vault/api-token)"
docker compose up -d
curl -fsS http://127.0.0.1:8077/healthz        # {"ok":true}
```

Keep the API on **loopback** (the compose file binds `127.0.0.1:8077`) or front it with your own mTLS.
The vault file persists in the `vault-data` volume at `/data/recovery.vault`.

> **Back up the vault file _and_ the unlock secret separately.** The threshold shares are your
> disaster-recovery path; the vault file + unlock secret are your day-to-day convenience copy.

---

## 3. One-time setup

Set a bearer header for convenience:

```bash
H="Authorization: Bearer $VAULT_API_TOKEN"
B="http://127.0.0.1:8077"
```

**a. Create (or import) your archive keypair** — the vault generates and stores it:

```bash
curl -fsS -H "$H" -X POST "$B/v1/archives" -H 'content-type: application/json' \
     -d '{"name":"primary"}'
# -> {"name":"primary","archive_pub_b64":"...","falcon_pub_b64":"..."}
```

Use `archive_pub_b64` to configure your **write-only archive nodes**:
`HybridPqcEncryptor(archive_pub)` lets them encrypt but never decrypt (see the Verifiable Archive
docs). `falcon_pub_b64` is the public key auditors use to verify the chain.

**b. Split the master key into shares** (e.g. 2-of-3, with AlgoVoi assist):

```bash
curl -fsS -H "$H" -X POST "$B/v1/archives/primary/split" -H 'content-type: application/json' \
     -d '{"threshold_k":2,"total_n":3}'
# -> {"envelope":{...}, "shares":["word word ...","word word ..."]}   # 2 client shares; AlgoVoi holds 1
```

- **Distribute the `shares`** to separate custodians (different people / sites / hardware). Treat each
  as a high-value secret; SLIP-39 mnemonics are paper-friendly.
- **Store the `envelope`** with the archive (it's not secret).
- To split **self-custody only** (AlgoVoi holds nothing), first disable assist (section 6) or pass
  `"include_algovoi_support": false` — then all *n* shares are returned to you.

---

## 4. Day-to-day use

The archive runs normally. When a **read/restore node** needs the master key to decrypt documents,
export it from the vault over loopback:

```bash
curl -fsS -H "$H" "$B/v1/archives/primary/secret"
# -> {"archive_sk_b64":"...","archive_pub_b64":"..."}
```

Feed it to the Archive SDK:

```python
from algovoi_doc_archive import Archive, LocalFsBackend, HybridPqcEncryptor, signing
sk = signing.b64u_decode(secret["archive_sk_b64"]); pk = signing.b64u_decode(secret["archive_pub_b64"])
arc = Archive(secret_key=..., public_key=..., storage=LocalFsBackend("/srv/archive"),
              encryptor=HybridPqcEncryptor(pk, sk))   # now able to retrieve/decrypt
```

Check state any time:

```bash
curl -fsS -H "$H" "$B/v1/status"
# -> {"algovoi_access":true,"archives":{"primary":{"has_envelope":true,"threshold_k":2,"total_n":3,...}}}
```

---

## 5. Recovery

### a. Self-recovery (you hold ≥ k shares)
Stand up a fresh appliance (new unlock secret is fine), restore the envelope, then recover from your
shares — one SLIP-39 mnemonic per `shares[]` entry:

```bash
curl -fsS -H "$H" -X POST "$B/v1/archives/primary/recover" -H 'content-type: application/json' \
     -d '{"shares":["<share-1 mnemonic>","<share-2 mnemonic>"]}'
# -> {"name":"primary","recovered":true,...}
```

The recovered key is checked against a sealed sentinel before it's accepted, then stored back into the
vault. Export it (section 4) and resume.

### b. Break-glass with AlgoVoi assist (you're below threshold)
If you've lost shares down to fewer than *k*, and you enabled assist:

1. Send AlgoVoi support the **envelope** (`GET /v1/archives/primary/envelope`) on a verified request.
2. AlgoVoi unwraps its **single** share **offline** and returns **one** SLIP-39 mnemonic.
3. Combine it with your remaining share(s) — total ≥ *k* — in the `recover` call above.

AlgoVoi sees only the non-secret envelope and contributes one inert share — never your other shares,
never your data.

> **Run a recovery drill** on a schedule: gather *k* shares, recover into a throwaway vault, confirm
> `recovered:true`, discard. A backstop you never test is a backstop you don't have.

---

## 6. Disable / revoke AlgoVoi access

Turn assist off for **future** splits:

```bash
curl -fsS -H "$H" -X POST "$B/v1/access" -H 'content-type: application/json' -d '{"enabled":false}'
# -> {"algovoi_access":false}
```

Fully **revoke** AlgoVoi's share from an **existing** archive — re-split with a fresh DEK (this
invalidates *all* prior shares, including AlgoVoi's), then redistribute:

```bash
curl -fsS -H "$H" -X POST "$B/v1/archives/primary/resplit" -H 'content-type: application/json' \
     -d '{"threshold_k":2,"total_n":3,"include_algovoi_support":false}'
```

After a `resplit`, destroy the old shares — they no longer reconstruct anything.

---

## 7. API reference

| Method | Path | Body | Purpose |
|---|---|---|---|
| GET | `/healthz` | — | liveness (no auth) |
| GET | `/v1/status` | — | archives + access state |
| POST | `/v1/archives` | `{name}` | generate + store an archive keypair |
| POST | `/v1/archives/{name}/split` | `{threshold_k,total_n,include_algovoi_support?}` | split → `{envelope,shares}` |
| POST | `/v1/archives/{name}/resplit` | same as split | rotate shares / revoke |
| POST | `/v1/archives/{name}/recover` | `{shares:[...]}` | reconstruct master into the vault |
| GET | `/v1/archives/{name}/envelope` | — | the non-secret envelope (for break-glass) |
| GET | `/v1/archives/{name}/secret` | — | export the master key (loopback + bearer) |
| POST | `/v1/access` | `{enabled}` | toggle AlgoVoi assist |

**Security checklist:** loopback/mTLS only · unlock secret + API token from a secret manager · shares
to separate custodians · back up the vault file and unlock secret separately · run recovery drills ·
disable/`resplit` to revoke AlgoVoi.
