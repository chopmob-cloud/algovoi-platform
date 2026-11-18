# AlgoVoi Recovery Vault (sealed appliance)

A sealed, **client-deployed** key-recovery vault for the AlgoVoi Verifiable Archive. It is a private
repository for *your own* archive keys, encrypted at rest, with **threshold (Shamir k-of-n)** recovery.
You run it; AlgoVoi never hosts it and never holds a usable key.

## Guarantees
- **Encrypted at rest.** Keys are stored under `scrypt(unlock_secret)` + AES-256-GCM. The on-disk file
  reveals nothing but a salt.
- **Threshold recovery.** The archive master key is Shamir-split; any *k* of *n* shares recover it,
  fewer reveal nothing.
- **Assisted-only AlgoVoi access.** When enabled, AlgoVoi holds **one** sub-threshold share — inert
  alone. It can be contributed to a break-glass recovery but can never decrypt or recover by itself.
- **Disable anytime.** `POST /v1/access {"enabled": false}` stops adding AlgoVoi shares; `resplit`
  drops AlgoVoi's share from an existing archive entirely.
- **Code sealed.** The crypto + custody modules are Nuitka-compiled to native `.so` in the image; no
  readable source ships.

## Run
```bash
# build + verify the sealed image (Docker host)
IMAGE=algovoi-recovery-vault:0.1.2 ./seal/build.sh
IMAGE=algovoi-recovery-vault:0.1.2 ./seal/verify.sh

# deploy (supply secrets from your secret manager)
VAULT_UNLOCK_SECRET=... VAULT_API_TOKEN=... docker compose up -d
```

## API (loopback, bearer-authenticated)
| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | liveness (no auth) |
| GET | `/v1/status` | archives + access state |
| POST | `/v1/archives` | `{name, auto_split?=true, threshold_k?=2, total_n?=3}` → generate + store an archive keypair; by default emits a 2-of-3 recovery (`{envelope, shares}`) in the same call |
| POST | `/v1/archives/{name}/split` | `{threshold_k,total_n,include_algovoi_support?}` → `{envelope, shares}` |
| POST | `/v1/archives/{name}/resplit` | rotate shares (revokes old shares / AlgoVoi share) |
| POST | `/v1/archives/{name}/recover` | `{shares:[...]}` → reconstruct master into the vault |
| GET | `/v1/archives/{name}/envelope` | the non-secret recovery envelope |
| POST | `/v1/access` | `{enabled}` → toggle AlgoVoi assist |

**Shares are secret.** They are returned by `split`/`resplit` so you can distribute them to your own
custodians; keep the API on loopback (or your own mTLS).

## Break-glass (AlgoVoi assist)
If you fall below threshold: send the (non-secret) envelope to AlgoVoi support on a verified request.
AlgoVoi unwraps its single share offline and returns one mnemonic; combine it with your remaining
shares (≥ k total) at `POST /v1/archives/{name}/recover`. AlgoVoi sees no other share and no data.
