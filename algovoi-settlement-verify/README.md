# algovoi-settlement-verify

**Multi-chain stablecoin settlement verification** — confirm a payment actually
settled (and finalised) on-chain, across **8 networks**, with one call.

Covers **Algorand, VOI, Base/EVM, Solana, Hedera, Stellar, Tempo, Arc** — including
the long-tail chains (Algorand ASA decimals, Hedera HTS, Stellar trustlines) that
generic payment SDKs don't verify well.

> Commercial product — **AlgoVoi Commercial Licence v1.0**. Not open source, not for
> redistribution. Contact chopmob@gmail.com for terms (Enterprise / On-prem / OEM).

## Why
Most tooling helps you *initiate* a payment. This verifies that an arbitrary
third-party settlement *landed* — with correct per-chain finality semantics — and
optionally binds it to a compliance receipt. That verification, across heterogeneous
chains, is the hard part.

## Design
- **Standalone.** Runtime deps are only `httpx` + `pydantic`. No chain SDKs (raw
  JSON-RPC/REST), no AlgoVoi infrastructure required.
- **RPC injected.** You supply endpoints via `RpcConfig` — point it at your own nodes.
- **One entrypoint.** `verify(payload, rpc=...) -> VerifyResult`.

## Usage
```python
import asyncio
from algovoi_settlement_verify import verify, PaymentPayload, NetworkEnum, RpcConfig

payload = PaymentPayload(
    network=NetworkEnum.base_mainnet,
    tx_id="0x…",
    expected_amount_microalgos=1_000_000,     # 6-dp microunits
    expected_receiver="0xRecipient…",
    expected_asset_id="0xA0b8…",              # USDC contract / asset id
)
result = asyncio.run(verify(payload, rpc=RpcConfig(base_rpc_url="https://your-node")))
print(result.verified, result.confirmed_amount, result.error)
```

Authority/standing-approval check (no amount/receiver):
```python
from algovoi_settlement_verify import verify_authority, NetworkEnum
await verify_authority("0x…", NetworkEnum.base_mainnet)
```

## Status
v0.1.0 — internal spike extracted from the AlgoVoi facilitator. `Private :: Do Not
Upload`. Not yet published to any registry.

## Third-party dependencies & attribution

This package **depends on** the following open-source libraries (installed from PyPI under their own licences). AlgoVoi does **not** vendor, copy, or modify them — they are imported as ordinary dependencies, not embedded. All are permissive (MIT / BSD / Apache-2.0); none are copyleft.

| Library | Licence |
|---|---|
| [`httpx`](https://github.com/encode/httpx) | BSD-3-Clause |
| [`pydantic`](https://github.com/pydantic/pydantic) | MIT |

Full attribution and the bundling obligation are in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).


## Licence — required to run

This is a commercial package and is **runtime-licence-enforced**: it refuses to initialise without a
valid AlgoVoi licence. Set your licence key in the `ALGOVOI_LICENSE_KEY` environment variable (or point
`ALGOVOI_LICENSE_FILE` at a file containing it) before constructing the engine. Running several suite
packages together? `ALGOVOI_LICENSE_KEY` may hold several keys (whitespace/comma-separated) — each picks
its own.

Install with the index token from your purchase (it also pulls this package's private suite
dependencies, so one `pip install` resolves the whole chain). Terms: the Self-Serve Starter Licence
(clickwrap, accepted at purchase) or your Enterprise/OEM agreement.
