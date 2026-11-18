# Third-Party Notices — `algovoi-agent-passport`

This AlgoVoi product is proprietary (`LicenseRef-AlgoVoi-Commercial-1.0` / `LicenseRef-AlgoVoi-Internal`). It **depends on**, but does **not** copy, modify, or vendor, the open-source libraries listed below. Each is installed from PyPI under its own licence; its full licence text ships inside that library's own distribution.

All listed dependencies use **permissive** licences (MIT / BSD / Apache-2.0). None are copyleft. No third-party source is bundled into this package.

> **If this package is ever redistributed in a *bundled* form** (Docker image, offline / air-gapped installer, PyInstaller/frozen build) the full licence + NOTICE text of every dependency in the frozen tree **must be reproduced here**. Generate that at bundle time with e.g. `pip-licenses --format=plain-vertical --with-license-file` over the pinned environment. The list below covers the **direct** dependencies; those carry their own transitive dependencies under their respective licences.

## Direct dependencies

| Library | Declared version | Licence (SPDX) | Source | Used for |
|---|---|---|---|---|
| `fastapi` | `>=0.110` | MIT | <https://github.com/fastapi/fastapi> | ASGI web framework (service mode) |
| `pydantic` | `>=2.5` | MIT | <https://github.com/pydantic/pydantic> | data models / schema validation |
| `rfc8785` | `>=0.1.4` | Apache-2.0 | <https://github.com/trailofbits/rfc8785.py> | RFC 8785 (JCS) JSON canonicalisation — the bytes signed/hashed |
| `pqcrypto` | `>=0.4.0` | MIT | <https://github.com/kpdemetriou/pqcrypto> | post-quantum primitives via PQClean (Falcon-1024 signatures; ML-KEM-1024 KEM where used) |
| `uvicorn` _(optional: `serve`)_ | `>=0.29` | BSD-3-Clause | <https://github.com/encode/uvicorn> | ASGI server (service mode) |

## Notes

- **`pqcrypto`** wraps the [PQClean](https://github.com/PQClean/PQClean) reference implementations. The primitives this product uses — **Falcon-1024** (FN-DSA) and, where applicable, **ML-KEM-1024** plus Keccak/SHA-3 — are provided under public-domain / MIT-style terms within PQClean. The compiled binaries are distributed by the `pqcrypto` PyPI package, not by AlgoVoi.
- Standards referenced by name (Falcon / FN-DSA, ML-KEM, FIPS 206, RFC 8785) are open standards, not trademarks of any dependency.
- **Apache-2.0 dependencies** (`rfc8785`): if bundled, their `NOTICE` files (where present) must be reproduced alongside this file per Apache-2.0 §4(d).

_AlgoVoi — chopmob@gmail.com_
